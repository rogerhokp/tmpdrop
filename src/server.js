import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import Database from 'better-sqlite3';
import { randomBytes, createHash } from 'node:crypto';
import { mkdir, writeFile, unlink, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';
import { lookup as mimeLookup } from 'node:dns';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const UPLOAD_DIR = process.env.UPLOAD_DIR || join(ROOT, 'uploads');
const DATA_DIR = process.env.DATA_DIR || join(ROOT, 'data');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_BASE = process.env.PUBLIC_BASE || `http://localhost:${PORT}`;
const MAX_BYTES = Number(process.env.MAX_BYTES || 25 * 1024 * 1024); // 25MB
const TTL_OPTIONS = { '1h': 3600, '24h': 86400 };
const DEFAULT_TTL = '1h';

// MIME allowlist — refuse anything else to limit abuse surface.
const ALLOWED_MIME = new Set([
  'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp',
  'application/pdf', 'text/plain', 'application/json', 'application/zip',
  'video/mp4', 'video/webm',
]);

await mkdir(UPLOAD_DIR, { recursive: true });
await mkdir(DATA_DIR, { recursive: true });

const db = new Database(join(DATA_DIR, 'files.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    slug TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_expires ON files(expires_at);
`);

const insert = db.prepare(`INSERT INTO files (slug, filename, mime, size, sha256, ip_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
const getBySlug = db.prepare(`SELECT * FROM files WHERE slug = ?`);
const findExpired = db.prepare(`SELECT slug FROM files WHERE expires_at <= ?`);
const delBySlug = db.prepare(`DELETE FROM files WHERE slug = ?`);

function slug() {
  return randomBytes(9).toString('base64url');
}
function hashIp(ip) {
  return createHash('sha256').update(String(ip)).digest('hex').slice(0, 16);
}
function safeExt(name) {
  const e = extname(name || '').toLowerCase();
  return /^\.[a-z0-9]{1,6}$/.test(e) ? e : '';
}

async function reapExpired() {
  const now = Math.floor(Date.now() / 1000);
  const rows = findExpired.all(now);
  for (const { slug } of rows) {
    try { await unlink(join(UPLOAD_DIR, slug)); } catch {}
    delBySlug.run(slug);
  }
  if (rows.length) app.log.info({ reaped: rows.length }, 'reaped expired files');
}

const app = Fastify({ logger: true, bodyLimit: MAX_BYTES + 1024 });

await app.register(rateLimit, {
  max: 30,
  timeWindow: '1 minute',
  keyGenerator: (req) => req.ip,
});
await app.register(multipart, {
  limits: { fileSize: MAX_BYTES, files: 1 },
});

app.get('/', async (_, reply) => {
  reply.type('text/html').send(`<!doctype html>
<meta charset="utf-8">
<title>tmpfiles selfhost</title>
<style>body{font:14px system-ui;max-width:560px;margin:4em auto;padding:0 1em}</style>
<h1>tmpfiles selfhost</h1>
<form method="post" action="/upload" enctype="multipart/form-data">
  <p><input type="file" name="file" required></p>
  <p>TTL:
    <label><input type="radio" name="ttl" value="1h" checked> 1 hour</label>
    <label><input type="radio" name="ttl" value="24h"> 24 hours</label>
  </p>
  <p><button>Upload</button></p>
</form>
<p>API: <code>curl -F file=@thing.png -F ttl=1h ${PUBLIC_BASE}/upload</code></p>`);
});

app.get('/healthz', async () => ({ ok: true }));

app.post('/upload', async (req, reply) => {
  const part = await req.file();
  if (!part) return reply.code(400).send({ error: 'no file' });

  const ttlKey = (part.fields?.ttl?.value) || DEFAULT_TTL;
  const ttlSec = TTL_OPTIONS[ttlKey];
  if (!ttlSec) return reply.code(400).send({ error: 'ttl must be 1h or 24h' });

  const mime = part.mimetype || 'application/octet-stream';
  if (!ALLOWED_MIME.has(mime)) {
    return reply.code(415).send({ error: `mime not allowed: ${mime}` });
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of part.file) {
    size += chunk.length;
    if (size > MAX_BYTES) return reply.code(413).send({ error: 'too large' });
    chunks.push(chunk);
  }
  if (part.file.truncated) return reply.code(413).send({ error: 'too large' });

  const buf = Buffer.concat(chunks, size);
  const sha = createHash('sha256').update(buf).digest('hex');
  const id = slug();
  const ext = safeExt(part.filename);
  const now = Math.floor(Date.now() / 1000);
  const expires = now + ttlSec;

  await writeFile(join(UPLOAD_DIR, id), buf, { flag: 'wx' });
  insert.run(id, part.filename || 'file', mime, size, sha, hashIp(req.ip), now, expires);

  const url = `${PUBLIC_BASE}/f/${id}${ext}`;
  return { url, slug: id, expires_at: expires, size, mime };
});

app.get('/f/:slug', async (req, reply) => {
  const raw = req.params.slug;
  const id = raw.replace(/\.[a-z0-9]{1,6}$/i, '');
  const row = getBySlug.get(id);
  if (!row) return reply.code(404).send({ error: 'not found' });
  if (row.expires_at <= Math.floor(Date.now() / 1000)) {
    return reply.code(410).send({ error: 'expired' });
  }
  const path = join(UPLOAD_DIR, id);
  try { await stat(path); } catch { return reply.code(404).send({ error: 'gone' }); }

  reply
    .header('Content-Type', row.mime)
    .header('Content-Length', row.size)
    .header('Content-Disposition', `inline; filename="${row.filename.replace(/"/g, '')}"`)
    .header('Cache-Control', 'private, max-age=300')
    .header('X-Content-Type-Options', 'nosniff')
    .header('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; sandbox");
  return reply.send(createReadStream(path));
});

setInterval(() => { reapExpired().catch((e) => app.log.error(e)); }, 60_000);
await reapExpired();

await app.listen({ port: PORT, host: HOST });
