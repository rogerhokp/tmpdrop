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
const PUBLIC_BASE = (process.env.PUBLIC_BASE || `http://localhost:${PORT}`).replace(/\/+$/, '');
const MAX_BYTES = Number(process.env.MAX_BYTES || 25 * 1024 * 1024); // 25MB
const TTL_OPTIONS = { '1h': 3600, '24h': 86400 };
const DEFAULT_TTL = '1h';

// Force-download these even though CSP sandbox would neuter them — browsers
// give text/html special treatment and it's the one type worth quarantining.
const FORCE_ATTACHMENT_MIME = new Set([
  'text/html', 'application/xhtml+xml',
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
function contentDisposition(name, disposition = 'inline') {
  const fallback = (name || 'file')
    .replace(/[^\x20-\x7e]+/g, '_')
    .replace(/["\\]/g, '_');
  const encoded = encodeURIComponent(name || 'file');
  return `${disposition}; filename="${fallback}"; filename*=UTF-8''${encoded}`;
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
  reply.type('text/html; charset=utf-8').send(renderIndex());
});

app.get('/healthz', async () => ({ ok: true }));

app.post('/upload', async (req, reply) => {
  const part = await req.file();
  if (!part) return reply.code(400).send({ error: 'no file' });

  const ttlKey = (part.fields?.ttl?.value) || DEFAULT_TTL;
  const ttlSec = TTL_OPTIONS[ttlKey];
  if (!ttlSec) return reply.code(400).send({ error: 'ttl must be 1h or 24h' });

  const mime = part.mimetype || 'application/octet-stream';

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
    .header('Content-Disposition', contentDisposition(row.filename, FORCE_ATTACHMENT_MIME.has(row.mime) ? 'attachment' : 'inline'))
    .header('Cache-Control', 'private, max-age=300')
    .header('X-Content-Type-Options', 'nosniff')
    .header('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; sandbox");
  return reply.send(createReadStream(path));
});

function renderIndex() {
  const maxMb = (MAX_BYTES / 1024 / 1024).toFixed(0);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>tmpdrop // ephemeral file drop</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {
    --bg: #0a0f0a;
    --fg: #33ff66;
    --dim: #1f6b2e;
    --hot: #aaffaa;
    --warn: #ffcc33;
    --err: #ff5577;
  }
  * { box-sizing: border-box; }
  html, body { background: var(--bg); color: var(--fg); margin: 0; padding: 0; }
  body {
    font-family: "Consolas", "Menlo", "DejaVu Sans Mono", "Courier New", monospace;
    font-size: 15px;
    line-height: 1.45;
    min-height: 100vh;
    text-shadow: 0 0 1px rgba(51,255,102,.6), 0 0 6px rgba(51,255,102,.15);
  }
  body::before {
    content: "";
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      to bottom,
      rgba(0,0,0,0) 0px,
      rgba(0,0,0,0) 2px,
      rgba(0,0,0,.18) 3px,
      rgba(0,0,0,.18) 3px
    );
    pointer-events: none;
    z-index: 9999;
  }
  body::after {
    content: "";
    position: fixed; inset: 0;
    background: radial-gradient(ellipse at center, rgba(0,0,0,0) 55%, rgba(0,0,0,.55) 100%);
    pointer-events: none;
    z-index: 9998;
  }
  main { max-width: 900px; margin: 0 auto; padding: 2em 1.5em 4em; }
  pre.banner {
    color: var(--hot);
    font-size: 11px;
    line-height: 1.05;
    margin: 0 0 1em;
    white-space: pre;
    overflow-x: auto;
  }
  .meta { color: var(--dim); margin-bottom: 2em; }
  .meta b { color: var(--fg); }
  h2 {
    color: var(--hot);
    font-size: 15px;
    font-weight: normal;
    margin: 2.5em 0 .8em;
    border-bottom: 1px dashed var(--dim);
    padding-bottom: .3em;
  }
  h2::before { content: ">> "; color: var(--dim); }
  p, li { margin: .4em 0; }
  a { color: var(--hot); text-decoration: underline; }
  a:hover { background: var(--fg); color: var(--bg); text-decoration: none; }
  code, pre.code {
    background: rgba(51,255,102,.06);
    border: 1px solid var(--dim);
    color: var(--hot);
    padding: 1px 5px;
    font-family: inherit;
  }
  pre.code {
    padding: .8em 1em;
    overflow-x: auto;
    white-space: pre;
  }
  .blink { animation: blink 1.1s steps(2, start) infinite; }
  @keyframes blink { to { visibility: hidden; } }

  form#u {
    border: 1px solid var(--fg);
    padding: 1em 1.2em;
    margin: 1em 0;
    position: relative;
  }
  form#u .label { color: var(--dim); margin-right: .6em; }
  form#u label.radio { margin-right: 1.2em; cursor: pointer; }
  form#u input[type=radio] { accent-color: var(--fg); }
  .drop {
    position: relative;
    display: block;
    border: 2px dashed var(--fg);
    padding: 2.6em 1em 2.2em;
    text-align: center;
    color: var(--fg);
    cursor: pointer;
    margin: .6em 0 1.2em;
    background:
      repeating-linear-gradient(45deg,
        rgba(51,255,102,.04) 0 12px,
        rgba(51,255,102,.08) 12px 24px);
    transition: all .12s;
    box-shadow: inset 0 0 0 4px var(--bg), 0 0 0 1px var(--fg);
  }
  .drop::before {
    content: "[ DROP ZONE ]";
    position: absolute;
    top: -.7em;
    left: 1.2em;
    background: var(--bg);
    color: var(--hot);
    padding: 0 .6em;
    font-size: 12px;
    letter-spacing: .15em;
  }
  .drop .arrow {
    color: var(--hot);
    font-size: 28px;
    line-height: 1;
    margin-bottom: .35em;
    animation: pulse 1.4s ease-in-out infinite;
  }
  @keyframes pulse { 0%,100% { opacity: .35; transform: translateY(0); } 50% { opacity: 1; transform: translateY(3px); } }
  .drop .big {
    font-size: 16px;
    color: var(--hot);
    margin-bottom: .35em;
    letter-spacing: .05em;
  }
  .drop .sub { color: var(--dim); font-size: 13px; }
  .drop .sub b { color: var(--fg); text-decoration: underline; }
  .drop.hover {
    background: rgba(51,255,102,.18);
    box-shadow: inset 0 0 0 4px var(--bg), 0 0 0 1px var(--fg), 0 0 18px rgba(51,255,102,.4);
  }
  .drop b { color: var(--hot); }
  input[type=file] { display: none; }
  button {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--fg);
    font: inherit;
    padding: .4em 1.2em;
    cursor: pointer;
  }
  button:hover:not(:disabled) { background: var(--fg); color: var(--bg); }
  button:disabled { color: var(--dim); border-color: var(--dim); cursor: not-allowed; }

  #out {
    margin-top: 1.2em;
    border-top: 1px dashed var(--dim);
    padding-top: 1em;
    min-height: 1em;
    white-space: pre-wrap;
    word-break: break-all;
  }
  #out .ok { color: var(--hot); }
  #out .err { color: var(--err); }
  #out .url { color: var(--warn); }
  #out .url a { color: var(--warn); }

  table.routes { border-collapse: collapse; width: 100%; margin: .5em 0; }
  table.routes th, table.routes td {
    border: 1px solid var(--dim);
    padding: .4em .7em;
    text-align: left;
    vertical-align: top;
  }
  table.routes th { color: var(--hot); font-weight: normal; }
  footer { margin-top: 3em; color: var(--dim); font-size: 12px; }
</style>
</head>
<body>
<main>
<pre class="banner">
 _____ __  __ ____  ____  ____   ___  ____
|_   _|  \\/  |  _ \\|  _ \\|  _ \\ / _ \\|  _ \\
  | | | |\\/| | |_) | | | | |_) | | | | |_) |
  | | | |  | |  __/| |_| |  _ <| |_| |  __/
  |_| |_|  |_|_|   |____/|_| \\_\\\\___/|_|
   ephemeral file drop // self-hosted // v1.0
</pre>

<div class="meta">
[ session ] <b>guest@tmpdrop</b> &middot;
[ max ] <b>${maxMb} MB</b> &middot;
[ ttl ] <b>1h / 24h</b> &middot;
[ status ] <b style="color:var(--hot)">ONLINE</b><span class="blink">_</span>
</div>

<p>
Upload a file. Get a link. The link dies on schedule. No accounts, no tracking,
no analytics, no third party. Files served with a strict <code>Content-Security-Policy</code>
sandbox so a malicious upload can't run in your browser.
</p>

<h2>drop a file</h2>

<form id="u" enctype="multipart/form-data">
  <label class="drop" id="drop" for="file">
    <div class="arrow">&#x25BC;</div>
    <div class="big">DRAG &amp; DROP A FILE HERE</div>
    <div class="sub">&mdash; or <b>click anywhere in this box</b> to browse &mdash;</div>
    <div id="picked" style="margin-top:.9em;color:var(--hot)"></div>
  </label>
  <input id="file" type="file" name="file" required>

  <div style="margin:.6em 0">
    <span class="label">[ttl]</span>
    <label class="radio"><input type="radio" name="ttl" value="1h" checked> 1 hour</label>
    <label class="radio"><input type="radio" name="ttl" value="24h"> 24 hours</label>
  </div>

  <button id="go" type="submit">&gt; transmit</button>
  <div id="out"></div>
</form>

<h2>api</h2>

<p>One endpoint. Multipart form. Public. No auth.</p>

<table class="routes">
  <tr><th>method</th><th>path</th><th>purpose</th></tr>
  <tr><td>POST</td><td><code>/upload</code></td><td>upload a file, get a URL + slug</td></tr>
  <tr><td>GET</td><td><code>/f/:slug</code></td><td>fetch a file (returns 410 once expired)</td></tr>
  <tr><td>GET</td><td><code>/healthz</code></td><td>liveness probe</td></tr>
</table>

<h2>upload — curl</h2>
<pre class="code">curl -F file=@screenshot.png -F ttl=1h ${PUBLIC_BASE}/upload</pre>

<p>Response (JSON):</p>
<pre class="code">{
  "url":        "${PUBLIC_BASE}/f/AbCdEfGhIjKl.png",
  "slug":       "AbCdEfGhIjKl",
  "expires_at": 1717000000,
  "size":       18234,
  "mime":       "image/png"
}</pre>

<h2>parameters</h2>
<table class="routes">
  <tr><th>field</th><th>required</th><th>notes</th></tr>
  <tr><td><code>file</code></td><td>yes</td><td>multipart file part. Max <b>${maxMb} MB</b>.</td></tr>
  <tr><td><code>ttl</code></td><td>no</td><td><code>1h</code> (default) or <code>24h</code>. Anything else: <code>400</code>.</td></tr>
</table>

<h2>file types</h2>
<p>Any file type is accepted. Size is the only gate — see <b>${maxMb} MB</b> above.</p>
<p>Uploads are served with a strict <code>Content-Security-Policy: sandbox</code>
plus <code>X-Content-Type-Options: nosniff</code>, so nothing in an uploaded file
can execute in your browser. <code>text/html</code> and
<code>application/xhtml+xml</code> are additionally forced to download rather
than render inline.</p>

<h2>status codes</h2>
<table class="routes">
  <tr><th>code</th><th>meaning</th></tr>
  <tr><td><code>200</code></td><td>ok</td></tr>
  <tr><td><code>400</code></td><td>no file, or bad <code>ttl</code></td></tr>
  <tr><td><code>410</code></td><td>file expired</td></tr>
  <tr><td><code>413</code></td><td>over size limit</td></tr>
  <tr><td><code>429</code></td><td>rate limited (30 req / min per IP)</td></tr>
</table>

<h2>retention &amp; privacy</h2>
<ul>
  <li>Files are deleted from disk + DB the minute they expire. There is no soft-delete.</li>
  <li>URL slugs are 12 chars of base64url (~72 bits of entropy). Not guessable.</li>
  <li>Uploader IPs are stored as a truncated SHA-256, never raw.</li>
  <li>No cookies. No analytics. No third-party requests on this page.</li>
</ul>

<footer>
[tmpdrop] open source &middot;
<a href="https://github.com/rogerhokp/tmpdrop">github.com/rogerhokp/tmpdrop</a>
&middot; MIT
</footer>
</main>

<script>
(() => {
  const form = document.getElementById('u');
  const file = document.getElementById('file');
  const drop = document.getElementById('drop');
  const picked = document.getElementById('picked');
  const out = document.getElementById('out');
  const go = document.getElementById('go');

  file.addEventListener('change', () => {
    if (file.files[0]) picked.textContent = '// ' + file.files[0].name + ' (' + fmt(file.files[0].size) + ')';
  });
  ['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('hover'); }));
  ['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('hover'); }));
  drop.addEventListener('drop', ev => {
    if (ev.dataTransfer.files && ev.dataTransfer.files[0]) {
      file.files = ev.dataTransfer.files;
      picked.textContent = '// ' + file.files[0].name + ' (' + fmt(file.files[0].size) + ')';
    }
  });

  function fmt(b) {
    if (b < 1024) return b + ' B';
    if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
    return (b/1024/1024).toFixed(2) + ' MB';
  }

  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    if (!file.files[0]) { out.innerHTML = '<span class="err">[err] no file selected</span>'; return; }
    const fd = new FormData(form);
    go.disabled = true;
    out.innerHTML = '<span style="color:var(--dim)">[..] transmitting ' + file.files[0].name + ' ...</span>';
    try {
      const r = await fetch('/upload', { method: 'POST', body: fd });
      const j = await r.json();
      if (!r.ok) {
        out.innerHTML = '<span class="err">[err ' + r.status + '] ' + (j.error || 'failed') + '</span>';
      } else {
        const exp = new Date(j.expires_at * 1000).toLocaleString();
        out.innerHTML =
          '<span class="ok">[ok] uploaded</span>\\n' +
          '  url     <span class="url"><a href="' + j.url + '" target="_blank" rel="noopener">' + j.url + '</a></span>\\n' +
          '  slug    ' + j.slug + '\\n' +
          '  size    ' + fmt(j.size) + '\\n' +
          '  mime    ' + j.mime + '\\n' +
          '  expires ' + exp;
      }
    } catch (e) {
      out.innerHTML = '<span class="err">[err] ' + e.message + '</span>';
    } finally {
      go.disabled = false;
    }
  });
})();
</script>
</body>
</html>`;
}

setInterval(() => { reapExpired().catch((e) => app.log.error(e)); }, 60_000);
await reapExpired();

await app.listen({ port: PORT, host: HOST });
