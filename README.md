# tmpdrop

Self-hosted ephemeral file host. A small Node service for sharing one-off
files (screenshots, logs, etc.) without handing them to a public third party.

## Why

Public file hosts retain your data on infrastructure you don't control and
expose it via predictable URLs that get scraped. This service runs on your
own box with:

- Unguessable URLs (12-char base64url slug = 72 bits of entropy).
- Any file type accepted — size is the only gate.
- `Content-Security-Policy: sandbox` + `X-Content-Type-Options: nosniff` on
  every download to neuter stored-XSS attempts. `text/html` is additionally
  forced to download rather than render.
- Per-upload TTL (1h or 24h), enforced by a reaper that deletes both the file
  and the DB row.
- Per-IP rate limit (30 req/min).
- 25MB size cap (override with `MAX_BYTES`).

## Run

```bash
cd tmpdrop
cp .env.example .env   # then edit
docker compose up -d --build
```

`docker compose` auto-loads `.env`. Useful keys:

| var | default | purpose |
| --- | --- | --- |
| `PUBLIC_BASE` | `http://localhost:3000` | URL printed in upload responses |
| `PORT` | `3000` | host port |
| `MAX_BYTES` | `26214400` | max upload size in bytes |
| `STORAGE_DIR` | `./data` | host dir holding `uploads/` and `db/` |

Put it behind Caddy/Cloudflare Tunnel for TLS. Example Caddyfile:

```
files.example.com {
  reverse_proxy localhost:3000
}
```

## Upload

```bash
curl -F file=@screenshot.png -F ttl=1h https://files.example.com/upload
# → {"url":"https://files.example.com/f/AbCdEf...png","expires_at":...}
```

`ttl` accepts `1h` or `24h` (default `1h`).

## File types

All MIME types are accepted. The `Content-Security-Policy: sandbox` +
`nosniff` headers prevent uploaded files from executing in the browser.
`text/html` and `application/xhtml+xml` are served as attachments (download)
rather than rendered inline — see `FORCE_ATTACHMENT_MIME` in `src/server.js`.

## Notes

- The DB stores a truncated SHA-256 of the uploader's IP, not the IP itself,
  so logs can be retained without holding raw client IPs.
- Files are stored on disk by slug (no extension), served with the original
  MIME from the DB row. The extension in the URL is cosmetic — the server
  ignores it on lookup.
- For higher abuse resistance, swap public uploads for a shared-token header
  (`Authorization: Bearer …`) — the change is ~3 lines in `/upload`.
