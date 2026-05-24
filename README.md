# tmpdrop

Self-hosted ephemeral file host. A small Node service for sharing one-off
files (screenshots, logs, etc.) without handing them to a public third party.

## Why

Public file hosts retain your data on infrastructure you don't control and
expose it via predictable URLs that get scraped. This service runs on your
own box with:

- Unguessable URLs (12-char base64url slug = 72 bits of entropy).
- Strict MIME allowlist (no HTML/JS — uploaded files can't run in the browser).
- `Content-Security-Policy: sandbox` + `X-Content-Type-Options: nosniff` on
  every download to neuter stored-XSS attempts.
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

## Allowed MIME types

png, jpeg, gif, webp, svg, bmp, pdf, txt, json, zip, mp4, webm. Edit
`ALLOWED_MIME` in `src/server.js` to change.

## Notes

- The DB stores a truncated SHA-256 of the uploader's IP, not the IP itself,
  so logs can be retained without holding raw client IPs.
- Files are stored on disk by slug (no extension), served with the original
  MIME from the DB row. The extension in the URL is cosmetic — the server
  ignores it on lookup.
- For higher abuse resistance, swap public uploads for a shared-token header
  (`Authorization: Bearer …`) — the change is ~3 lines in `/upload`.
