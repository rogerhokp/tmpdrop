# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-05-24

### Added
- Drag-and-drop upload with unguessable 12-char base64url slugs (72 bits of entropy).
- Per-upload TTL (`1h` or `24h`) enforced by a reaper that deletes both the file and the DB row.
- Strict MIME allowlist (images, PDF, text, JSON, ZIP, MP4, WebM); HTML/JS rejected.
- `Content-Security-Policy: sandbox` and `X-Content-Type-Options: nosniff` on every download.
- Per-IP rate limit (30 req/min).
- 25 MB size cap, overridable via `MAX_BYTES`.
- Configurable storage directory via `STORAGE_DIR`.
- SHA-256-hashed uploader IPs in the DB (no raw IPs retained).
- Retro CRT landing page.
- Dockerfile and `docker-compose.yml`.
- Non-ASCII filename support on download.
