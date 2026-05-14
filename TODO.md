# TODO — Many-faced Honeypot

## Resolved (this session)

- [x] **DB path resolution ignored TOML config** — `_resolve_db_path()` only checked env var, causing data loss on every deploy. Fixed in PR #66: now checks env → TOML `database.path` → default.
- [x] **Client sent bot IP instead of sensor ID** as message prefix — reports rejected by server's AUTHORIZED_BEES check. Fixed in PRs #64, #65: both `_send_report()` and `process_request()` now pass `settings.HIVELOGIN`.
- [x] **Config file location confusion** — service runs as `honeypot` user reading `/home/honeypot/.config/manyfaced/config.toml`, not root's config. Documented in AGENTS.md.
- [x] **Deploy workflow too slow** — tests/typecheck ran on every master push. Changed to fast-path: lint only → deploy. Tests still run on PRs.

---

## High Priority

### 1. Geolocation completely broken (bot_country = 100% empty)
All `bot_country` and `bot_continent` fields are empty in the DB. The geolocation lookup pipeline isn't configured or working. Need to:
- Check if MaxMind GeoIP database is installed on the droplet
- Verify geoip library dependencies are available
- Add a config option for API-based geolocation as fallback

### 2. Protocol detection layer missing (all detected_id = UNKNOWN_HTTP)
Every record has `detected_id=4294967294` (UNKNOWN_HTTP), meaning non-HTTP traffic (SSH probes, etc.) is being force-parsed as HTTP and failing silently. Need:
- A protocol detection step before HTTP parsing
- Separate handlers for SSH, FTP, Telnet, etc.
- Proper `detected_id` values per protocol

### 3. request_raw mostly empty (~50-92% empty)
The raw request capture pipeline has gaps — many records don't have the full original request preserved. Need to audit where `raw_request` is set vs where it's lost during parsing/serialization.

---

## Medium Priority

### 4. No honeypot.log file persistence
Logging goes only to journalctl with no file backup. If the journal gets rotated/vacuumed, all historical logs are gone. Consider:
- Adding a file-based log handler alongside journalctl
- Or at least documenting that analysis must use `journalctl` queries

### 5. Stale root config on droplet
`/root/.config/manyfaced/config.toml` has TOML syntax errors (`False` instead of `false`). It's ignored by the service but causes Python import failures when debugging as root. Should be cleaned up or removed.

---

## Low Priority / Nice-to-Have

### 6. Deployment-analysis scripts
The `deployment-analysis/analyze_production.py` script exists but hasn't been updated for newer data patterns (sensor ID prefix, new DB schema fields). Could use a refresh.

### 7. Lockfile in bots/ dir
A `lockfile` sits in `/opt/manyfaced/bots/` — unclear what it's for or if it's still needed. Investigate and document or remove.
