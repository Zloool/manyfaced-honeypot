# TODO — Many-faced Honeypot

## High Priority

### 1. Database WAL checkpointing & backup strategy
The DB uses `PRAGMA journal_mode=WAL` but never checkpoints, causing unbounded WAL growth and corruption on copy (as seen during scp). The last ~90 rows of 1,069,387 records were corrupted because the WAL sidecar was missing.

**Fix:**
- Add periodic `PRAGMA wal_checkpoint(TRUNCATE)` in a background thread or via cron on the server
- Implement automated DB backup (e.g., daily rsync/cron job that copies both `.sqlite` and `.sqlite-wal`)
- On startup, run `PRAGMA integrity_check` and warn if corruption is detected

### 2. Data retention / database rotation
The DB is already **198 MB** after ~22 days with no cleanup strategy. At this rate it'll be multi-gigabytes in months. No records are ever archived or deleted.

**Fix:**
- Add a `--rotate` flag or cron job that archives old records (e.g., >30 days) to a separate file
- Or implement automatic DELETE WHERE timestamp < X, with optional archive-to-S3/local-file first
- Consider partitioning by month if using PostgreSQL backend

### 3. Geolocation rate limiting blocks the hot path
`geolocate.py` uses `time.sleep(1.33)` between requests to stay within ip-api.com's 45 req/min limit. With ~86K unique IPs, this means lookups for new IPs stall the honeypot response. The sleep happens synchronously in the request handler thread.

**Fix:**
- Move geolocation to a background worker queue (similar to report_queue.py pattern)
- Pre-populate geo data from a local GeoIP database (MaxMind MMDB — the `geoip2` optional dep is already listed)
- Or use ip-api.com's batch endpoint / cache aggressively and accept stale data for high-frequency IPs

### 4. No alerting on credential captures
When SSH or HTTP credentials are captured, they're silently stored in the DB with no notification. Operators have to manually query the database to find them.

**Fix:**
- Add a notification hook (email, webhook, Telegram bot message) when `login` field is populated
- Configurable via `[alerting]` section in config.toml
- At minimum: log at ERROR level with clear formatting so it stands out in journalctl

---

## Medium Priority

### 5. No web dashboard / data visualization
All collected data sits in SQLite with no way to view it without writing custom scripts. A simple embedded dashboard would make the honeypot much more useful for operators.

**Fix:**
- Add a lightweight Flask/FastAPI server (optional, behind `--dashboard` flag)
- Show: top attackers map, request timeline, captured credentials table, protocol distribution chart
- Can be a separate module to keep core dependencies minimal

### 6. Missing handlers for detected protocols
Protocol detection identifies SSH, Redis, MongoDB, TLS, DNS, SMB, Telnet, RDP, VNC — but only SSH has a handler that returns data. Others return empty responses or generic fallbacks.

**Fix:**
- Add `redis_handler.py` with fake redis banner + command responses
- Add `mongodb_handler.py` with fake MongoDB wire protocol responses
- Add `telnet_handler.py` with login prompt simulation (capture credentials)
- Add `rdp_handler.py` and `vnc_handler.py` with connection refusal banners

### 7. No Docker / container support
No Dockerfile, docker-compose, or containerization despite having GitHub Actions CI. Makes deployment inconsistent across environments.

**Fix:**
- Add a multi-stage Dockerfile (build deps in one stage, slim runtime in another)
- Add `docker-compose.yml` for client + server setup
- Document containerized deployment in README

### 8. No API for querying collected data
External tools (SIEMs, dashboards, alerting systems) have no way to access honeypot data programmatically.

**Fix:**
- Add a REST API endpoint (could be part of the dashboard server from #5)
- Support: list top IPs, search by IP/date range, export credentials, get protocol stats
- Authenticated via API key from config.toml

---

## Low Priority / Nice-to-Have

### 9. Fix duplicate logger in `mfh.py`
Line 16 and line 18 both define `logger = logging.getLogger(__name__)`. Minor but sloppy.

### 10. Hardcoded lockfile path
`_DEFAULT_LOCKFILE` is hardcoded to `/opt/manyfaced/bots/lockfile` — won't work for non-root users or development environments. Should use XDG paths like other config.

### 11. No metrics export (Prometheus/statsd)
No way to integrate with monitoring stacks. A Prometheus text collector exposing request counts, unique IPs, protocol distribution would be valuable.

### 12. `request_raw` empty for non-HTTP traffic
For SSH probes and other detected protocols, the raw bytes are captured but stored inconsistently — sometimes as truncated strings, sometimes empty. The `_handle_ssh_probe` and `_handle_non_http_probe` methods pass different formats to BearStorage compared to HTTP paths.

### 13. No integration tests for full data pipeline
Tests cover individual modules (handlers, storage, config) but there's no end-to-end test that simulates: bot connects → honeypot responds → report sent → stored in DB → queryable.

### 14. Empty connection handling could be improved
`detect_protocol()` returns `None` for empty bytes, which falls through to the HTTP parser and then gets caught as a parse error, creating a fallback record with generic data. Could detect this earlier and store it more cleanly.

---

## Already Fixed (remove from TODO)

- ~~Geolocation completely broken~~ — Working via ip-api.com with caching
- ~~Protocol detection layer missing~~ — 14 protocols detected in `protocol.py`
- ~~No honeypot.log file persistence~~ — Config has LOG_FILE path, though production uses journalctl
