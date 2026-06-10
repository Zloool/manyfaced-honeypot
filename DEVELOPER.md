# Developer Guide

## Prerequisites

- Python 3.8+
- `pip install -r requirements.txt`

## Running Locally

```bash
# Quick test: client + server on same host
python3 mfh.py -c 8888 -s 9999 -v

# Client only (e.g., to serve fake WordPress)
python3 mfh.py -c 80 -v

# Server only (for testing report ingestion)
python3 mfh.py -s 666 -v
```

The config file auto-generates via `manyfaced --generate-config` (uses `Config.generate_config_file()`). A reference template is available at `manyfaced/settings.toml.example`.

## Codebase Deep Dive

### Entry Point: mfh.py

```
mfh.py (main)
  ├── args = parse()          # CLI parsing
  ├── Process(client)        # HTTPHandler in child
  ├── Process(server)        # ServerHandler in child
  └── Process(updater)       # trigger() in child (optional)
```

Both client and server run as separate `multiprocessing.Process` instances. They communicate over raw TCP with encrypted payloads.

### Process: manyfaced/ Package

```
manyfaced/
├── common/        # Shared utilities (config, args, crypto, utils)
├── client/        # Honeypot CLIENT (create_server, send_report)
├── server/        # Honeypot SERVER (collects bot reports)
├── handlers/      # Request processing (ABC pattern, service handlers)
└── db/            # Data persistence layer
```

### Key Classes

#### BaseHandler (server-side ABC) — `handlers/base_handler.py`

Core request handling pipeline for encrypted messages from the client:

```python
handle_request(message)
  └── parse_message()      # Split on ":" into [identifier, encrypted]
  └── decrypt_message()    # AES decrypt with key from get_key()
  └── parse_json()          # Deserialize JSON data
  └── process_request()     # Abstract — implemented by subclass

get_key():        # Abstract — return decryption key for identifier
process_request(): # Abstract — handle decrypted data
```

#### HTTPHandlerBase (client-side ABC) — `handlers/base_handler.py`

Abstract base for service-specific HTTP handlers. Subclasses implement:
- `matches_path()`: Check if this handler should handle the request
- `generate_response()`: Generate a realistic HTTP response
- `handle_login()`: (Optional) Process login attempts and capture credentials

#### HTTPHandler — `handlers/http_handler.py`

CLIENT-side entry point. When a bot connects:
1. Parses raw HTTP request
2. Routes to the appropriate service handler via Router + ordered route table (`manyfaced.handlers.routes`)
3. Service handler generates realistic honeypot response
4. Spawns `send_report()` process to send encrypted report back to server
5. Returns the fake HTTP response to the bot

**Routing:** The route table is an ordered list of `Route(matcher, handler_cls, detected_id, name)` entries in `manyfaced.handlers.routes`. First match wins — order is the dispatch policy. Per-service route files live in `manyfaced/handlers/routes/` (e.g., `routes_bitrix.py`).

#### Service Handlers — `handlers/*.py`

Each service handler manages a specific service:
- **WordPressHandler**: WordPress CMS (login, admin, xmlrpc, content)
- **PhpMyAdminHandler**: phpMyAdmin (login, database pages)
- **JenkinsHandler**: Jenkins CI/CD (login, jobs, script console)
- **TomcatHandler**: Apache Tomcat (manager, host-manager, server-status)
- **DrupalHandler**: Drupal CMS (login, admin, nodes)
- **CPanelHandler**: cPanel/WHM (login, webmail)
- **GenericHandler**: Default "monster page" for unknown paths

Each handler:
- Defines `PATH_PATTERNS` for matching URLs
- Generates realistic HTML responses mimicking the real service
- Captures login credentials from POST requests
- Returns fake error/redirect responses to encourage further probing

#### ServerHandler — `server/server.py`

SERVER-side handler. When a report arrives:
1. Extends `BaseHandler` for encrypted message processing
2. `get_key()` looks up `AUTHORIZED_BEANS` dict by identifier
3. `process_request()` spawns `save_data()` process to insert into DB
4. Returns "200 OK" as response

#### BotProfile — `handlers/base_handler.py`

Tracks per-bot state for a handler's service:
- Request history
- Detected behaviors (SQL injection, LFI/RFI, RCE, credential stuffing, etc.)
- Escalation level (idle → scanning → probing → exploiting → compromised)
- Captured credentials

#### AESCipher — `common/myenc.py`

AES-256-CBC encryption:
- Key: `SHA-256(HIVEPASS)` → 32 bytes
- IV: `os.urandom(16)` prepended
- Format: `base64(IV + ciphertext)`
- PKCS7 padding (block size 32)

#### BearRequests — `db/dbconnect.py`

Dataclass: `ip`, `raw_request`, `timestamp`, `parsed_request`, `is_detected`, `HIVELOGIN`
`Insert(bear)` delegates to `get_storage()` → SQLite or PostgreSQL.

### Data Models

#### BearRequests (in flight)
```python
{
    "ip": "1.2.3.4",
    "raw_request": "GET /wp-login.php HTTP/1.1\r\n...",
    "timestamp": "2026-04-19 06:36:00.123456",
    "parsed_request": {
        "command": "GET",
        "path": "/wp-login.php",
        "request_version": "HTTP/1.1",
        "headers": {"Host": "...", "User-Agent": "..."}
    },
    "is_detected": 1,           # or UNKNOWN_HTTP = 4294967294
    "HIVELOGIN": "honeybee"
}
```

#### honeypot_bears (in database)
| Field            | Type   | Source                    |
|----------------- |--------|---------------------------|
| bot_ip           | text   | `data["ip"]`              |
| hostname         | text   | `HIVELOGIN` from client   |
| timestamp        | text   | UTC now                   |
| request_path     | text   | `data.parsed_request.path`|
| request_command  | text   | `data.parsed_request.command`|
| request_version  | text   | `data.parsed_request.version`|
| request_raw      | text   | `data["raw_request"]`     |
| bot_user_agent   | text   | `data.parsed_request.ua`  |
| bot_country      | text   | geoip2 lookup             |
| bot_continent    | text   | geoip2 lookup             |
| bot_tracert      | text   | TODO (never implemented)  |
| bot_dns_name     | text   | socket.gethostbyaddr      |
| detected_id      | int    | `data.is_detected`        |
| hive_id          | int    | per-config                |
| login            | text   | `HIVELOGIN`               |

## How to Add a New Service Handler

The full recipe is codified in the **add-service-handler** skill. This section summarizes the current architecture (the old `registry.py` pattern no longer exists).

### Current Architecture

```
manyfaced/handlers/
├── base_handler.py          # HTTPHandlerBase ABC — subclass this
├── http_handler.py           # Main entry point, dispatches via Router
├── __init__.py               # Imports all handlers + exports in __all__
├── <svc>_handler.py          # Your new handler class (subclass HTTPHandlerBase)
│
└── routes/                   # Per-service route files
    ├── __init__.py           # Concatenates per-service ROUTES into one ordered table
    └── routes_<svc>.py       # Route entries for your service
```

### Steps

1. **Create handler class** in `manyfaced/handlers/<svc>_handler.py` extending `HTTPHandlerBase`:
   - Define `domain = '<svc>'` and `DETECTED_ID = 1` (or a special ID from `status.py`)
   - Implement `generate_response(path, raw_request, bot_ip, headers)` → `(bytes, int)`
   - Add `handle_login()` logic if the service has authentication

2. **Export from** `manyfaced/handlers/__init__.py`:
   - Add import: `from manyfaced.handlers.<svc>_handler import <Svc>Handler`
   - Add `<Svc>Handler` to `__all__` list (alphabetical order)

3. **Register routes** in `manyfaced/handlers/routes/`:
   - Create `routes_<svc>.py` with lazy-import helper (`def _<svc>() -> type:`) and `ROUTES: list[Route] = [...]`
   - Import + concatenate in `routes/__init__.py` (order = dispatch priority, first match wins)

4. **Add to monster page** in `generic_handler._SERVICE_INFO`:
   - Add `' <svc>': ('Display Name', 'Version', 'Running (vVersion)')`
   - Optionally add representative paths in `_SERVICE_PATHS`

5. **Write tests** mirroring existing handler test patterns in `test/test_handlers/test_service_handlers.py`

### Canonical Example

See `bitrix_handler.py` + `routes_bitrix.py` for a clean, minimal reference implementation. The Bitrix handler demonstrates:
- Multiple page types (admin login, auth, setup, portal) each with their own HTML method
- POST credential capture via `handle_login()`
- Login-failed responses that encourage further probing

### Routing Caveats

- **Ordering = dispatch policy:** First route match wins. To change precedence, reorder entries in `routes/__init__.py`.
- **Overlap resolution:** `/xmlrpc.php` → WordPressHandler (not ConfigDisclosure), `/mysql` → PhpMyAdminHandler. Higher-priority routes listed first.
- **WebDAV is deliberately NOT route-registered** — it uses a separate dispatch mechanism.

## How to Change Database Schema

1. Update `_CREATE_TABLE_SQL` in `manyfaced/db/storage.py` (SQLite) and `_CREATE_TABLE_PG_SQL` (PostgreSQL)
2. Update `_INSERT_SQL` and `_INSERT_PG_SQL` to match
3. Update `insert()` method field mapping in both `SQLiteStorage` and `PostgreSQLStorage`
4. Add tests for new fields

## Testing

### Run all tests
```bash
cd /home/zlol/manyfaced-honeypot
/usr/bin/python3 -m pytest test/ -v
```

### Test file structure
```
test/
├── conftest.py               # Shared test utilities
├── test_integration.py       # Full pipeline: socket -> decrypt -> DB -> query
├── test_client.py            # Client-specific unit tests
├── test_http_handler.py      # HTTPHandler tests
├── test_config.py            # Config system tests
├── test_storage.py           # Storage backend tests
└── test_*.py                 # Other test modules
```

### Key testing patterns
- Use `multiprocessing.Process` to test server/client behavior
- Use real `AESCipher` for encryption roundtrips
- Check SQLite DB directly for persistence tests
- Mock the `geoip2` module (it can't be imported in tests)
- Set `AUTHORIZED_BEANS` via `sys.modules` dict, not env var

## Security Notes

1. **pickle.dump_file()** — `common/utils.py` uses `pickle` for fallback data storage. This is unsafe with untrusted data. The file is written to `temp.db` in the working directory.

2. **Shared secrets** — `HIVEPASS` is the shared encryption key. Never commit real keys. Use environment variables or `settings.toml.example` (gitignored).

3. **AUTHORIZED_BEANS** — In server mode, this dict determines which bots are authorized. If empty/no entries match, decryption will fail.

4. **geoip2 dependency** — The `python-geoip-geolite2` package requires a GeoLite2 database to be installed separately. Without it, country/continent fields will be empty.

5. **Subprocess git pull** — The `update.py:pull()` runs `git pull` and `pip install -r requirements.txt` in a subprocess. This is a security risk in production — consider pinning versions.

## Handler Coverage Analysis

### Current Handlers (10 total)

| Handler | Domain | Purpose |
|---------|--------|---------|
| WordPressHandler | wordpress | WordPress CMS emulation |
| DrupalHandler | drupal | Drupal CMS emulation |
| PhpMyAdminHandler | phpmyadmin | phpMyAdmin database admin |
| CPanelHandler | cpanel | cPanel/WHM control panel |
| JenkinsHandler | jenkins | Jenkins CI/CD server |
| TomcatHandler | tomcat | Apache Tomcat servlet container |
| WebDAVHandler | webdav | WebDAV file sharing |
| BitrixHandler | bitrix | Bitrix CMS emulation |
| ConfigDisclosureHandler | config_disclosure | Sensitive file disclosure (config files, backups) |
| GenericHandler | generic | Fallback for unmatched paths + "monster page" |

### Known Coverage Gaps

Production data shows **97% of bot traffic hits the root path `/`** which currently falls to GenericHandler. See `docs/production-analysis-handler-coverage.md` for a complete analysis.

**High-priority gaps:**
- Root path `/` — 17,033 hits (needs targeted responses by User-Agent)
- Favicon `/favicon.ico` — 36 hits (bot fingerprinting trigger)
- Login paths `/login`, `/j_spring_security_check` — Spring Security emulation needed
- Environment files `/.env` — ConfigDisclosureHandler expansion
- API endpoints `/api/*`, `/v*/api-docs`, Swagger — New API handler needed
- Next.js paths `/_next/*` — New NextJS handler needed
- PHP eval RCE `eval-stdin.php` patterns — New EvalStdin handler needed

### Adding A New Handler

See the **add-service-handler** skill for the full recipe. Summary:

1. Create `manyfaced/handlers/<name>_handler.py` extending `HTTPHandlerBase`
2. Export from `handlers/__init__.py` (import + add to `__all__`)
3. Register routes in `routes/` (create `routes_<name>.py`, import + concatenate in `routes/__init__.py`)
4. Add service info to `generic_handler._SERVICE_INFO` for monster page inclusion
5. Write tests in `test/test_handlers/test_service_handlers.py`

See existing handlers for patterns — `bitrix_handler.py` + `routes_bitrix.py` is a clean reference implementation.

## Debugging Tips

- `-v` (verbose) mode prints every bot interaction
- Check `temp.db` for failed reports (pickle-fallback)
- Check `bots/honeypot.db` for saved bear data
- Server sends `CODE 300 ERROR: {exception}` for unhandled errors
- Client sends `200 OK` or `207 Multi-Status` for WebDAV

## Deployment Checklist

- [ ] Set `HONEY_HIVEPASS` to a strong random string
- [ ] Set `HONEY_HIVEHOST` to your actual server IP
- [ ] Set `HONEY_HIVEPORT` to the correct port
- [ ] Configure `DB_BACKEND` and `DB_*` settings
- [ ] Add authorized bears to `AUTHORIZED_BEANS` if needed
- [ ] Verify `temp.db` directory is writable
- [ ] Set up monitoring/alerting for bot connection volume
- [ ] Consider rate limiting to avoid abuse of honeypot ports
