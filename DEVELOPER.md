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

The config file auto-generates from `manyfaced/settings.toml.example` on first run via `manyfaced --generate-config`.

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
2. Routes to the appropriate service handler via HandlerRegistry
3. Service handler generates realistic honeypot response
4. Spawns `send_report()` process to send encrypted report back to server
5. Returns the fake HTTP response to the bot

#### HandlerRegistry — `handlers/registry.py`

Manages and routes HTTP requests to specialized handlers.
Maintains a registry of handlers and routes based on path patterns.
Handlers are checked in registration order; first match wins.

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
2. `get_key()` looks up `AUTHORISEDBEARS` dict by identifier
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

1. Create a new class in `manyfaced/handlers/` that extends `HTTPHandlerBase`
2. Define `domain` and `PATH_PATTERNS`
3. Implement `matches_path()` and `generate_response()`
4. Add login handling with `handle_login()` if the service has auth
5. Register the handler in `handlers/registry.py`
6. Export it from `handlers/__init__.py`

```python
from manyfaced.handlers.base_handler import HTTPHandlerBase
import datetime

class MyServiceHandler(HTTPHandlerBase):
    domain = "my_service"
    PATH_PATTERNS = ["/my-service", "/my-service/"]
    DETECTED_ID = 1

    def matches_path(self, path: str) -> bool:
        path_lower = path.lower().split("?")[0]
        return any(path_lower.startswith(p) for p in self.PATH_PATTERNS)

    def generate_response(self, path, raw_request, bot_ip, headers=None):
        profile = self.get_or_create_profile(bot_ip)
        request_data = {
            "path": path,
            "method": self._extract_method(raw_request),
            "headers": dict(headers) if headers else {},
            "raw": raw_request,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        if method == "POST" and "login" in path.lower():
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        body = self._main_page()
        response = self._build_http_response(body, path)
        self._response_count += 1
        return response, self.DETECTED_ID

    def _main_page(self):
        return "<html><body><h1>My Service</h1></body></html>"

    def _login_failed_response(self):
        body = "<html><body><h1>Login Failed</h1></body></html>"
        return self._build_http_response(body, "/my-service/login")

    def _extract_method(self, raw_request):
        parts = raw_request.split()
        return parts[0].upper() if parts else "GET"

    def _build_http_response(self, body, path, status="200 OK"):
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: Apache/2.4.57 (Ubuntu)\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        return response.encode("iso-8859-1")
```

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
- Set `AUTHORISEDBEARS` via `sys.modules` dict, not env var

## Security Notes

1. **pickle.dump_file()** — `common/utils.py` uses `pickle` for fallback data storage. This is unsafe with untrusted data. The file is written to `temp.db` in the working directory.

2. **Shared secrets** — `HIVEPASS` is the shared encryption key. Never commit real keys. Use environment variables or `settings.toml.example` (gitignored).

3. **AUTHORISEDBEARS** — In server mode, this dict determines which bots are authorized. If empty/no entries match, decryption will fail.

4. **geoip2 dependency** — The `python-geoip-geolite2` package requires a GeoLite2 database to be installed separately. Without it, country/continent fields will be empty.

5. **Subprocess git pull** — The `update.py:pull()` runs `git pull` and `pip install -r requirements.txt` in a subprocess. This is a security risk in production — consider pinning versions.

## Handler Coverage Analysis

### Current Handlers (11 total)

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

### Adding a New Handler

1. Create `manyfaced/handlers/<name>_handler.py` extending `HTTPHandlerBase`
2. Define `domain`, `PATH_PATTERNS`, and `generate_response()` method
3. Register in `handlers/__init__.py` (add to `_HANDLER_CLASSES`)
4. Add service info to `generic_handler._SERVICE_INFO` for monster page inclusion
5. Write tests in `test/test_<name>_handler.py`

See existing handlers for patterns — `wordpress_handler.py` is a good reference for a complete implementation.

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
- [ ] Add authorized bears to `AUTHORISEDBEARS` if needed
- [ ] Verify `temp.db` directory is writable
- [ ] Set up monitoring/alerting for bot connection volume
- [ ] Consider rate limiting to avoid abuse of honeypot ports
