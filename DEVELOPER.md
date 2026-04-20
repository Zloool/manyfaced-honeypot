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

The config file auto-generates from `manyfaced/common/settings.toml.example` on first run via `manyfaced --generate-config`.

## Codebase Deep Dive

### Entry Point: mfh.py

```
mfh.py (main)
  ├── settings.py.example → settings.py (auto-copy if missing)
  ├── args = parse()          # CLI parsing
  ├── Process(client)        # client.main() in child
  ├── Process(server)        # server.main() in child
  └── Process(updater)     # trigger() in child (optional)
```

Both client and server run as separate `multiprocessing.Process` instances. They communicate over raw TCP with encrypted payloads.

### Process: manyfaced/ Package

```
manyfaced/
├── common/        # Shared utilities
├── client/        # Honeypot CLIENT (impersonates web services)
├── server/        # Honeypot SERVER (collects bot reports)
├── handlers/      # Request processing (ABC pattern)
└── db/            # Data persistence layer
```

### Key Classes

#### BaseHandler (ABC) — `handlers/base_handler.py`

Core request handling pipeline:

```python
handle_request(message)
  └── parse_message()      # Split on ":" into [identifier, encrypted]
  └── decrypt_message()    # AES decrypt with key from get_key()
  └── parse_json()          # Deserialize JSON data
  └── process_request()     # Abstract — implemented by subclass

get_key():        # Abstract — return decryption key for identifier
process_request(): # Abstract — handle decrypted data
```

#### HTTPHandler — `handlers/http_handler.py`

CLIENT-side handler. When a bot connects:
1. `get_key()` returns `HIVEPASS` (shared key for all bots)
2. `process_request()` calls `get_honey_http()` to serve a fake face from `client.py`'s `faces` dict
3. Spawns `send_report()` process to send encrypted report back to server
4. Returns the fake HTTP response to the bot

#### ServerHandler — `server/server.py`

SERVER-side handler. When a report arrives:
1. `get_key()` looks up `AUTHORISEDBEARS` dict by identifier
2. `process_request()` spawns `save_data()` process to insert into DB
3. Returns "200 OK" as response

#### BearStorage — `common/bearstorage.py`

Data container for bot information:
- IP, raw request, timestamp
- Path, command, version, User-Agent
- Country/continent/timezone (via `geoip2.lookup()`)
- DNS name (via `socket.gethostbyaddr()`)

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

## How to Add New Faces

Faces are URL-path → response-file mappings. Two place to add faces depending on the service type.

### Step 1: Add path mapping

For WordPress-specific paths, edit `manyfaced/client/client.py` (the `faces` dict at the top).

```python
# In client.py:
faces = {
    ...
    "/new/fake/path": "response_name",  # Add this line
}
```

### Step 2: Create response file

Create `manyfaced/client/responses/response_name` (no extension, or `.html`, `.xml`, etc.).

Examples:
- `wplogin.html` → fake WordPress login page (HTML)
- `wpconfig.php` → fake WordPress config (PHP)
- `webdav.xml` → fake WebDAV response (XML)
- `zero` → bare-bones default page

### Step 3: Add special routing (if needed)

If the face needs special treatment (like `webdav.xml` for 207 Multi-Status or `robots` for robots.txt), add routing logic in `get_honey_http()` in `client.py`:

```python
if face == "webdav.xml":
    output_data = honey_webdav(bot_ip)
elif face == "robots":
    output_data = honey_robots()
else:
    output_data = honey_generic(face)
```

## How to Add a New Handler

1. Create a new class in `manyfaced/handlers/` that extends `BaseHandler`
2. Implement `get_key()` and `process_request()`
3. Use the handler where appropriate in client/server code

```python
from manyfaced.handlers.base_handler import BaseHandler

class MyHandler(BaseHandler):
    def get_key(self, identifier):
        return HIVEPASS

    def process_request(self, data):
        # Handle decrypted bot data
        return output_response
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
├── test_integration.py   # Full pipeline: socket → decrypt → DB → query
├── test_client.py        # Client-specific unit tests
└── conftest.py           # Shared test utilities
```

### Key testing patterns
- Use `multiprocessing.Process` to test server/client behavior
- Use real `AESCipher` for encryption roundtrips
- Check SQLite DB directly for persistence tests
- Mock the `geoip2` module (it can't be imported in tests)
- Set `AUTHORISEDBEARS` via `sys.modules` dict, not env var

## Security Notes

1. **pickle.dump_file()** — `common/utils.py` uses `pickle` for fallback data storage. This is unsafe with untrusted data. The file is written to `temp.db` in the working directory.

2. **Shared secrets** — `HIVEPASS` is the shared encryption key. Never commit real keys. Use environment variables or `settings.py` (gitignored).

3. **AUTHORISEDBEARS** — In server mode, this dict determines which bots are authorized. If empty/no entries match, decryption will fail.

4. **geoip2 dependency** — The `python-geoip-geolite2` package requires a GeoLite2 database to be installed separately. Without it, country/continent fields will be empty.

5. **Subprocess git pull** — The `update.py:pull()` runs `git pull` and `pip install -r requirements.txt` in a subprocess. This is a security risk in production — consider pinning versions.

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
