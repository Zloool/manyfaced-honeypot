# Many-faced Honeypot

A socket-based Python honeypot designed to explore and study internet crawlers, bots, and automated scanning tools. It impersonates various web services (WordPress, phpMyAdmin, WebDAV, etc.) and logs bot activity for analysis.

## Quick Start

### Installation (recommended)

```bash
# 1. Install the package (installs all runtime deps: cryptography, geoip)
pip install -e .

# 2. (Optional) Install dev deps for testing
pip install -e ".[dev]"

# 3. Generate a config file (or skip — defaults work for local testing)
manyfaced --generate-config

# 4. Edit config file at ~/.config/manyfaced/config.toml
#    (or use environment variables with HONEY_ prefix)
```

### Quick Run (legacy)

For development you can also run without installing:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate config example
cp manyfaced/common/settings.toml.example manyfaced/common/config.toml
# Edit config.toml with your keys and credentials

# 3. Run the client only (impersonates web services)
python3 mfh.py -c 80

# 4. Run the server only (receives encrypted bot reports)
python3 mfh.py -s 666

# 5. Run both together
python3 mfh.py -c 80 -s 666

# 6. Verbose mode (logs bot interactions)
python3 mfh.py -c 80 -s 666 -v

# 7. Enable self-updating client
python3 mfh.py -c 80 -s 666 -u
```

## Architecture Overview

```
                    ┌──────────────────────┐
                    │       mfh.py         │
                    │   (process manager)   │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
         ┌─────────┐     ┌──────────┐    ┌──────────┐
         │ CLIENT  │     │ SERVER   │    │ UPDATER  │
         │ (port   │     │ (port    │    │ (optional│
         │ -c PORT)│     │ -s PORT) │    │  -u      │
         └─────────┘     └──────────┘    └──────────┘
              │                │
              ▼                ▼
     ┌────────────────┐  ┌──────────────┐
     │ Faces (fake    │  │ BearStorage  │
     │  web services) │  │ DB insert    │
     └────────────────┘  └──────────────┘
```

### Two-Process Model

The honeypot runs two independent processes:

- **CLIENT** (`-c PORT`): Listens on a port and impersonates well-known vulnerable services. When a bot requests paths like `/wp-login.php` or `/phpmyadmin`, the client responds with fake but realistic content from `manyfaced/client/responses/`. After serving the fake response, the client **reports back** the bot's IP, raw request, and metadata to the SERVER via an encrypted TCP connection.

- **SERVER** (`-s PORT`): Listens on a separate port for encrypted bot reports from clients (or from external clients). It decrypts the report using a shared AES key, parses the data, and stores it in the database via `Process` (spawns a background subprocess for the insertion).

- **UPDATER** (`-u`): Optional process that sleeps 1 hour, pulls latest code, installs deps, and auto-restarts the honeypot.

### Data Flow

```
Bot → Client (fake HTTP response)
     → Client encrypts bot data with AES → sends to Server
     → Server decrypts → parses JSON → saves to SQLite/PostgreSQL

Client internal:
  Bot request → look up path in faces/ → return fake page
  Client → send_report() → encrypted TCP to SERVER
```

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c [PORT]` | disabled | Start CLIENT on PORT (impersonates web services) |
| `-s [PORT]` | disabled | Start SERVER on PORT (receives encrypted reports) |
| `-u` | false | Enable auto-update (pulls from git every hour) |
| `-v` | false | Verbose logging mode |
| `-p` | false | Proxy mode (sets X-Forwarded-For handling) |

## Configuration

The honeypot uses a modern, three-layer TOML configuration system:

1. **Code defaults** (hardcoded in `manyfaced/common/config.py`)
2. **TOML config file** — `~/.config/manyfaced/config.toml` (XDG base dir)
3. **Environment variables** (prefix `HONEY_`, always highest precedence)

### Generating a config file

```bash
# Install the package first
pip install -e .

# Generate config file (creates ~/.config/manyfaced/config.toml)
manyfaced --generate-config

# Edit it
nano ~/.config/manyfaced/config.toml
```

### TOML Config file format

```toml
[honeypot]
honeyport = 80
honeyfolder = "bots"

[hive]
hivehost = "127.0.0.1"
hiveport = 8080
hivelogin = "honeybee"
hivepass = "beehive123"

[database]
backend = "sqlite"
path = "bots/honeypot.db"
pg_host = "localhost"
pg_port = 5432
pg_db = "honeypot"
pg_user = "postgres"
pg_password = "postgres"

[security]
# semicolon-separated bearid:key pairs
authorised_bears = ""
```

### Environment Variables

All settings can be overridden via environment variables. The `HONEY_` prefix maps to the TOML keys:

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEY_HONEYPORT` | `80` | Port for the CLIENT (fake web services) |
| `HONEY_HONEYFOLDER` | `bots` | Folder for client responses |
| `HONEY_HIVEHOST` | `127.0.0.1` | Server host to report to |
| `HONEY_HIVEPORT` | `8080` | Server port to receive reports |
| `HONEY_HIVELOGIN` | `honeybee` | Bot identification login |
| `HONEY_HIVEPASS` | `beehive123` | Shared AES encryption key |
| `DB_BACKEND` | `sqlite` | Database backend: `sqlite` or `postgresql` |
| `DB_PATH` | `bots/honeypot.db` | SQLite database file path |
| `DB_PG_HOST` | `localhost` | PostgreSQL host |
| `DB_PG_PORT` | `5432` | PostgreSQL port |
| `DB_PG_DB` | `honeypot` | PostgreSQL database name |
| `DB_PG_USER` | `postgres` | PostgreSQL username |
| `DB_PG_PASSWORD` | `postgres` | PostgreSQL password |

### Backward compatibility

For backward compatibility, `manyfaced/common/settings.py` still works as a thin wrapper:

```python
from manyfaced.common.settings import HONEYPORT, HIVELOGIN
# Works exactly as before, delegates to Config behind the scenes
```

## Database

### SQLite (Default)

Data is stored in `honeypot_bears` table. No manual setup needed — the database is auto-created on first insert.

```sql
CREATE TABLE honeypot_bears (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_ip           TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    request_path     TEXT,
    request_command  TEXT,
    request_version  TEXT,
    request_raw      TEXT,
    bot_user_agent   TEXT,
    bot_country      TEXT,
    bot_continent    TEXT,
    bot_tracert      TEXT,
    bot_dns_name     TEXT,
    detected_id      INTEGER,
    hive_id          INTEGER,
    login            TEXT
);
```

### PostgreSQL

Set `HONEY_DB_BACKEND=postgresql` and configure the `HONEY_PG_*` environment variables.

## Faces (Impersonated Services)

The client impersonates 70+ different web service endpoints. When a bot requests a known path, the client serves a fake but realistic response from `manyfaced/client/responses/`:

| Fake Service | Response Files |
|-------------|----------------|
| WordPress login | `wplogin.html` |
| WordPress debug log | `wp-content.html` |
| WordPress config | `wpconfig.php` |
| phpMyAdmin | `phpadmin.php`, `phpadminsetup.php` |
| WebDAV | `webdav.xml`, `webdav.html` |
| Bitrix admin | `bitrix.html` |
| Generic/unknown | `zero` (77 bytes) |

The complete list of detected paths is in `manyfaced/client/client.py` (the `faces` dict at the top of the file).

## Project Structure

```
manyfaced-honeypot/
├── pyproject.toml                  # PEP 621 package metadata & build config
├── mfh.py                          # Main entry point & process manager
├── manyfaced/
│   ├── __init__.py                 # Package init
│   ├── common/
│   │   ├── config.py               # Modern Config (TOML + env + defaults)
│   │   ├── settings.py             # Backward-compat shim (delegates to Config)
│   │   ├── settings.toml.example   # Template config (in-package copy)
│   │   ├── arguments.py            # CLI argument parser
│   │   ├── handler.py              # DEPRECATED (use handlers/base_handler.py)
│   │   ├── httphandler.py          # HTTPRequest wrapper class
│   │   ├── myenc.py                # AESCipher (AES-256-CBC encrypt/decrypt)
│   │   ├── bearstorage.py          # BearStorage data container
│   │   ├── status.py               # Constants (timeouts, detection IDs)
│   │   ├── update.py               # Auto-update logic
│   │   └── utils.py                # Socket helpers, dump_file
│   ├── server/
│   │   └── server.py               # ServerHandler + TCP listener
│   ├── client/
│   │   ├── client.py               # Face routing, responses, create_server()
│   │   └── responses/              # Fake web service content (10 files)
│   ├── handlers/
│   │   ├── base_handler.py         # BaseHandler ABC (parse, decrypt, route)
│   │   └── http_handler.py         # HTTPHandler (CLIENT-side request processing)
│   └── db/
│       ├── dbconnect.py            # BearRequests dataclass + Insert()
│       ├── storage.py              # SQLiteStorage, PostgreSQLStorage, get_storage()
│       ├── dbscript.sql            # Legacy ClickHouse schema
│       └── README.md               # Database backend docs
├── test/
│   ├── conftest.py                 # Test utilities
│   ├── test_integration.py         # Full pipeline integration tests
│   └── test_client.py              # Client unit tests
├── requirements.txt                # Legacy manual deps
├── pytest.ini                      # pytest config
└── .gitignore
```

## Running Tests

```bash
# From project root:
cd /home/zlol/manyfaced-honeypot
/usr/bin/python3 -m pytest test/ -v
```

See `test/test_integration.py` for full pipeline tests (socket → decrypt → save → query).

## Key Constants

Defined in `manyfaced/common/status.py`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `UNKNOWN_HTTP` | 4294967294 | Path not found in faces dict |
| `UNKNOWN_NON_HTTP` | 4294967292 | Non-HTTP request type |
| `BOT_TIMEOUT` | 0.25s | Time to wait for complete bot data |
| `CLIENT_TIMEOUT` | 2s | Socket recv timeout |

## Encryption Format

Messages between client and server use AES-256-CBC with:

- Key derivation: `SHA-256(HIVEPASS)` → 32 bytes
- IV: 16 random bytes prepended to ciphertext
- Encoding: `base64(IV + ciphertext)`
- Message format: `identifier:encrypted_data`
- Plaintext: JSON with fields: `ip`, `raw_request`, `timestamp`, `parsed_request`, `is_detected`, `HIVELOGIN`

## Dependencies

| Package | Purpose |
|------|-------|
| cryptography>=41.0 | AES-256-CBC encryption for client-server comms |
| python-geoip | IP geolocation for bot attribution |
| python-geoip-geolite2 | GeoLite2 database for geolocation |
| pytest (dev) | Testing framework |

Install all deps in one command:

```bash
pip install -e .          # runtime only
pip install -e ".[dev]"   # runtime + dev
```

## Known Issues & TODOs

- `manyfaced/common/handler.py` is DEPRECATED but still present
- `tracert` field in BearStorage is marked TODO (never implemented)
- `settings.py` uses `__getattr__` magic for AUTHORISEDBEARS (test note: must set via sys.modules)
- `utils.py:dump_file()` uses unsafe pickle (see [DEVELOPER.md](./DEVELOPER.md#security))
- ClickHouse support replaced with SQLite/PostgreSQL but ClickHouse SQL file still in repo
