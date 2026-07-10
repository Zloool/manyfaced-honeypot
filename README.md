# Many-faced Honeypot

A socket-based Python honeypot designed to explore and study internet crawlers, bots, and automated scanning tools. It impersonates many web services and protocols (WordPress, phpMyAdmin, WebDAV, Jenkins, Redis, MongoDB, SSH, …) and logs bot activity for analysis.

## Quick Start

### Installation

```bash
# 1. Install the package (installs all runtime deps: cryptography)
pip install -e .

# 2. (Optional) Install dev deps for testing/linting
pip install -e ".[dev]"

# 3. Generate a config file (or skip — defaults work for local testing)
manyfaced --generate-config

# 4. Edit the config at ~/.config/manyfaced/config.toml
#    (or override any value with HONEY_ environment variables)
```

### Run

```bash
# Run the CLIENT only (impersonates services on a port)
manyfaced -c 80

# Run the SERVER only (receives encrypted bot reports)
manyfaced -s 666

# Run both together, verbose
manyfaced -c 80 -s 666 -v

# No flags: starts both using the ports from config.toml
manyfaced -v
```

If the package is not installed, the equivalent from the repo root is:

```bash
python -m manyfaced.mfh -c 80 -s 666 -v
```

> **Note:** `mfh.py` at the repo root is a thin legacy shim that calls
> `manyfaced.mfh:run`. Prefer the `manyfaced` console script (or
> `python -m manyfaced.mfh`) — the shim may be removed.

## Architecture Overview

```
                    ┌──────────────────────┐
                    │   manyfaced (CLI)    │
                    │   (process manager)   │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
         ┌─────────┐     ┌──────────┐    ┌──────────────┐
         │ CLIENT  │     │ SERVER   │    │ DASHBOARD     │
         │ (port   │     │ (port    │    │ (read-only,   │
         │ -c PORT)│     │ -s PORT) │    │ if enabled)   │
         └─────────┘     └──────────┘    └──────────────┘
              │                │
              ▼                ▼
     ┌────────────────┐  ┌──────────────┐
     │ Handlers (fake │  │ Storage      │
     │  web services) │  │ DB insert    │
     └────────────────┘  └──────────────┘
```

### Two-Process Model

The honeypot runs as supervised child processes managed by a single parent:

- **CLIENT** (`-c PORT`): Listens on a port and impersonates well-known vulnerable services. When a bot requests paths like `/wp-login.php` or `/phpmyadmin`, the client responds with fake but realistic content from specialized handlers (WordPress, phpMyAdmin, WebDAV, etc.). After serving the fake response, the client **reports back** the bot's IP, raw request, and metadata to the SERVER via an encrypted TCP connection.

- **SERVER** (`-s PORT`): Listens on a separate port for encrypted bot reports from clients. It decrypts the report using a shared AES key, parses the data, and stores it in the database.

- **DASHBOARD** (optional): A read-only stats web view that runs alongside the server only when explicitly enabled in config (see [Stats Dashboard](#stats-dashboard-issue-234)).

Production deployment is automated via GitHub Actions (`.github/workflows/deploy.yml`) on push to `master` — it ships code to the production droplet and restarts the systemd service. CI gates (lint / typecheck / tests) run on pull requests via `.github/workflows/ci.yml`.

### Data Flow

```
Bot → Client (fake HTTP response)
     → Client encrypts bot data with AES → sends to Server
     → Server decrypts → parses JSON → saves to SQLite/PostgreSQL

Client internal:
  Bot request → route to handler → generate response
  Client → send_report() → encrypted TCP to SERVER
```

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c [PORT]` | disabled | Start CLIENT on PORT (impersonates web services) |
| `-s [PORT]` | disabled | Start SERVER on PORT (receives encrypted reports) |
| `-v` | false | Verbose logging mode |
| `--port-mode` | `single` | Port listening mode: `single`, `top`, or `all` |
| `--top-ports` | empty | Comma-separated port list when `--port-mode=top` |
| `--generate-config` | false | Write `~/.config/manyfaced/config.toml` and exit |

### Port Modes

The CLIENT honeypot supports three listening modes:

| Mode | Description | Ports |
|------|-------------|-------|
| `single` | Listen on a single port (default) | `-c PORT` or `HONEY_HONEYPORT` |
| `top` | Listen on the top 50 most-scanned ports | See below |
| `all` | Listen on all 65535 TCP ports | 1–65535 |

**Top 50 ports** (default when `--port-mode=top`):

```text
21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
5432, 5900, 5901, 6379, 8080, 8443, 9200, 11211, 27017, 5672,
15672, 4369, 2181, 9090, 8888, 7001, 7002, 11300–11311, 5000
```

Custom port list for `top` mode:

```bash
manyfaced --port-mode top --top-ports "80,443,8080,3306"
```

**Example usage:**

```bash
# Single port (default, backward compatible)
manyfaced -c 80

# Top 50 most-scanned ports
manyfaced --port-mode top

# All 65535 ports
manyfaced --port-mode all

# Custom port list
manyfaced --port-mode top --top-ports "22,80,443,8080"

# Combined with server
manyfaced --port-mode top -s 666 -v
```

> **Note:** `--port-mode all` spawns a listener per port. This is resource-intensive and may take time to start. Use with caution on production systems.

## Configuration

The honeypot uses a three-layer TOML configuration system:

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
port_mode = "single"        # "single", "top", or "all"
top_ports = ""              # comma-separated, used when port_mode=top

[hive]
hivehost = "127.0.0.1"
hiveport = 8080
hivelogin = "honeybee"
hivepass = "beehive123"     # required shared AES key

[database]
backend = "sqlite"          # "sqlite" or "postgresql"
path = "bots/honeypot.db"
pg_host = "localhost"
pg_port = 5432
pg_db = "honeypot"
pg_user = "postgres"
pg_password = "postgres"
pg_sslmode = "prefer"       # disable/require/prefer/…
pg_dsn = ""                 # full URI; when set, overrides the pg_* fields

[security]
# semicolon-separated "bee_id:key" pairs for authorized client sensors (bees)
authorized_bees = ""
# default encryption key for unknown client identifiers
default_key = ""

[dashboard]
enabled = false
port = 8443
bind = "127.0.0.1"
secret = ""                 # auto-generated by --generate-config
time_range = "24h"          # 24h, 7d, 30d, all

[logging]
file = "bots/honeypot.log"
```

### Environment Variables

All settings can be overridden via environment variables. The `HONEY_` prefix maps to the TOML keys (e.g. `HONEY_HONEYPORT` → `[honeypot] honeyport`). Explicit env vars always win over TOML and code defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEY_HONEYPORT` | `80` | Port for the CLIENT (fake web services) |
| `HONEY_HONEYFOLDER` | `bots` | Folder for client responses |
| `HONEY_PORT_MODE` | `single` | Port listening mode: `single`, `top`, or `all` |
| `HONEY_TOP_PORTS` | _(empty)_ | Comma-separated port list when `port_mode=top` |
| `HONEY_HIVEHOST` | `127.0.0.1` | Server host to report to |
| `HONEY_HIVEPORT` | `8080` | Server port to receive reports |
| `HONEY_HIVELOGIN` | `honeybee` | Bot identification login |
| `HONEY_HIVEPASS` | _(required)_ | Shared AES encryption key — must be set |
| `HONEY_DEFAULT_KEY` | _(required)_ | Default key for unknown client identifiers — must be set |
| `HONEY_AUTHORIZED_BEES` | _(empty)_ | Authorized client sensors (`id:key;id:key`) |
| `HONEY_DB_BACKEND` | `sqlite` | Database backend: `sqlite` or `postgresql` |
| `HONEY_DB_PATH` | `bots/honeypot.db` | SQLite database file path |
| `HONEY_PG_HOST` | `localhost` | PostgreSQL host |
| `HONEY_PG_PORT` | `5432` | PostgreSQL port |
| `HONEY_PG_DB` | `honeypot` | PostgreSQL database name |
| `HONEY_PG_USER` | `postgres` | PostgreSQL username |
| `HONEY_PG_PASSWORD` | _(required)_ | PostgreSQL password |
| `HONEY_PG_SSLMODE` | `prefer` | PostgreSQL TLS mode (`disable`/`require`/`prefer`/…) |
| `HONEY_PG_DSN` | _(empty)_ | PostgreSQL connection URI; when set, overrides the `HONEY_PG_*` fields |
| `HONEY_DASHBOARD_ENABLED` | `false` | Enable the read-only stats dashboard |
| `HONEY_DASHBOARD_PORT` | `8443` | Dashboard listen port (non-standard) |
| `HONEY_DASHBOARD_BIND` | `127.0.0.1` | Dashboard bind address (loopback by default) |
| `HONEY_DASHBOARD_SECRET` | _(auto-generated)_ | Access secret; every request needs `?token=<secret>` |
| `HONEY_DASHBOARD_TIME_RANGE` | `24h` | Default stats window: `24h`, `7d`, `30d`, `all` |
| `HONEY_LOG_FILE` | `bots/honeypot.log` | JSON log file path |
| `HONEY_DUMP_FILE` | `bots/honeypot.dump.jsonl` | JSONL fallback for failed DB writes |
| `HONEY_LOCKFILE` | `~/.config/manyfaced/lock` | Prevents multiple instances |
| `HONEY_ALERT_*` | — | Alerting overrides (webhook, SMTP, Telegram, `log_only`) |

### Stats Dashboard (issue #234)

A read-only web dashboard shows captured-attacker statistics (top services, source IPs, countries/continents, most-probed paths, detected vs. undetected ratio, request volume over time, and the latest raw capture). It is **off by default** and designed to be hostile to probing:

- Only starts when `[dashboard] enabled = true` in `config.toml` (or `HONEY_DASHBOARD_ENABLED=true`) and the server is running.
- Binds to a **non-standard port** (`HONEY_DASHBOARD_PORT`, default `8443`) on **loopback** (`127.0.0.1`) unless you deliberately change `HONEY_DASHBOARD_BIND`.
- Every request must carry `?token=<secret>`. The secret is **auto-generated** by `manyfaced --generate-config` (`secrets.token_urlsafe`, never a static default) and compared with `hmac.compare_digest`. A missing or wrong token returns a generic **404** — the endpoint never advertises itself as an admin panel.
- **Read-only**: no config editing, no mutation, no user management. Dashboard access is logged separately (`manyfaced.web.dashboard.access`) so viewing the dashboard never pollutes the `honeypot_bears` capture dataset.
- All dynamic values are HTML-escaped on render.

```bash
# Start the server with the dashboard enabled in config.toml:
manyfaced -s 8080

# Open (token from config.toml [dashboard] secret):
#   http://127.0.0.1:8443/?token=<HONEY_DASHBOARD_SECRET>&range=7d
```

### Backward compatibility

You can still import the global settings object from `manyfaced.common.config`:

```python
from manyfaced.common.config import settings
HONEYPORT = settings.HONEYPORT
HIVELOGIN = settings.HIVELOGIN
# Works exactly as before, delegates to Config behind the scenes
```

Old code that did `from manyfaced.common.settings import HONEYPORT` is no longer supported — use `from manyfaced.common.config import settings` instead.

## Database

### SQLite (Default)

Data is stored in the `honeypot_bears` table. No manual setup needed — the database is auto-created on first insert. The schema is defined in `manyfaced/db/sql_builder.py`:

```sql
CREATE TABLE IF NOT EXISTS honeypot_bears (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_ip           TEXT NOT NULL,
    hostname         TEXT,
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
    login            TEXT,
    bot_profile_data TEXT,
    listen_port      INTEGER,
    bot_asn          TEXT,
    bot_org          TEXT,
    classification   TEXT,
    benign_source    TEXT,
    UNIQUE(bot_ip, timestamp)
);
```

### PostgreSQL

PostgreSQL is a **first-class, optional** storage backend. SQLite stays the default; Postgres is used only when an operator sets `HONEY_DB_BACKEND=postgresql`. The two backends share the same `honeypot_bears` schema and the same `insert`/`recent_records`/`aggregate_stats` API, so the dashboard, cron retention, and backup tooling work unchanged.

```sql
CREATE TABLE IF NOT EXISTS honeypot_bears (
    id               SERIAL PRIMARY KEY,
    bot_ip           TEXT NOT NULL,
    hostname         TEXT,
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
    login            TEXT,
    bot_profile_data TEXT,
    listen_port      INTEGER,
    bot_asn          VARCHAR(32),
    bot_org          VARCHAR(255),
    classification   VARCHAR(16),
    benign_source    VARCHAR(64),
    UNIQUE(bot_ip, timestamp)
);
```

**Backend selection (both work):** `HONEY_DB_BACKEND=postgresql` (env) **or** `backend = "postgresql"` in the `[database]` section of `config.toml`. The TOML `pg_*` values (`pg_host`, `pg_port`, `pg_db`, `pg_user`, `pg_password`, `pg_sslmode`, `pg_dsn`) are honored too — explicit env vars and constructor args still override them.

**Connection / TLS (issue #243 #9):** set `HONEY_PG_SSLMODE` (default `prefer`) for managed/remote Postgres, or set `HONEY_PG_DSN` to a full connection URI (e.g. `postgres://user:pass@host:5432/db`) — when a DSN is set it is passed straight to `psycopg2.connect(dsn=...)` and the discrete `HONEY_PG_*` host/port params are ignored.

**Connection lifecycle:** one `PostgreSQLStorage` instance is created per process and reused for every captured report (a fresh connection per insert would overwhelm Postgres under bot load). A dropped connection is transparently reconnected before the next write, and a transient outage dumps the record to the JSONL fallback file (same safety valve SQLite uses) instead of silently losing it.

**Verify a deploy writes (not just listens):** `scripts/verify_deploy.sh` is backend-aware — for Postgres it inserts a probe row through the real `get_storage()` path and reads it back via an independent `psycopg2` connection, so the "starts but records nothing" regression is caught on Postgres too.

**Backups:** `scripts/backup-db.sh` and `backup_database()` are backend-aware. For Postgres they shell out to `pg_dump -Fc` (password via the `PGPASSWORD` env var, never interpolated into the command) and rotate the `.dump` files — SQLite keeps its existing `.sqlite` WAL checkpoint + copy flow.

**Migrating SQLite → Postgres (one-time ETL):** stop the service, then run `python scripts/migrate_sqlite_to_postgres.py` — it streams `honeypot_bears` rows in batches (keyset pagination on `id`) into Postgres via the existing `ON CONFLICT(bot_ip, timestamp) DO NOTHING` dedup, so it is safely re-runnable. Then flip `HONEY_DB_BACKEND=postgresql`, restart, and confirm `verify_deploy.sh` passes. Keep the old `.sqlite` as rollback until retention parity is confirmed.

**Schema migration (known limitation):** the idempotent `CREATE TABLE IF NOT EXISTS` adds *new* columns to a fresh install, and `PostgreSQLStorage._init_db` adds the `listen_port` column online when missing. There is **no** path to reconcile a *renamed/retyped* column on a drifted live PG schema (the way `migrate_db.py` does for SQLite) — recreate the table from the code's expected schema if you hit that.

**Packaging:** the `psycopg2-binary` dependency is installed via the `[postgres]` extra — the Docker image builds with `pip install .[postgres]`, and CI installs `--extra postgres` so the real-Postgres test job can run. SQLite-only deploys do not pull the C-extension wheel.

## Handlers (Impersonated Services)

The client impersonates **47+** different web service and protocol endpoints. When a bot requests a known path or speaks a known wire protocol, the client serves a fake but realistic response from the appropriate handler. Each handler defines `PATH_PATTERNS` (or protocol detection) and implements `matches_path()` / `generate_response()`.

Representative handlers:

| Handler | Domain | Key Paths |
|---------|--------|-----------|
| WordPressHandler | wordpress | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`, `/wp-content/` |
| PhpMyAdminHandler | phpmyadmin | `/phpmyadmin/`, `/pma/` |
| JenkinsHandler | jenkins | `/jenkins/`, `/manage/` |
| TomcatHandler | tomcat | `/manager/`, `/host-manager/`, `/server-status/` |
| DrupalHandler | drupal | `/user/login`, `/admin/` |
| CPanelHandler | cpanel | `/cpanel/`, `/webmail/` |
| WebDAVHandler | webdav | `/webdav/`, `/dav/` |
| BitrixHandler | bitrix | `/bitrix/` |
| ConfigDisclosureHandler | config_disclosure | `/.env`, `/wp-config.php.bak`, `/config.json` |
| GenericHandler | generic | Fallback for unknown paths |

Full set of impersonated domains: `atlassian`, `aws_creds`, `bitrix`, `citrix`, `coldfusion`, `config_disclosure`, `cpanel`, `dbadmin`, `docker`, `drupal`, `elastic`, `elasticsearch`, `env_disc`, `exploit_cgi`, `fingerprint_probe`, `fortinet`, `generic`, `gitlab`, `grafana`, `hnap`, `iot`, `jenkins`, `joomla`, `jupyter`, `kubernetes`, `langflow`, `laravel`, `magento`, `mcp`, `nextjs`, `nginx`, `nginx_probe`, `phpmyadmin`, `phpunit`, `plex`, `rabbitmq`, `redis_admin`, `sharepoint`, `solr`, `splunk`, `spring`, `squid`, `thinkphp`, `tomcat`, `webdav`, `wordpress`, `zabbix` — plus protocol-level probes for SSH, Telnet, Redis, MongoDB, TLS, SMB, and DNS.

Handler implementations are in `manyfaced/handlers/` (and `manyfaced/handlers/routes/` for service-specific route handlers). See `docs/DEVELOPER.md` for how to add a new face.

## Project Structure

```
manyfaced-honeypot/
├── pyproject.toml                  # PEP 621 package metadata & build config
├── mfh.py                          # Legacy shim → manyfaced.mfh:run
├── manyfaced/
│   ├── __init__.py                 # Package init
│   ├── mfh.py                      # CLI entry point (multiprocess manager)
│   ├── settings.toml.example       # Example TOML config
│   ├── common/
│   │   ├── arguments.py            # CLI argument parser
│   │   ├── bearstorage.py          # BearRequests dataclass (capture record)
│   │   ├── config.py               # Modern Config (TOML + env + defaults)
│   │   ├── config_resolver.py      # TOML/env precedence logic
│   │   ├── classification.py       # benign vs. malicious source classification
│   │   ├── credential_extractor.py # Extracts creds from captured payloads
│   │   ├── faces.py                # Face/domain registry
│   │   ├── geolocate.py            # IP → country/continent/ASN
│   │   ├── httphandler.py          # HTTPRequest wrapper class
│   │   ├── logging_setup.py        # Logging configuration
│   │   ├── metrics.py              # Live in-process metrics (no deps)
│   │   ├── myenc.py                # AESCipher (AES-256-CBC encrypt/decrypt)
│   │   ├── ports.py                # Top-50 port list
│   │   ├── protocol.py             # Protocol detection utilities
│   │   ├── status.py               # Constants (detection IDs)
│   │   └── utils.py                # Socket helpers, dump_file
│   ├── server/
│   │   └── server.py               # ServerHandler + TCP listener
│   ├── client/
│   │   ├── client.py               # create_server(), send_report()
│   │   ├── report_sender.py        # Encrypted report delivery
│   │   └── ssh_creds.py            # SSH credential handling
│   ├── handlers/
│   │   ├── base_handler.py         # BaseHandler ABC, BotProfile
│   │   ├── http_handler.py         # HTTPHandler (CLIENT-side request processing)
│   │   ├── router.py               # HandlerRouter (routes requests)
│   │   ├── report_queue.py        # Async report delivery pool
│   │   ├── routes/                 # Service-specific route handlers
│   │   └── *.py                    # Service handlers (WordPress, phpMyAdmin, etc.)
│   ├── db/
│   │   ├── dbconnect.py            # BearRequests dataclass + Insert()
│   │   ├── sql_builder.py          # CREATE TABLE / INSERT DDL (SQLite + PG)
│   │   └── storage.py              # SQLiteStorage, PostgreSQLStorage
│   ├── web/
│   │   └── dashboard.py            # Read-only stats dashboard
│   └── data/
│       └── benign_sources.toml     # Curated research-scanner allowlist
├── systemd/                        # Systemd service files + logrotate config
├── templates/                      # honeypot.env.example, iptables rules
├── scripts/                        # backup-db.sh, verify_deploy.sh, migrations
├── docs/                           # DEVELOPER.md, CONTRIBUTING.md, MAINTENANCE.md
├── test/                           # pytest suite (~76% coverage target)
└── .github/workflows/              # ci.yml, deploy.yml, codeql.yml, docs-drift.yml, triage-comment.yml
```

## Running Tests

```bash
# From project root (coverage gate enforced at 76%, matching CI):
pip install -e ".[dev]"
pytest -v --tb=short

# Lint / format / typecheck:
ruff check .
ruff format --check .
basedpyright manyfaced/
```

See `test/test_integration.py` for full pipeline tests (socket → decrypt → save → query).

## Key Constants

Defined in `manyfaced/common/status.py`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `UNKNOWN_HTTP` | 4294967294 | Path not found in faces dict |
| `UNKNOWN_NON_HTTP` | 4294967292 | Non-HTTP request type |
| `SSH_CLIENT` | 4294967293 | SSH protocol probe |
| `UNKNOWN_TLS` | 4294967287 | TLS ClientHello (handshake) |
| `UNKNOWN_SMB` | 4294967286 | SMB/NBT (NetBIOS Session Service) probe |
| `UNKNOWN_TELNET` | 4294967285 | Telnet probe |
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
| psycopg2-binary>=2.9 (postgres extra) | PostgreSQL driver |
| pytest + pytest-cov (dev) | Testing framework with coverage reporting |
| basedpyright (dev) | Static type checking |
| ruff==0.15.20 (dev) | Linting and formatting |

Install all deps in one command:

```bash
pip install -e .                # runtime only
pip install -e ".[dev]"         # runtime + dev
pip install -e ".[dev,postgres]"  # + PostgreSQL driver
```

Requires Python 3.12+.

## Container / Docker

The honeypot ships a `Dockerfile`, `.dockerignore`, and `compose.yaml` (issue #146) for reproducible local dev, CI, and a future containerized deploy (#149). The image runs as the non-root `honeypot` user and persists captures in a named volume at `/opt/manyfaced/bots`.

```bash
# Local dev / test:
cp templates/honeypot.env.example .env   # edit secrets (HIVEPASS etc.)
docker compose up --build

# One-off config generation inside the image:
docker compose run --rm honeypot --generate-config

# Validate the compose file without starting anything:
docker compose config --quiet
```

Honeypot ports are wired from the `HONEY_*` env scheme (see `templates/honeypot.env.example`). In `top` mode the honeypot binds high container ports (privileged host ports are redirected via iptables — see `templates/setup-iptables-privileged-ports.sh`); `compose.yaml` maps a representative subset for local testing. To bind low host ports directly, grant the container `NET_BIND_SERVICE` (commented in `compose.yaml`).

The image build is verified on every push/PR by the **Build Image** workflow, which builds the image and smoke-tests `manyfaced --generate-config` plus `docker compose config`.

## Known Issues & TODOs

- `bot_tracert` field in the schema is marked TODO (never implemented)
- `utils.py:dump_file()` writes to `DUMP_FILE` (JSONL format) using `json.dumps()` — safe with untrusted data
