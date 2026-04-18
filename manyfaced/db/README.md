# manyfaced-db

## Storage System

This honeypot supports **SQLite** and **PostgreSQL** as database backends.

### SQLite (Default)

SQLite is the default backend. The database file is **auto-created on first insert** -- no manual setup needed.

The default DB path is `bots/honeypot.db` (configurable via env var `DB_PATH`).

### PostgreSQL (Optional)

To use PostgreSQL instead:

1. Set your connection environment variables:
   - `HONEY_PG_HOST` - PostgreSQL host
   - `HONEY_PG_PORT` - PostgreSQL port
   - `HONEY_PG_USER` - PostgreSQL username
   - `HONEY_PG_PASSWORD` - PostgreSQL password
   - `HONEY_PG_DB` - PostgreSQL database name

2. Set `HONEY_DB_BACKEND=postgresql`

### Switching Backends

Just set the `HONEY_DB_BACKEND` environment variable:

```bash
# Use SQLite (default)
HONEY_DB_BACKEND=sqlite

# Use PostgreSQL
HONEY_DB_BACKEND=postgresql
```

No code changes needed -- the backend is selected at runtime based on the env var.

### Schema

All data is stored in a single `honeypot_bears` table with the following columns:

| Column            | Type    | Description                    |
|-------------------|---------|--------------------------------|
| id                | integer | Primary key                    |
| bot_ip            | text    | IP address of the bot          |
| hostname          | text    | Bot's reported hostname        |
| timestamp         | text    | Request timestamp              |
| request_path      | text    | HTTP request path              |
| request_command   | text    | HTTP command (GET, POST, etc.) |
| request_version   | text    | HTTP version                   |
| request_raw       | text    | Raw request data               |
| bot_user_agent    | text    | Bot's User-Agent string        |
| bot_country       | text    | Detected country               |
| bot_continent     | text    | Detected continent             |
| bot_tracert       | text    | Traceroute information         |
| bot_dns_name      | text    | DNS name of the bot            |
| detected_id       | text    | Detected bot identification    |
| hive_login        | text    | Hivescape login info           |

### Migration Note

**Old ClickHouse SQL migration files have been removed.** There is no migration needed for SQLite -- the database is created automatically on first use.
