# Configuration Guide

## settings.py — the Heart of the Honeypot

If `manyfaced/common/settings.py` doesn't exist, it's auto-generated from `settings.py.example` on first run. This file controls every aspect of the honeypot's behavior.

> **Tip:** You can override any setting via environment variable. See the table below for the mapping.

### Quick Setup

```bash
# Copy the example template
cp manyfaced/common/settings.py.example manyfaced/common/settings.py

# Edit it (or use env vars as described below)
nano manyfaced/common/settings.py
```

## Settings Reference

### Encryption Key

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `HIVEPASS` | `HONEY_HIVEPASS` | `beehive123` | Shared AES-256-CBC key used by all clients to encrypt bot reports. **Change this before deploying to production.** |

### Database Settings

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `DB_BACKEND` | `DB_BACKEND` | `sqlite` | Choose between `sqlite` and `postgresql` |
| `DB_PATH` | `DB_PATH` | `bots/honeypot.db` | Path to SQLite database file (ignored if PostgreSQL) |

### PostgreSQL Settings (for PostgreSQL backend)

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `DB_PG_HOST` | `HONEY_PG_HOST` | `localhost` | PostgreSQL server hostname |
| `DB_PG_PORT` | `HONEY_PG_PORT` | `5432` | PostgreSQL server port |
| `DB_PG_DB` | `HONEY_PG_DB` | `honeypot` | Database name to connect to |
| `DB_PG_USER` | `HONEY_PG_USER` | `postgres` | PostgreSQL username |
| `DB_PG_PASSWORD` | `HONEY_PG_PASSWORD` | `postgres` | PostgreSQL password |

### Honeypot Targeting

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `IP_DETECT` | — | — | (unused, placeholder) |
| `IP_DETECT` | — | — | (unused, placeholder) |
| `IP_DETECT` | — | — | (unused, placeholder) |

### Bot Identification

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `HIVELOGIN` | `HONEY_HIVELOGIN` | `honeybee` | Bot identification string. Sent as the `HIVELOGIN`/`identifier` field in encrypted reports. |

### GeoIP Settings

Required by `python-geoip-geolite2` for IP-to-country/continent mapping.

```python
# Create directories for GeoLite2 database
mkdir -p mygeoip/GeoIP
# Download GeoLite2 databases and place .dat files here
```

| Setting | Env Var | Default |
|---------|---------|-------|
| `GEOIP_PATH` | — | `mygeoip/GeoIP/` |
| `GEOIP_PATH2` | — | `mygeoip/GeoIP2/` |

> **Note:** Without the GeoLite2 database files, `bot_country` and `bot_continent` fields will be empty in the database.

## Authorization (Server Only)

### AUTHORIZED_BEANS

Dict mapping bot identifiers to their encryption keys. Only bots whose identifier appears here will have their reports accepted.

```python
AUTHORIZED_BEANS = {
    "honeybee": "beehive123",
    # "other_client": "other_key",
}
```

If `AUTHORIZED_BEANS` is empty or the identifier is not found, the server will reject the report.

### DETECTEDID

Dict mapping known path patterns to detection IDs. Used to classify the type of scanner.

```python
DETECTEDID = {
    "UNKNOWN_HTTP": 4294967294,
    "UNKNOWN_NON_HTTP": 4294967292,
    # Add your custom path-to-ID mappings
}
```

## Environment Variable Reference (Summary)

| Env Var | Maps to | Default | Required? |
|---------|---------|---------|-----------|
| `HONEY_HIVEPASS` | HIVEPASS | `beehive123` | Yes |
| `HONEY_HIVELOGIN` | HIVELOGIN | `honeybee` | No |
| `DB_BACKEND` | DB_BACKEND | `sqlite` | No |
| `DB_PATH` | DB_PATH | `bots/honeypot.db` | No (default) |
| `HONEY_PG_HOST` | DB_PG_HOST | `localhost` | If PostgreSQL |
| `HONEY_PG_PORT` | DB_PG_PORT | `5432` | If PostgreSQL |
| `HONEY_PG_DB` | DB_PG_DB | `honeypot` | If PostgreSQL |
| `HONEY_PG_USER` | DB_PG_USER | `postgres` | If PostgreSQL |
| `HONEY_PG_PASSWORD` | DB_PG_PASSWORD | `postgres` | If PostgreSQL |

## Production Checklist

- [ ] Set `HONEY_HIVEPASS` to a strong, random 32+ character string
- [ ] Set `HONEY_HIVELOGIN` to a unique identifier for your honeypot
- [ ] Configure `DB_BACKEND` and `DB_*` settings for your production database
- [ ] Install GeoLite2 database files in `mygeoip/GeoIP/` and `mygeoip/GeoIP2/`
- [ ] Set `AUTOFOLDER` for data storage (if applicable)
- [ ] Set `DB_PATH` to a secure, loggable location
- [ ] Set `DB_LOGGING` to control debug output verbosity
- [ ] Add `AUTHORIZED_BEANS` entries if deploying multiple clients
- [ ] Back up your `settings.py` file (contains secrets!)
- [ ] Verify the honeypot is on an isolated network

## GeoLite2 Setup

The honeypot uses `python-geoip-geolite2` for IP-to-location mapping. You need to obtain and install the databases:

```bash
# 1. Download from MaxMind
# Go to https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Register, then download:
#   - GeoLite2-Country.mmdb
#   - GeoLite2-City.mmdb (optional)

# 2. Extract to the correct directories
mkdir -p mygeoip/GeoIP
mkdir -p mygeoip/GeoIP2
cp GeoLite2-Country-*.dat mygeoip/GeoIP/
cp GeoLite2-Country-*.mmdb mygeoip/GeoIP2/
```

## Testing Without GeoIP

For local testing without GeoLite2, the honeypot will still work — country/continent will just be empty strings. Test the core flow:

```bash
python3 mfh.py -c 8888 -s 9999 -v
# Connect from another terminal: echo "test" | nc 127.0.0.1 8888
# Watch verbose output for the data flow
```
