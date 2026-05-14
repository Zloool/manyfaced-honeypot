# TODO — Many-faced Honeypot

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

## Medium Priority

### 4. No honeypot.log file persistence
Logging goes only to journalctl with no file backup. If the journal gets rotated/vacuumed, all historical logs are gone. Consider:
- Adding a file-based log handler alongside journalctl
- Or at least documenting that analysis must use `journalctl` queries
