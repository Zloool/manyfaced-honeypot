"""SQL schema and record-extraction helpers for storage backends.

Extracted from db/storage.py to reduce line count and eliminate duplication
between SQLiteStorage.insert() and PostgreSQLStorage.insert().
"""

# ---------------------------------------------------------------------------
# SQL schemas (shared between backends)
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS honeypot_bears (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_ip       TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    request_path TEXT,
    request_command TEXT,
    request_version TEXT,
    request_raw  TEXT,
    bot_user_agent TEXT,
    bot_country  TEXT,
    bot_continent TEXT,
    bot_tracert  TEXT,
    bot_dns_name TEXT,
    detected_id  INTEGER,
    hive_id      INTEGER,
    login        TEXT,
    UNIQUE(bot_ip, timestamp)
)
"""

INSERT_SQL = """\
INSERT OR IGNORE INTO honeypot_bears
    (bot_ip, hostname, timestamp, request_path, request_command,
     request_version, request_raw, bot_user_agent, bot_country,
     bot_continent, bot_tracert, bot_dns_name, detected_id, hive_id, login)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

CREATE_TABLE_PG_SQL = """\
CREATE TABLE IF NOT EXISTS honeypot_bears (
    id           SERIAL PRIMARY KEY,
    bot_ip       VARCHAR(45) NOT NULL,
    hostname     VARCHAR(255),
    timestamp    TEXT NOT NULL,
    request_path VARCHAR(4096),
    request_command VARCHAR(10),
    request_version TEXT,
    request_raw  TEXT,
    bot_user_agent TEXT,
    bot_country  VARCHAR(100),
    bot_continent VARCHAR(100),
    bot_tracert  TEXT,
    bot_dns_name VARCHAR(512),
    detected_id  INTEGER,
    hive_id      INTEGER,
    login        VARCHAR(255),
    UNIQUE(bot_ip, timestamp)
)
"""

INSERT_PG_SQL = """\
INSERT INTO honeypot_bears
    (bot_ip, hostname, timestamp, request_path, request_command,
     request_version, request_raw, bot_user_agent, bot_country,
     bot_continent, bot_tracert, bot_dns_name, detected_id, hive_id, login)
VALUES
    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT(bot_ip, timestamp) DO NOTHING
"""


def extract_record_fields(record: dict) -> tuple:
    """Extract and normalize fields from a bear record dict.

    Shared by both SQLiteStorage.insert() and PostgreSQLStorage.insert().

    Args:
        record: Dict with keys like 'ip', 'parsed_request', 'timestamp', etc.

    Returns:
        Tuple of 15 values matching the INSERT statement placeholders.
    """
    parsed = record.get('parsed_request') or {}

    bot_ip = record.get('ip') or ''
    hostname = record.get('hostname') or record.get('HIVELOGIN') or ''
    timestamp = record.get('timestamp') or ''
    request_path = parsed.get('path') or record.get('request_path') or ''
    request_command = parsed.get('command') or record.get('request_command') or ''
    request_version = (
        parsed.get('request_version')
        or parsed.get('version')
        or record.get('request_version')
        or ''
    )
    request_raw = record.get('raw_request') or ''
    bot_user_agent = parsed.get('user_agent') or record.get('ua') or ''
    bot_country = record.get('country') or ''
    bot_continent = record.get('continent') or ''
    bot_tracert = record.get('tracert') or ''
    bot_dns_name = record.get('dns_name') or ''
    detected_id = record.get('is_detected')
    if detected_id is None:
        detected_id = record.get('isDetected')
    hive_id = record.get('hive_id')
    login = record.get('login') or ''

    # Convert timestamps to text if needed
    from datetime import datetime  # noqa: PLC0415

    if isinstance(timestamp, datetime):
        timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
    timestamp = str(timestamp)

    return (
        bot_ip,
        hostname,
        timestamp,
        request_path,
        request_command,
        request_version,
        request_raw,
        bot_user_agent,
        bot_country,
        bot_continent,
        bot_tracert,
        bot_dns_name,
        int(detected_id) if detected_id is not None else None,
        int(hive_id) if hive_id is not None else None,
        login,
    )
