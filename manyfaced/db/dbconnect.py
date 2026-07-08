"""Database connector for honeypot bear records.

Replaces the ClickHouse ORM with the new storage backend (SQLite/PostgreSQL).
BearRequests is now a dataclass and Insert() delegates to the configured backend.
"""

from dataclasses import dataclass
from typing import Any

from .storage import get_storage


@dataclass
class BearRequests:
    """Data class for honeypot bear request data."""

    ip: str
    raw_request: str
    timestamp: str
    parsed_request: dict[str, Any]
    is_detected: int
    HIVELOGIN: str
    ua: str = ''
    dns_name: str = ''
    country: str = ''
    continent: str = ''
    login: str = ''
    bot_profile_data: dict[str, Any] | None = None
    listen_port: int = 0


def Insert(bear: BearRequests) -> None:
    """Insert bear data into the configured storage backend."""
    record: dict[str, Any] = {
        'ip': bear.ip,
        'raw_request': bear.raw_request,
        'timestamp': bear.timestamp,
        'parsed_request': bear.parsed_request,
        'is_detected': bear.is_detected,
        'HIVELOGIN': bear.HIVELOGIN,
        'ua': bear.ua,
        'dns_name': bear.dns_name,
        'country': bear.country,
        'continent': bear.continent,
        'login': bear.login,
        'listen_port': bear.listen_port,
    }

    # Bot profile data — accumulated state (escalation, dialogue, history) for this IP
    if bear.bot_profile_data:
        record['bot_profile_data'] = bear.bot_profile_data

    storage = get_storage()
    storage.insert(record)
