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


def Insert(bear: BearRequests) -> None:
    """Insert bear data into the configured storage backend."""
    storage = get_storage()
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
    }
    storage.insert(record)
