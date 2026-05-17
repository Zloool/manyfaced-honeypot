"""Tests for the HTTP enrichment pipeline and hostname extraction."""

from pathlib import Path
from unittest.mock import MagicMock


class TestEnrichmentPipeline:
    """Tests for the HTTP enrichment pipeline (ua, dns_name, country, continent)."""

    def test_enrichment_fields_flow_through_save_data(self):
        """A payload with ua/dns_name/country/continent should reach storage.insert()."""
        from manyfaced.server.server import ServerHandler
        from manyfaced.db.storage import _resolve_db_path

        bear_data = {
            'ip': '203.0.113.42',
            'raw_request': 'GET /wp-login.php HTTP/1.1\r\nHost: honeypot\r\n\r\n',
            'timestamp': '2026-05-14 12:00:00.000000',
            'parsed_request': {
                'command': 'GET',
                'path': '/wp-login.php',
                'version': 'HTTP/1.1',
                'headers': {'Host': 'honeypot'},
            },
            'is_detected': 1,
            'HIVELOGIN': '',
            'ua': 'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
            'dns_name': 'scanner.example.net',
            'country': 'United States',
            'continent': 'North America',
        }

        args_obj = MagicMock(server=(0, 8090), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())
        handler.save_data(bear_data, args_obj)

        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_user_agent, bot_dns_name, bot_country, bot_continent '
            'FROM honeypot_bears WHERE bot_ip = ?',
            ('203.0.113.42',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 'Mozilla/5.0 (compatible; Nmap Scripting Engine)'
        assert row[1] == 'scanner.example.net'
        assert row[2] == 'United States'
        assert row[3] == 'North America'

    def test_enrichment_defaults_to_empty_when_missing(self):
        """Missing enrichment keys should result in empty strings in the DB."""
        from manyfaced.server.server import ServerHandler
        from manyfaced.db.storage import _resolve_db_path

        bear_data = {
            'ip': '198.51.100.7',
            'raw_request': 'GET / HTTP/1.1\r\n\r\n',
            'timestamp': '2026-05-14 13:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/'},
            'is_detected': 0,
            'HIVELOGIN': '',
        }

        args_obj = MagicMock(server=(0, 8091), verbose=False)
        handler = ServerHandler(args_obj, MagicMock())
        handler.save_data(bear_data, args_obj)

        import sqlite3

        conn = sqlite3.connect(_resolve_db_path())
        row = conn.execute(
            'SELECT bot_user_agent, bot_dns_name, bot_country, bot_continent '
            'FROM honeypot_bears WHERE bot_ip = ?',
            ('198.51.100.7',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == ''
        assert row[1] == ''
        assert row[2] == ''
        assert row[3] == ''


class TestHostnameFallback:
    """Tests for hostname extraction with HIVELOGIN fallback."""

    def test_hostname_fallback_to_hivelogin(self):
        """When record has no 'hostname' key, storage should fall back to HIVELOGIN."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_hostname_fallback.sqlite'
        with SQLiteStorage(db_path) as store:
            # No 'hostname' key — only HIVELOGIN is present
            store.insert(
                {
                    'ip': '10.99.99.99',
                    'timestamp': '2026-05-14 14:00:00',
                    'parsed_request': {'command': 'GET', 'path': '/'},
                    'is_detected': 1,
                    'raw_request': 'GET / HTTP/1.1\r\n\r\n',
                    'HIVELOGIN': 'admin_user',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            'SELECT hostname FROM honeypot_bears WHERE bot_ip = ?',
            ('10.99.99.99',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 'admin_user'

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_hostname_takes_precedence_over_hivelogin(self):
        """When both hostname and HIVELOGIN are present, hostname wins."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_hostname_precedence.sqlite'
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    'ip': '10.88.88.88',
                    'hostname': 'real-hostname.local',
                    'timestamp': '2026-05-14 15:00:00',
                    'parsed_request': {'command': 'GET', 'path': '/'},
                    'is_detected': 1,
                    'raw_request': 'GET / HTTP/1.1\r\n\r\n',
                    'HIVELOGIN': 'admin_user',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            'SELECT hostname FROM honeypot_bears WHERE bot_ip = ?',
            ('10.88.88.88',),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 'real-hostname.local'

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)
