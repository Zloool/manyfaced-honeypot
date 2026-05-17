"""Test SQLite storage backend directly (no encryption)."""

from datetime import datetime
from pathlib import Path


class TestSQLiteStorageDirect:
    """Test SQLite storage backend directly (no encryption)."""

    def test_insert_and_query_record(self):
        """Verify SQLiteStorage insert works end-to-end."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_integration_store.sqlite'
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    'ip': '1.2.3.4',
                    'hostname': 'example.com',
                    'timestamp': '2026-04-19 03:00:00.000000',
                    'parsed_request': {
                        'command': 'GET',
                        'path': '/test',
                        'version': 'HTTP/1.1',
                        'headers': {'Host': 'x'},
                    },
                    'is_detected': 1,
                    'raw_request': 'GET /test\r\n\r\n',
                    'ua': 'TestAgent',
                    'country': 'US',
                    'continent': 'NA',
                    'tracert': '',
                    'dns_name': '',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            'SELECT bot_ip, request_path, request_command, request_version, '
            'detected_id, login FROM honeypot_bears'
        ).fetchone()
        conn.close()

        assert row[0] == '1.2.3.4'
        assert row[1] == '/test'
        assert row[2] == 'GET'
        assert row[3] == 'HTTP/1.1'
        assert row[4] == 1
        assert row[5] == ''

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_insert_handles_extra_fields(self):
        """SQLiteStorage should handle extra fields gracefully."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_extra.sqlite'
        with SQLiteStorage(db_path) as store:
            store.insert(
                {
                    'ip': '5.6.7.8',
                    'timestamp': '2026-04-19 04:00:00',
                    'extra_field': 'ignored',
                }
            )

        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute('SELECT bot_ip FROM honeypot_bears').fetchone()
        conn.close()
        assert row[0] == '5.6.7.8'

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)

    def test_insert_with_datetime_timestamp(self):
        """Datetime objects as timestamp should also work."""
        from manyfaced.db.storage import SQLiteStorage

        db_path = 'bots/test_dt.sqlite'

        with SQLiteStorage(db_path) as store:
            store.insert({'ip': '9.10.11.12', 'timestamp': '2026-04-19 05:00:00'})
        with SQLiteStorage(db_path) as store:
            store.insert({'ip': '13.14.15.16', 'timestamp': datetime(2026, 4, 19, 6, 0, 0)})

        import sqlite3

        conn = sqlite3.connect(db_path)
        count = conn.execute('SELECT COUNT(*) FROM honeypot_bears').fetchone()[0]
        conn.close()
        assert count == 2

        if Path(db_path).exists():
            Path(db_path).unlink(missing_ok=True)
