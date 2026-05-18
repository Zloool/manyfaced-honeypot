"""Tests for manyfaced.db.dbconnect (BearRequests dataclass and Insert function)."""

import sys
from dataclasses import fields
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path (conftest handles this, but be safe)
# ---------------------------------------------------------------------------
_project_root = __import__('os').path.abspath(
    __import__('os').path.join(__import__('os').path.dirname(__file__), '..')
)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from manyfaced.db.dbconnect import BearRequests, Insert  # noqa: E402


# ---------------------------------------------------------------------------
# BearRequests dataclass tests
# ---------------------------------------------------------------------------


class TestBearRequestsCreation:
    """Tests for BearRequests dataclass instantiation."""

    def test_create_with_all_fields(self):
        bear = BearRequests(
            ip='1.2.3.4',
            raw_request='GET /admin HTTP/1.1',
            timestamp='2024-01-15 10:30:00',
            parsed_request={'path': '/admin', 'command': 'GET'},
            is_detected=1,
            HIVELOGIN='admin',
        )
        assert bear.ip == '1.2.3.4'
        assert bear.raw_request == 'GET /admin HTTP/1.1'
        assert bear.timestamp == '2024-01-15 10:30:00'
        assert bear.parsed_request == {'path': '/admin', 'command': 'GET'}
        assert bear.is_detected == 1
        assert bear.HIVELOGIN == 'admin'
        # Enrichment fields default to ''
        assert bear.ua == ''
        assert bear.dns_name == ''
        assert bear.country == ''
        assert bear.continent == ''

    def test_create_with_enrichment_fields(self):
        """BearRequests should carry enrichment data from the client payload."""
        bear = BearRequests(
            ip='1.2.3.4',
            raw_request='GET /admin HTTP/1.1',
            timestamp='2024-01-15 10:30:00',
            parsed_request={'path': '/admin', 'command': 'GET'},
            is_detected=1,
            HIVELOGIN='admin',
            ua='Mozilla/5.0 (compatible; bot)',
            dns_name='scan.example.com',
            country='Russia',
            continent='Europe',
        )
        assert bear.ua == 'Mozilla/5.0 (compatible; bot)'
        assert bear.dns_name == 'scan.example.com'
        assert bear.country == 'Russia'
        assert bear.continent == 'Europe'

    def test_create_with_empty_fields(self):
        bear = BearRequests(
            ip='',
            raw_request='',
            timestamp='',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )
        assert bear.ip == ''
        assert bear.raw_request == ''
        assert bear.timestamp == ''
        assert bear.parsed_request == {}
        assert bear.is_detected == 0
        assert bear.HIVELOGIN == ''

    def test_create_with_none_values(self):
        """BearRequests has no defaults, so passing None should work."""
        bear = BearRequests(
            ip=None,  # type: ignore
            raw_request=None,  # type: ignore
            timestamp=None,  # type: ignore
            parsed_request=None,  # type: ignore
            is_detected=None,  # type: ignore
            HIVELOGIN=None,  # type: ignore
        )
        assert bear.ip is None
        assert bear.raw_request is None
        assert bear.timestamp is None
        assert bear.parsed_request is None
        assert bear.is_detected is None
        assert bear.HIVELOGIN is None

    def test_create_with_int_is_detected(self):
        bear = BearRequests(
            ip='10.0.0.1',
            raw_request='test',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )
        assert isinstance(bear.is_detected, int)
        assert bear.is_detected == 0

    def test_create_with_nonzero_is_detected(self):
        bear = BearRequests(
            ip='10.0.0.1',
            raw_request='test',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=42,
            HIVELOGIN='',
        )
        assert bear.is_detected == 42


class TestBearRequestsDataclassRepr:
    """Tests for dataclass behaviour (fields, repr, eq)."""

    def test_dataclass_fields(self):
        field_names = [f.name for f in fields(BearRequests)]
        assert field_names == [
            'ip',
            'raw_request',
            'timestamp',
            'parsed_request',
            'is_detected',
            'HIVELOGIN',
            'ua',
            'dns_name',
            'country',
            'continent',
            'login',
        ]

    def test_dataclass_repr(self):
        bear = BearRequests(
            ip='1.2.3.4',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )
        repr_str = repr(bear)
        assert 'BearRequests' in repr_str
        assert '1.2.3.4' in repr_str
        assert 'GET / HTTP/1.1' in repr_str

    def test_dataclass_equality(self):
        bear1 = BearRequests(
            ip='1.2.3.4',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )
        bear2 = BearRequests(
            ip='1.2.3.4',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )
        bear3 = BearRequests(
            ip='5.6.7.8',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )
        assert bear1 == bear2
        assert bear1 != bear3


class TestInsertFunction:
    """Tests for the Insert() function."""

    def test_insert_calls_storage_insert(self, tmp_path):
        """Insert() should call storage.insert() with the correct record dict."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='1.2.3.4',
            raw_request='POST /login HTTP/1.1',
            timestamp='2024-06-01 12:00:00',
            parsed_request={'path': '/login', 'command': 'POST'},
            is_detected=1,
            HIVELOGIN='testuser',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        mock_storage.insert.assert_called_once()
        record = mock_storage.insert.call_args[0][0]
        assert record['ip'] == '1.2.3.4'
        assert record['raw_request'] == 'POST /login HTTP/1.1'
        assert record['timestamp'] == '2024-06-01 12:00:00'
        assert record['parsed_request'] == {'path': '/login', 'command': 'POST'}
        assert record['is_detected'] == 1
        assert record['HIVELOGIN'] == 'testuser'

    def test_insert_with_empty_parsed_request(self):
        """Insert handles BearRequests with empty parsed_request dict."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='10.0.0.1',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['parsed_request'] == {}

    def test_insert_with_complex_parsed_request(self):
        """Insert passes through complex parsed_request dicts."""
        mock_storage = MagicMock()

        parsed = {
            'path': '/admin/config',
            'command': 'PUT',
            'request_version': 'HTTP/2.0',
            'user_agent': 'Mozilla/5.0',
        }
        bear = BearRequests(
            ip='192.168.1.1',
            raw_request='PUT /admin/config HTTP/2.0',
            timestamp='2024-03-15 08:30:00',
            parsed_request=parsed,
            is_detected=1,
            HIVELOGIN='root',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['parsed_request'] == parsed

    def test_insert_with_none_bear_values(self):
        """Insert passes through None values as-is in the record dict."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip=None,  # type: ignore
            raw_request=None,  # type: ignore
            timestamp=None,  # type: ignore
            parsed_request=None,  # type: ignore
            is_detected=None,  # type: ignore
            HIVELOGIN=None,  # type: ignore
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['ip'] is None
        assert record['raw_request'] is None
        assert record['timestamp'] is None
        assert record['parsed_request'] is None
        assert record['is_detected'] is None
        assert record['HIVELOGIN'] is None

    def test_insert_with_is_detected_zero(self):
        """Insert correctly passes is_detected=0."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='10.0.0.1',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['is_detected'] == 0

    def test_insert_with_is_detected_one(self):
        """Insert correctly passes is_detected=1."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='10.0.0.1',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=1,
            HIVELOGIN='',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['is_detected'] == 1

    def test_insert_calls_get_storage_once(self):
        """Insert should call get_storage exactly once."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='1.1.1.1',
            raw_request='test',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage) as mock_get:
            Insert(bear)
            mock_get.assert_called_once()

    def test_insert_record_has_all_keys(self):
        """The record dict passed to storage.insert() must contain all 10 keys."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='1.1.1.1',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-01-01 00:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        expected_keys = {
            'ip',
            'raw_request',
            'timestamp',
            'parsed_request',
            'is_detected',
            'HIVELOGIN',
            'ua',
            'dns_name',
            'country',
            'continent',
            'login',
        }
        assert set(record.keys()) == expected_keys

    def test_insert_passes_enrichment_fields_through(self):
        """Insert should carry ua/dns_name/country/continent into the record dict."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='1.2.3.4',
            raw_request='GET /admin HTTP/1.1',
            timestamp='2024-06-01 12:00:00',
            parsed_request={'path': '/admin'},
            is_detected=1,
            HIVELOGIN='root',
            ua='Mozilla/5.0 (compatible; bot)',
            dns_name='scan.example.com',
            country='Russia',
            continent='Europe',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['ua'] == 'Mozilla/5.0 (compatible; bot)'
        assert record['dns_name'] == 'scan.example.com'
        assert record['country'] == 'Russia'
        assert record['continent'] == 'Europe'

    def test_insert_enrichment_defaults_to_empty(self):
        """Enrichment fields should default to '' when not provided."""
        mock_storage = MagicMock()

        bear = BearRequests(
            ip='1.2.3.4',
            raw_request='GET / HTTP/1.1',
            timestamp='2024-06-01 12:00:00',
            parsed_request={},
            is_detected=0,
            HIVELOGIN='',
        )

        with patch('manyfaced.db.dbconnect.get_storage', return_value=mock_storage):
            Insert(bear)

        record = mock_storage.insert.call_args[0][0]
        assert record['ua'] == ''
        assert record['dns_name'] == ''
        assert record['country'] == ''
        assert record['continent'] == ''
