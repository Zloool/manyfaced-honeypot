"""
Tests for manyfaced.common.utils, manyfaced.common.config, and manyfaced.common.arguments.

Usage:
    /usr/bin/python3 -m pytest test/test_utils_config_args.py -v -c /home/zlol/manyfaced-honeypot/pytest.ini
"""

import os
import pickle
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ---------------------------------------------------------------------------
# Mock geoip modules before any module that uses it is imported
# ---------------------------------------------------------------------------
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules["geoip"] = geoip_mock
sys.modules["geoip.geolite2"] = geoip_mock.geolite2
sys.modules["GeoIP"] = MagicMock()

# ---------------------------------------------------------------------------
# Import units under test
# ---------------------------------------------------------------------------
from manyfaced.common.utils import dump_file, receive_timeout
from manyfaced.common.config import Config, _find_config_file, _load_toml, _resolve, _env_prefix
from manyfaced.common.arguments import parse


# ===================================================================
# Helper utilities
# ===================================================================

class _TempDB:
    """Context manager that patches dump_file to use a temp file."""

    def __init__(self, path):
        self.path = path
        self._mock = None

    def __enter__(self):
        self._real_open = open
        self._mock = patch("manyfaced.common.utils.open", self._patched_open)
        self._mock.start()
        return self.path

    def __exit__(self, *exc):
        if self._mock:
            self._mock.stop()

    def _patched_open(self, path, mode, *args, **kwargs):
        return self._real_open(self.path, mode, *args, **kwargs)


def _write_toml(tmp_path, content):
    """Write a TOML file and return its Path."""
    toml_path = tmp_path / "config.toml"
    toml_path.write_text(content)
    return toml_path


def _make_time_counter(start=1000.0, increment=0.1):
    """Create a time.time() side_effect that increments by `increment` each call."""
    counter = [0]

    def side_effect():
        counter[0] += 1
        return start + counter[0] * increment

    return side_effect


# ===================================================================
# utils.py  –  dump_file / receive_timeout
# ===================================================================

class TestDumpFile:
    """Tests for dump_file(data): reads/writes pickle to temp.db, appends data to list."""

    def test_creates_file_and_writes_data(self, tmp_path):
        """dump_file creates temp.db, writes pickled list with data."""
        db_path = tmp_path / "temp.db"
        with _TempDB(db_path):
            dump_file({"key": "value"})
        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == [{"key": "value"}]

    def test_appends_to_existing_list(self, tmp_path):
        """dump_file appends data to existing list in temp.db."""
        db_path = tmp_path / "temp.db"
        db_path.write_bytes(pickle.dumps([{"first": 1}]))

        with _TempDB(db_path):
            dump_file({"second": 2})

        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == [{"first": 1}, {"second": 2}]

    def test_handles_missing_file(self, tmp_path):
        """dump_file handles missing temp.db gracefully (creates new list)."""
        db_path = tmp_path / "temp.db"
        assert not db_path.exists()

        with _TempDB(db_path):
            dump_file("new_data")

        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == ["new_data"]

    def test_multiple_appends(self, tmp_path):
        """Multiple dump_file calls accumulate data."""
        db_path = tmp_path / "temp.db"

        with _TempDB(db_path):
            dump_file("item1")
            dump_file("item2")
            dump_file("item3")

        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == ["item1", "item2", "item3"]

    def test_dump_file_with_dict_data(self, tmp_path):
        """dump_file handles dict data correctly."""
        db_path = tmp_path / "temp.db"
        with _TempDB(db_path):
            dump_file({"url": "http://example.com", "method": "GET"})
        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == [{"url": "http://example.com", "method": "GET"}]

    def test_dump_file_with_bytes_data(self, tmp_path):
        """dump_file handles bytes data correctly."""
        db_path = tmp_path / "temp.db"
        with _TempDB(db_path):
            dump_file(b"raw bytes data")
        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == [b"raw bytes data"]


class TestReceiveTimeout:
    """Tests for receive_timeout(the_socket, timeout): non-blocking socket recv with timeout logic.

    The function works as follows:
    - Sets socket to non-blocking
    - Loops: tries to recv data; if data received, resets begin time
    - Breaks when: (total_data AND elapsed > timeout) OR (elapsed > timeout*2)
    - time.sleep(0.1) is called between recv attempts when no data
    - Returns "".join(total_data)
    """

    @pytest.fixture
    def _mock_sleep(self, monkeypatch):
        """Monkey-patch time.sleep to be a no-op."""
        monkeypatch.setattr("time.sleep", lambda *a: None)

    def test_assembles_multiple_receives(self, monkeypatch, _mock_sleep):
        """receive_timeout assembles data from multiple recv calls until timeout."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=1.0:
        # Calls 1-4: recv data (begin resets each time)
        # Calls 5-14: recv empty (total_data non-empty, elapsed < timeout)
        # Call 15: recv empty, elapsed=1.1 > 1.0 → break
        data_chunks = [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: text/html\r\n",
            b"\r\n",
            b"<!DOCTYPE html>",
        ] + [b""] * 11  # 11 empty responses to trigger timeout

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>"
        assert mock_socket.setblocking.called
        assert mock_socket.recv.call_count == 15  # 4 data + 11 empty = break at 15

    def test_returns_empty_on_immediate_empty(self, monkeypatch, _mock_sleep):
        """receive_timeout returns empty string after timeout*2 when no data."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=1.0:
        # timeout*2 = 2.0, so after 20 calls elapsed=2.1 > 2.0 → break
        mock_socket.recv = MagicMock(return_value=b"")

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == ""

    def test_timeout_breaks_after_data_received(self, monkeypatch, _mock_sleep):
        """receive_timeout breaks out of loop after timeout once data has been received."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=0.5:
        # Call 1: recv data, begin=1000.1
        # Calls 2-6: recv empty (elapsed < 0.5)
        # Call 7: recv empty, elapsed=0.6 > 0.5 → break
        data_chunks = [b"data1", b"data2", b"data3", b"data4", b"data5"] + [b""] * 3

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == b"data1data2data3data4data5"

    def test_timeout_without_data(self, monkeypatch, _mock_sleep):
        """receive_timeout returns empty after timeout*2 even with no data."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=0.5:
        # timeout*2 = 1.0, so after 10 calls elapsed=1.1 > 1.0 → break
        mock_socket.recv = MagicMock(return_value=b"")

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == ""

    def test_refreshes_begin_on_data(self, monkeypatch, _mock_sleep):
        """receive_timeout resets begin time when new data arrives, extending the window."""
        mock_socket = MagicMock()
        # With 0.5s increments and timeout=1.0:
        # Call 1: t=1000.5, recv=b"a", begin=1000.5
        # Call 2: t=1001.0, elapsed=0.5, recv=b"b", begin=1001.0
        # Call 3: t=1001.5, elapsed=0.5, recv=b"c", begin=1001.5
        # Call 4: t=1002.0, elapsed=0.5, recv=b"", total_data non-empty, 0.5 NOT > 1.0
        # Call 5: t=1002.5, elapsed=1.0, 1.0 NOT > 1.0
        # Call 6: t=1003.0, elapsed=1.5, 1.5 > 1.0 → break
        data_chunks = [b"a", b"b", b"c", b"", b"", b""]

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)

        # time advances by 0.5 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.5))

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == b"abc"

    def test_socket_error_handled(self, monkeypatch, _mock_sleep):
        """receive_timeout handles socket.error (would block) gracefully."""
        from socket import error as socket_error
        mock_socket = MagicMock()

        # With 0.1s increments and timeout=0.5:
        # Calls 1-3: raise socket_error
        # Call 4: recv=b"got data", begin reset
        # Calls 5-9: recv empty (elapsed < 0.5)
        # Call 10: recv empty, elapsed=0.6 > 0.5 → break
        recv_count = [0]

        def side_effect(*args):
            recv_count[0] += 1
            if recv_count[0] <= 3:
                raise socket_error("would block")
            return b"got data"

        mock_socket.recv = MagicMock(side_effect=side_effect)
        mock_socket.setblocking = MagicMock()

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == b"got data"

    def test_single_chunk(self, monkeypatch, _mock_sleep):
        """receive_timeout handles a single recv call with data then empty."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=1.0:
        # Call 1: recv=b"hello", begin=1000.1
        # Calls 2-11: recv empty (elapsed < 1.0)
        # Call 12: recv empty, elapsed=1.1 > 1.0 → break
        data_chunks = [b"hello"] + [b""] * 11

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == b"hello"

    def test_timeout_exactly_at_timeout2(self, monkeypatch, _mock_sleep):
        """receive_timeout breaks when elapsed time reaches timeout*2 with no data."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=1.0:
        # timeout*2 = 2.0, so after 20 calls elapsed=2.1 > 2.0 → break
        mock_socket.recv = MagicMock(return_value=b"")

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == ""

    def test_data_then_timeout(self, monkeypatch, _mock_sleep):
        """receive_timeout collects data, then times out after receiving data."""
        mock_socket = MagicMock()
        # With 0.1s increments and timeout=0.5:
        # Call 1: recv=b"hello", begin=1000.1
        # Call 2: recv=b" world", begin=1000.2
        # Calls 3-7: recv empty (elapsed < 0.5 from begin=1000.2)
        # Call 8: recv empty, elapsed=0.6 > 0.5 → break
        data_chunks = [b"hello", b" world"] + [b""] * 6

        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)

        # time advances by 0.1 each call
        monkeypatch.setattr("time.time", _make_time_counter(increment=0.1))

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == b"hello world"


# ===================================================================
# config.py  –  Config.load / generate_config_file / _find_config_file / _load_toml / _resolve
# ===================================================================

class TestConfigDefaults:
    """Config with no TOML file, no env vars → returns defaults."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        """Remove all HONEY_ env vars."""
        for key in list(os.environ.keys()):
            if key.startswith("HONEY_"):
                monkeypatch.delenv(key, raising=False)

    def test_defaults_no_toml_no_env(self, tmp_path, monkeypatch):
        """All values should be defaults when no TOML and no env vars."""
        config_path = _write_toml(tmp_path, "")  # empty TOML = no overrides

        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: config_path)

            cfg = Config.load()

        assert cfg.HONEYPORT == 80
        assert cfg.HONEYFOLDER == "bots"
        assert cfg.HIVEHOST == "127.0.0.1"
        assert cfg.HIVEPORT == 8080
        assert cfg.HIVELOGIN == "honeybee"
        assert cfg.HIVEPASS == "beehive123"
        assert cfg.DB_BACKEND == "sqlite"
        assert cfg.DB_PATH == "bots/honeypot.db"
        assert cfg.DB_PG_HOST == "localhost"
        assert cfg.DB_PG_PORT == 5432
        assert cfg.DB_PG_DB == "honeypot"
        assert cfg.DB_PG_USER == "postgres"
        assert cfg.DB_PG_PASSWORD == "***"
        assert cfg.AUTHORISEDBEARS == {}


class TestConfigToml:
    """Config with TOML file overrides, verify TOML values take precedence over defaults."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        for key in list(os.environ.keys()):
            if key.startswith("HONEY_"):
                monkeypatch.delenv(key, raising=False)

    def test_toml_overrides_defaults(self, tmp_path, monkeypatch):
        """TOML values override code defaults."""
        toml_content = """
[honeypot]
honeyport = 443
honeyfolder = "malware"

[hive]
hivehost = "10.0.0.1"
hiveport = 9999
hivelogin = "admin"
hivepass = "secret123"

[database]
backend = "sqlite"
path = "data/honeypot.db"
pg_host = "db.example.com"
pg_port = 5433
pg_db = "myhoneypot"
pg_user = "admin"
pg_password = "dbpass"

[security]
authorised_bears = ""
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: config_path)

            cfg = Config.load()

        assert cfg.HONEYPORT == 443
        assert cfg.HONEYFOLDER == "malware"
        assert cfg.HIVEHOST == "10.0.0.1"
        assert cfg.HIVEPORT == 9999
        assert cfg.HIVELOGIN == "admin"
        assert cfg.HIVEPASS == "secret123"
        assert cfg.DB_PATH == "data/honeypot.db"
        assert cfg.DB_PG_HOST == "db.example.com"
        assert cfg.DB_PG_PORT == 5433
        assert cfg.DB_PG_DB == "myhoneypot"
        assert cfg.DB_PG_USER == "admin"
        assert cfg.DB_PG_PASSWORD == "dbpass"


class TestConfigEnvVars:
    """Config with env vars override TOML and defaults."""

    def test_env_vars_override_toml(self, tmp_path, monkeypatch):
        """Environment variables override TOML values."""
        toml_content = """
[honeypot]
honeyport = 443
honeyfolder = "toml_folder"

[hive]
hivehost = "10.0.0.1"
hiveport = 9999
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: config_path)
            m.setenv("HONEY_HONEYPORT", "8080")
            m.setenv("HONEY_HONEYFOLDER", "env_folder")
            m.setenv("HONEY_HIVEPORT", "3000")

            cfg = Config.load()

        assert cfg.HONEYPORT == 8080
        assert cfg.HONEYFOLDER == "env_folder"
        assert cfg.HIVEPORT == 3000
        assert cfg.HIVEHOST == "10.0.0.1"


class TestConfigEnvVarPrecedence:
    """Env vars win over TOML which wins over defaults."""

    def test_three_layer_precedence(self, tmp_path, monkeypatch):
        """Verify: env > TOML > defaults for each field."""
        toml_content = """
[honeypot]
honeyport = 443
honeyfolder = "toml_folder"

[hive]
hivehost = "10.0.0.1"
hiveport = 9999
hivelogin = "toml_login"
hivepass = "toml_pass"

[database]
backend = "postgresql"
path = "toml_path.db"
pg_host = "toml_host"
pg_port = 5433
pg_db = "toml_db"
pg_user = "toml_user"
pg_password = "toml_pass"

[security]
authorised_bears = ""
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: config_path)
            m.setenv("HONEY_HONEYPORT", "9090")
            m.setenv("HONEY_HIVEPORT", "7070")

            cfg = Config.load()

        assert cfg.HONEYPORT == 9090
        assert cfg.HIVEPORT == 7070
        assert cfg.HONEYFOLDER == "toml_folder"
        assert cfg.HIVEHOST == "10.0.0.1"
        assert cfg.HIVELOGIN == "toml_login"
        assert cfg.HIVEPASS == "toml_pass"
        assert cfg.DB_BACKEND == "postgresql"
        assert cfg.DB_PATH == "toml_path.db"
        assert cfg.DB_PG_HOST == "toml_host"
        assert cfg.DB_PG_PORT == 5433
        assert cfg.DB_PG_DB == "toml_db"
        assert cfg.DB_PG_USER == "toml_user"
        assert cfg.DB_PG_PASSWORD == "toml_pass"

    def test_defaults_when_no_toml_no_env(self, tmp_path, monkeypatch):
        """When no TOML and no env, all defaults apply."""
        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: None)
            for key in list(os.environ.keys()):
                if key.startswith("HONEY_"):
                    m.delenv(key, raising=False)

            cfg = Config.load()

        assert cfg.HONEYPORT == 80
        assert cfg.HONEYFOLDER == "bots"
        assert cfg.HIVEHOST == "127.0.0.1"
        assert cfg.HIVEPORT == 8080
        assert cfg.HIVELOGIN == "honeybee"
        assert cfg.HIVEPASS == "beehive123"
        assert cfg.DB_BACKEND == "sqlite"
        assert cfg.DB_PATH == "bots/honeypot.db"
        assert cfg.DB_PG_HOST == "localhost"
        assert cfg.DB_PG_PORT == 5432
        assert cfg.DB_PG_DB == "honeypot"
        assert cfg.DB_PG_USER == "postgres"
        assert cfg.DB_PG_PASSWORD == "***"


class TestConfigGenerateConfigFile:
    """generate_config_file creates file at expected path with correct TOML content."""

    def test_creates_file_at_default_path(self, tmp_path, monkeypatch):
        """generate_config_file writes to ~/.config/manyfaced/config.toml by default."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))

        cfg = Config(
            HONEYPORT=443,
            HONEYFOLDER="bots",
            HIVEHOST="127.0.0.1",
            HIVEPORT=8080,
            HIVELOGIN="honeybee",
            HIVEPASS="beehive123",
            DB_BACKEND="sqlite",
            DB_BACKENDS=("sqlite", "postgresql"),
            DB_PATH="bots/honeypot.db",
            DB_PG_HOST="localhost",
            DB_PG_PORT=5432,
            DB_PG_DB="honeypot",
            DB_PG_USER="postgres",
            DB_PG_PASSWORD="***",
            AUTHORISEDBEARS={},
        )

        path = cfg.generate_config_file()

        assert path == fake_home / ".config" / "manyfaced" / "config.toml"
        assert path.exists()
        content = path.read_text()
        assert "[honeypot]" in content
        assert "honeyport = 443" in content
        assert 'honeyfolder = "bots"' in content
        assert "[hive]" in content
        assert 'hivehost = "127.0.0.1"' in content
        assert "hiveport = 8080" in content
        assert 'hivelogin = "honeybee"' in content
        assert 'hivepass = "beehive123"' in content
        assert "[database]" in content
        assert 'backend = "sqlite"' in content
        assert 'path = "bots/honeypot.db"' in content
        assert 'pg_host = "localhost"' in content
        assert "pg_port = 5432" in content
        assert 'pg_db = "honeypot"' in content
        assert 'pg_user = "postgres"' in content
        assert 'pg_password = "***"' in content
        assert "[security]" in content

    def test_creates_file_at_custom_path(self, tmp_path, monkeypatch):
        """generate_config_file writes to a custom path when specified."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER="bots",
            HIVEHOST="127.0.0.1",
            HIVEPORT=8080,
            HIVELOGIN="honeybee",
            HIVEPASS="beehive123",
            DB_BACKEND="sqlite",
            DB_BACKENDS=("sqlite", "postgresql"),
            DB_PATH="bots/honeypot.db",
            DB_PG_HOST="localhost",
            DB_PG_PORT=5432,
            DB_PG_DB="honeypot",
            DB_PG_USER="postgres",
            DB_PG_PASSWORD="***",
            AUTHORISEDBEARS={},
        )

        custom_path = tmp_path / "custom" / "config.toml"
        path = cfg.generate_config_file(path=custom_path)

        assert path == custom_path
        assert path.exists()
        assert "honeyport = 80" in path.read_text()


class TestConfigLoadCustomPath:
    """load with explicit config_path."""

    def test_load_with_explicit_config_path(self, tmp_path, monkeypatch):
        """Config.load accepts an explicit config_path argument."""
        toml_content = """
[honeypot]
honeyport = 8888
"""
        config_path = _write_toml(tmp_path, toml_content)

        cfg = Config.load(config_path=config_path)

        assert cfg.HONEYPORT == 8888
        assert cfg.HONEYFOLDER == "bots"

    def test_load_with_string_path(self, tmp_path, monkeypatch):
        """Config.load accepts a string config_path."""
        toml_content = """
[honeypot]
honeyport = 7777
"""
        config_path = str(_write_toml(tmp_path, toml_content))

        cfg = Config.load(config_path=config_path)

        assert cfg.HONEYPORT == 7777


class TestConfigAuthorisedBears:
    """Parse semicolon-separated authorised_bears from env var."""

    def test_env_var_authorised_bears(self, monkeypatch):
        """AUTHORISEDBEARS parsed from HONEY_AUTHORISEDBEARS env var."""
        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: None)
            m.setenv("HONEY_AUTHORISEDBEARS", "bear1:key1;bear2:key2;bear3:key3")

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {"bear1": "key1", "bear2": "key2", "bear3": "key3"}

    def test_authorised_bears_empty_env(self, monkeypatch):
        """Empty HONEY_AUTHORISEDBEARS env var returns default empty dict."""
        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: None)
            m.setenv("HONEY_AUTHORISEDBEARS", "")

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {}

    def test_authorised_bears_without_colon_ignored(self, monkeypatch):
        """Pairs without colon are ignored in authorised_bears parsing."""
        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: None)
            m.setenv("HONEY_AUTHORISEDBEARS", "bear1:key1;invalid_no_colon;bear2:key2")

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {"bear1": "key1", "bear2": "key2"}

    def test_authorised_bears_from_toml(self, tmp_path, monkeypatch):
        """AUTHORISEDBEARS can be set via TOML file."""
        toml_content = """
[security]
authorised_bears = "toml_bear:toml_key"
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: config_path)
            m.delenv("HONEY_AUTHORISEDBEARS", raising=False)

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {"toml_bear": "toml_key"}

    def test_authorised_bears_env_overrides_toml(self, tmp_path, monkeypatch):
        """AUTHORISEDBEARS env var overrides TOML."""
        toml_content = """
[security]
authorised_bears = "toml_bear:toml_key"
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr("manyfaced.common.config._find_config_file", lambda: config_path)
            m.setenv("HONEY_AUTHORISEDBEARS", "env_bear:env_key")

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {"env_bear": "env_key"}


# ===================================================================
# arguments.py  –  parse()
# ===================================================================

class TestParseDefaults:
    """No args → client=None, server=None, updater=False, verbose=False."""

    def test_no_args_defaults(self):
        """When no arguments are given, all optional flags should be None/False."""
        args = parse(args=[])

        assert args.client is None
        assert args.server is None
        assert args.updater is False
        assert args.verbose is False
        assert args.proxy is False
        assert args.generate_config is False


class TestParseClient:
    """-c 80 → client=80."""

    def test_client_port(self):
        args = parse(args=["-c", "80"])
        assert args.client == 80


class TestParseServer:
    """-s 666 → server=666."""

    def test_server_port(self):
        args = parse(args=["-s", "666"])
        assert args.server == 666


class TestParseClientServer:
    """-c 80 -s 666 → both set."""

    def test_client_and_server(self):
        args = parse(args=["-c", "80", "-s", "666"])
        assert args.client == 80
        assert args.server == 666


class TestParseVerbose:
    """-v → verbose=True."""

    def test_verbose_short(self):
        args = parse(args=["-v"])
        assert args.verbose is True

    def test_verbose_long(self):
        args = parse(args=["--verbose"])
        assert args.verbose is True


class TestParseUpdater:
    """-u → updater=True."""

    def test_updater(self):
        args = parse(args=["-u"])
        assert args.updater is True


class TestParseProxy:
    """-p → proxy=True."""

    def test_proxy_short(self):
        args = parse(args=["-p"])
        assert args.proxy is True

    def test_proxy_long(self):
        args = parse(args=["--proxy"])
        assert args.proxy is True


class TestParseGenerateConfig:
    """--generate-config → generate_config=True."""

    def test_generate_config(self):
        args = parse(args=["--generate-config"])
        assert args.generate_config is True


class TestParseAllFlags:
    """Combine all flags."""

    def test_all_flags(self):
        args = parse(args=["-c", "80", "-s", "666", "-u", "-v", "-p", "--generate-config"])
        assert args.client == 80
        assert args.server == 666
        assert args.updater is True
        assert args.verbose is True
        assert args.proxy is True
        assert args.generate_config is True


class TestParseClientNoPort:
    """-c without port → client=HONEYPORT default."""

    def test_client_no_port_uses_default(self):
        from manyfaced.common.settings import HONEYPORT
        args = parse(args=["-c"])
        assert args.client == HONEYPORT

    def test_server_no_port_uses_default(self):
        from manyfaced.common.settings import HIVEPORT
        args = parse(args=["-s"])
        assert args.server == HIVEPORT


# ===================================================================
# Additional edge-case tests
# ===================================================================

class TestResolve:
    """Tests for the _resolve helper function."""

    def test_resolve_int_default(self):
        result = _resolve("honeyport", 80, "honeypot", None, "HONEY_")
        assert result == 80

    def test_resolve_int_from_toml(self):
        toml = {"honeypot.honeyport": 443}
        result = _resolve("honeyport", 80, "honeypot", toml, "HONEY_")
        assert result == 443

    def test_resolve_int_from_env(self, monkeypatch):
        monkeypatch.setenv("HONEY_HONEYPORT", "9090")
        result = _resolve("honeyport", 80, "honeypot", None, "HONEY_")
        assert result == 9090

    def test_resolve_str_default(self):
        result = _resolve("honeyfolder", "bots", "honeypot", None, "HONEY_")
        assert result == "bots"

    def test_resolve_str_from_toml(self):
        toml = {"honeypot.honeyfolder": "malware"}
        result = _resolve("honeyfolder", "bots", "honeypot", toml, "HONEY_")
        assert result == "malware"

    def test_resolve_str_from_env(self, monkeypatch):
        monkeypatch.setenv("HONEY_HONEYFOLDER", "env_folder")
        result = _resolve("honeyfolder", "bots", "honeypot", None, "HONEY_")
        assert result == "env_folder"

    def test_resolve_dict_default(self):
        result = _resolve("authorised_bears", {}, "security", None, "HONEY_")
        assert result == {}

    def test_resolve_dict_from_toml(self):
        toml = {"security.authorised_bears": "bear1:key1"}
        result = _resolve("authorised_bears", {}, "security", toml, "HONEY_")
        assert result == "bear1:key1"

    def test_resolve_tuple_from_env(self, monkeypatch):
        monkeypatch.setenv("HONEY_BACKENDS", "sqlite;postgresql")
        result = _resolve("backends", ("sqlite", "postgresql"), "database", None, "HONEY_")
        assert result == ["sqlite", "postgresql"]

    def test_env_overrides_toml(self, monkeypatch):
        toml = {"honeypot.honeyport": 443}
        monkeypatch.setenv("HONEY_HONEYPORT", "9090")
        result = _resolve("honeyport", 80, "honeypot", toml, "HONEY_")
        assert result == 9090

    def test_toml_overrides_default(self):
        toml = {"honeypot.honeyport": 443}
        result = _resolve("honeyport", 80, "honeypot", toml, "HONEY_")
        assert result == 443


class TestEnvPrefix:
    """Tests for _env_prefix."""

    def test_default_prefix(self):
        assert _env_prefix() == "HONEY_"


class TestLoadToml:
    """Tests for _load_toml."""

    def test_load_toml_flat_dict(self, tmp_path):
        toml_content = """
[honeypot]
honeyport = 443
honeyfolder = "test"

[hive]
hiveport = 9999
"""
        toml_path = _write_toml(tmp_path, toml_content)
        result = _load_toml(toml_path)
        assert result["honeypot.honeyport"] == 443
        assert result["honeypot.honeyfolder"] == "test"
        assert result["hive.hiveport"] == 9999

    def test_load_toml_missing_file_raises(self, tmp_path):
        toml_path = tmp_path / "nonexistent.toml"
        with pytest.raises(FileNotFoundError):
            _load_toml(toml_path)
