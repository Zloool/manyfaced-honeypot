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
# utils.py  –  dump_file / receive_timeout
# ===================================================================

class TestDumpFile:
    """Tests for dump_file(data): reads/writes pickle to temp.db, appends data to list."""

    def test_creates_file_and_writes_data(self, tmp_path):
        """dump_file creates temp.db, writes pickled list with data."""
        db_path = tmp_path / "temp.db"
        with patch("manyfaced.common.utils.open", MagicMock(return_value=open(db_path, "wb"))):
            # We need to patch the actual open used inside dump_file.
            # Simpler: monkey-patch the module's working directory approach.
            pass

        # Simpler approach: override the filename by patching open at the module level
        with patch("manyfaced.common.utils.open", patch_open_context(db_path)):
            dump_file({"key": "value"})
            loaded = pickle.loads(db_path.read_bytes())
        assert loaded == [{"key": "value"}]

    def test_appends_to_existing_list(self, tmp_path):
        """dump_file appends data to existing list in temp.db."""
        db_path = tmp_path / "temp.db"
        # Pre-populate the file
        db_path.write_bytes(pickle.dumps([{"first": 1}]))

        with patch("manyfaced.common.utils.open", patch_open_context(db_path)):
            dump_file({"second": 2})

        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == [{"first": 1}, {"second": 2}]

    def test_handles_missing_file(self, tmp_path):
        """dump_file handles missing temp.db gracefully (creates new list)."""
        db_path = tmp_path / "temp.db"
        assert not db_path.exists()

        with patch("manyfaced.common.utils.open", patch_open_context(db_path)):
            dump_file("new_data")

        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == ["new_data"]

    def test_multiple_appends(self, tmp_path):
        """Multiple dump_file calls accumulate data."""
        db_path = tmp_path / "temp.db"

        with patch("manyfaced.common.utils.open", patch_open_context(db_path)):
            dump_file("item1")
            dump_file("item2")
            dump_file("item3")

        loaded = pickle.loads(db_path.read_bytes())
        assert loaded == ["item1", "item2", "item3"]


class TestReceiveTimeout:
    """Tests for receive_timeout(the_socket, timeout): non-blocking socket recv with timeout logic."""

    def test_assembles_multiple_receives(self, monkeypatch):
        """receive_timeout assembles data from multiple recv calls until empty."""
        mock_socket = MagicMock()
        data_chunks = [b"HTTP/1.1 200 OK\r\n", b"Content-Type: text/html\r\n", b"\r\n", b"<!DOCTYPE html>", b""]

        call_count = [0]
        def side_effect(*args):
            idx = call_count[0]
            call_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)
        monkeypatch.setattr("time.time", lambda: 1000.0)
        monkeypatch.setattr("time.sleep", lambda *a: None)

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>"
        assert mock_socket.setblocking.called
        assert mock_socket.recv.call_count == 5  # 4 data + 1 empty

    def test_returns_empty_on_immediate_empty(self, monkeypatch):
        """receive_timeout returns empty string when socket immediately returns empty."""
        mock_socket = MagicMock()
        mock_socket.recv = MagicMock(return_value=b"")
        monkeypatch.setattr("time.time", lambda: 1000.0)
        monkeypatch.setattr("time.sleep", lambda *a: None)

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == ""

    def test_timeout_breaks_after_data_received(self, monkeypatch):
        """receive_timeout breaks out of loop after timeout once data has been received."""
        mock_socket = MagicMock()
        mock_socket.recv = MagicMock(side_effect=[b"data1", b"data2", b"data3", b"data4", b"data5"])
        monkeypatch.setattr("time.sleep", lambda *a: None)

        # time.time advances by 0.01 each call to simulate real time passing
        call_count = [0]
        def time_side_effect():
            call_count[0] += 1
            return 1000.0 + call_count[0] * 0.01

        monkeypatch.setattr("time.time", time_side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        # Should have received some data then timed out
        assert result == b"data1data2data3data4data5"

    def test_timeout_without_data(self, monkeypatch):
        """receive_timeout returns empty after timeout*2 even with no data."""
        mock_socket = MagicMock()
        mock_socket.recv = MagicMock(side_effect=[])

        call_count = [0]
        def recv_side_effect(*args):
            call_count[0] += 1
            if call_count[0] <= 20:
                raise Exception("would block")  # socket.error equivalent
            return b""

        mock_socket.recv = MagicMock(side_effect=recv_side_effect)
        monkeypatch.setattr("time.sleep", lambda *a: None)

        call_count[0] = 0
        def time_side_effect():
            call_count[0] += 1
            return 1000.0 + call_count[0] * 0.01

        monkeypatch.setattr("time.time", time_side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == ""

    def test_refreshes_begin_on_data(self, monkeypatch):
        """receive_timeout resets begin time when new data arrives, extending the window."""
        mock_socket = MagicMock()
        data_chunks = [b"a", b"b", b"c", b""]
        recv_count = [0]

        def side_effect(*args):
            idx = recv_count[0]
            recv_count[0] += 1
            return data_chunks[idx]

        mock_socket.recv = MagicMock(side_effect=side_effect)
        monkeypatch.setattr("time.sleep", lambda *a: None)

        # time advances: 0, 0.5, 1.0, 1.5, 2.0
        # With timeout=1.0: begin starts at 0, data at 0.5 resets begin to 0.5, data at 1.0 resets to 1.0,
        # empty at 1.5, then 2.0 - 1.0 = 1.0 > timeout → break
        call_count = [0]
        def time_side_effect():
            call_count[0] += 1
            return 1000.0 + call_count[0] * 0.5

        monkeypatch.setattr("time.time", time_side_effect)

        result = receive_timeout(mock_socket, timeout=1.0)

        assert result == b"abc"

    def test_socket_error_handled(self, monkeypatch):
        """receive_timeout handles socket.error (would block) gracefully."""
        from socket import error as socket_error
        mock_socket = MagicMock()

        recv_count = [0]
        def side_effect(*args):
            recv_count[0] += 1
            if recv_count[0] <= 3:
                raise socket_error("would block")
            return b"got data"

        mock_socket.recv = MagicMock(side_effect=side_effect)
        mock_socket.recv = MagicMock(side_effect=side_effect)
        mock_socket.setblocking = MagicMock()
        monkeypatch.setattr("time.sleep", lambda *a: None)

        call_count = [0]
        def time_side_effect():
            call_count[0] += 1
            return 1000.0 + call_count[0] * 0.01

        monkeypatch.setattr("time.time", time_side_effect)

        result = receive_timeout(mock_socket, timeout=0.5)

        assert result == b"got data"


# ===================================================================
# config.py  –  Config.load / generate_config_file / _find_config_file / _load_toml / _resolve
# ===================================================================

# Helper: create a TOML file with given sections
def _write_toml(tmp_path, content):
    """Write a TOML file and return its Path."""
    toml_path = tmp_path / "config.toml"
    toml_path.write_text(content)
    return toml_path


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
honeyfolder = "malware"

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
        # TOML values not overridden should still apply
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
            # Only override HONEYPORT and HIVEPORT via env
            m.setenv("HONEY_HONEYPORT", "9090")
            m.setenv("HONEY_HIVEPORT", "7070")

            cfg = Config.load()

        # Env wins
        assert cfg.HONEYPORT == 9090
        assert cfg.HIVEPORT == 7070

        # TOML wins over defaults (no env for these)
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
            # Clear all HONEY_ env vars
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
        # Use tmp_path as home
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
        # Other values should be defaults since TOML only has honeyport
        assert cfg.HONEYFOLDER == "bots"


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
            # Clear env var so TOML wins
            m.delenv("HONEY_AUTHORISEDBEARS", raising=False)

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {"toml_bear": "toml_key"}


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
# Additional helper: patch open for dump_file testing
# ===================================================================

class patch_open_context:
    """Context manager that patches builtins.open to use a specific file path."""

    def __init__(self, path):
        self.path = path
        self._real_open = open

    def __enter__(self):
        self._mock = patch("manyfaced.common.utils.open", new=self._patched)
        self._mock.start()
        return self._mock

    def __exit__(self, *exc):
        self._mock.stop()

    def _patched(self, *args, **kwargs):
        return self._real_open(self.path, *args[1:], **kwargs)
