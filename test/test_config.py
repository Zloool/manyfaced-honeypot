"""
Tests for manyfaced.common.utils, manyfaced.common.config, and manyfaced.common.arguments.

Usage:
    /usr/bin/python3 -m pytest test/test_utils_config_args.py -v -c /home/zlol/manyfaced-honeypot/pytest.ini
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ---------------------------------------------------------------------------
# Mock geoip modules before any module that uses it is imported
# ---------------------------------------------------------------------------
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules['geoip'] = geoip_mock
sys.modules['geoip.geolite2'] = geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()

# ---------------------------------------------------------------------------
# Import units under test
# ---------------------------------------------------------------------------
from manyfaced.common.config import Config, _load_toml, _resolve, _env_prefix


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
        self._mock = patch('manyfaced.common.utils.open', self._patched_open)
        self._mock.start()
        return self.path

    def __exit__(self, *exc):
        if self._mock:
            self._mock.stop()

    def _patched_open(self, path, mode, *args, **kwargs):
        return self._real_open(self.path, mode, *args, **kwargs)


def _write_toml(tmp_path, content):
    """Write a TOML file and return its Path."""
    toml_path = tmp_path / 'config.toml'
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


class TestConfigDefaults:
    """Config with no TOML file, no env vars → returns defaults."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        """Remove all HONEY_ env vars."""
        for key in list(os.environ.keys()):
            if key.startswith('HONEY_'):
                monkeypatch.delenv(key, raising=False)

    def test_defaults_no_toml_no_env(self, tmp_path, monkeypatch):
        """All values should be defaults when no TOML and no env vars.

        Note: HIVEPASS and DEFAULT_KEY must be explicitly configured in production.
        Tests that load Config without these values will see None, which triggers
        a fatal error at module-level validation. We set them in the TOML to
        simulate a properly configured deployment.
        """
        toml_content = """
[hive]
hivepass = "beehive123"

[security]
default_key = "default_beehive_key"
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)

            cfg = Config.load()

        assert cfg.HONEYPORT == 80
        assert cfg.HONEYFOLDER == 'bots'
        assert cfg.HIVEHOST == '127.0.0.1'
        assert cfg.HIVEPORT == 8080
        assert cfg.HIVELOGIN == 'honeybee'
        assert cfg.HIVEPASS == 'beehive123'
        assert cfg.DB_BACKEND == 'sqlite'
        assert cfg.DB_PATH == 'bots/honeypot.db'
        assert cfg.DB_PG_HOST == 'localhost'
        assert cfg.DB_PG_PORT == 5432
        assert cfg.DB_PG_DB == 'honeypot'
        assert cfg.DB_PG_USER == 'postgres'
        assert cfg.DB_PG_PASSWORD == '***'
        assert cfg.AUTHORISEDBEARS == {}
        assert cfg.DEFAULT_KEY == 'default_beehive_key'


class TestConfigToml:
    """Config with TOML file overrides, verify TOML values take precedence over defaults."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        for key in list(os.environ.keys()):
            if key.startswith('HONEY_'):
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
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)

            cfg = Config.load()

        assert cfg.HONEYPORT == 443
        assert cfg.HONEYFOLDER == 'malware'
        assert cfg.HIVEHOST == '10.0.0.1'
        assert cfg.HIVEPORT == 9999
        assert cfg.HIVELOGIN == 'admin'
        assert cfg.HIVEPASS == 'secret123'
        assert cfg.DB_PATH == 'data/honeypot.db'
        assert cfg.DB_PG_HOST == 'db.example.com'
        assert cfg.DB_PG_PORT == 5433
        assert cfg.DB_PG_DB == 'myhoneypot'
        assert cfg.DB_PG_USER == 'admin'
        assert cfg.DB_PG_PASSWORD == 'dbpass'


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
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)
            m.setenv('HONEY_HONEYPORT', '8080')
            m.setenv('HONEY_HONEYFOLDER', 'env_folder')
            m.setenv('HONEY_HIVEPORT', '3000')

            cfg = Config.load()

        assert cfg.HONEYPORT == 8080
        assert cfg.HONEYFOLDER == 'env_folder'
        assert cfg.HIVEPORT == 3000
        assert cfg.HIVEHOST == '10.0.0.1'


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
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)
            m.setenv('HONEY_HONEYPORT', '9090')
            m.setenv('HONEY_HIVEPORT', '7070')

            cfg = Config.load()

        assert cfg.HONEYPORT == 9090
        assert cfg.HIVEPORT == 7070
        assert cfg.HONEYFOLDER == 'toml_folder'
        assert cfg.HIVEHOST == '10.0.0.1'
        assert cfg.HIVELOGIN == 'toml_login'
        assert cfg.HIVEPASS == 'toml_pass'
        assert cfg.DB_BACKEND == 'postgresql'
        assert cfg.DB_PATH == 'toml_path.db'
        assert cfg.DB_PG_HOST == 'toml_host'
        assert cfg.DB_PG_PORT == 5433
        assert cfg.DB_PG_DB == 'toml_db'
        assert cfg.DB_PG_USER == 'toml_user'
        assert cfg.DB_PG_PASSWORD == 'toml_pass'

    def test_defaults_when_no_toml_no_env(self, tmp_path, monkeypatch):
        """When no TOML and no env, all defaults apply EXCEPT HIVEPASS/DEFAULT_KEY.

        After the security fix, HIVEPASS and DEFAULT_KEY have no defaults —
        they must be explicitly configured. Tests that load Config without
        these values will hit a fatal SystemExit at module level.
        We set them in the TOML to simulate a properly configured deployment.
        """
        toml_content = """
[hive]
hivepass = "beehive123"

[security]
default_key = "default_beehive_key"
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)

            cfg = Config.load()

        assert cfg.HONEYPORT == 80
        assert cfg.HONEYFOLDER == 'bots'
        assert cfg.HIVEHOST == '127.0.0.1'
        assert cfg.HIVEPORT == 8080
        assert cfg.HIVELOGIN == 'honeybee'
        assert cfg.HIVEPASS == 'beehive123'
        assert cfg.DB_BACKEND == 'sqlite'
        assert cfg.DB_PATH == 'bots/honeypot.db'
        assert cfg.DB_PG_HOST == 'localhost'
        assert cfg.DB_PG_PORT == 5432
        assert cfg.DB_PG_DB == 'honeypot'
        assert cfg.DB_PG_USER == 'postgres'
        assert cfg.DB_PG_PASSWORD == '***'
        assert cfg.DEFAULT_KEY == 'default_beehive_key'

    def test_hivepass_required_raises_systemexit(self, tmp_path, monkeypatch):
        """Config.load() with no HIVEPASS raises SystemExit(1) at module level."""
        import subprocess
        import sys

        toml_content = '[honeypot]\nhoneyport = 80\n'
        toml_path = tmp_path / 'config.toml'
        toml_path.write_text(toml_content)

        # Use a fresh Python process with a clean sys.modules
        script = tmp_path / 'test_import.py'
        script.write_text(f"""
import sys, os, importlib, importlib.util, types

# Clear any cached manyfaced modules
mods_to_remove = [k for k in sys.modules if k.startswith('manyfaced')]
for m in mods_to_remove:
    del sys.modules[m]

os.environ['XDG_CONFIG_HOME'] = '{tmp_path}'
# Remove any existing config
import pathlib
for p in pathlib.Path.home().glob('.config/manyfaced/config.toml'):
    p.unlink()

# Now import fresh
spec = importlib.util.spec_from_file_location(
    'config',
    '/home/zlol/manyfaced-honeypot/manyfaced/common/config.py'
)
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    sys.exit(0)  # Should not reach here
except SystemExit as e:
    sys.exit(e.code)
""")
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 1, (
            f'Expected SystemExit(1), got {result.returncode}: {result.stderr}'
        )

    def test_default_key_required_raises_systemexit(self, tmp_path, monkeypatch):
        """Config.load() with no DEFAULT_KEY raises SystemExit(1) at module level."""
        import subprocess
        import sys

        toml_content = '[honeypot]\nhoneyport = 80\n\n[hive]\nhivepass = "testpass"\n'
        toml_path = tmp_path / 'config.toml'
        toml_path.write_text(toml_content)

        script = tmp_path / 'test_import2.py'
        script.write_text(f"""
import sys, os, importlib, importlib.util

mods_to_remove = [k for k in sys.modules if k.startswith('manyfaced')]
for m in mods_to_remove:
    del sys.modules[m]

os.environ['XDG_CONFIG_HOME'] = '{tmp_path}'
import pathlib
for p in pathlib.Path.home().glob('.config/manyfaced/config.toml'):
    p.unlink()

spec = importlib.util.spec_from_file_location(
    'config',
    '/home/zlol/manyfaced-honeypot/manyfaced/common/config.py'
)
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    sys.exit(0)
except SystemExit as e:
    sys.exit(e.code)
""")
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 1, (
            f'Expected SystemExit(1), got {result.returncode}: {result.stderr}'
        )


class TestConfigGenerateConfigFile:
    """generate_config_file creates file at expected path with correct TOML content."""

    def test_creates_file_at_default_path(self, tmp_path, monkeypatch):
        """generate_config_file writes to ~/.config/manyfaced/config.toml by default."""
        fake_home = tmp_path / 'home'
        fake_home.mkdir()
        monkeypatch.setenv('HOME', str(fake_home))

        cfg = Config(
            HONEYPORT=443,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='single',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )

        path = cfg.generate_config_file()

        assert path == fake_home / '.config' / 'manyfaced' / 'config.toml'
        assert path.exists()
        content = path.read_text()
        assert '[honeypot]' in content
        assert 'honeyport = 443' in content
        assert 'honeyfolder = "bots"' in content
        assert '[hive]' in content
        assert 'hivehost = "127.0.0.1"' in content
        assert 'hiveport = 8080' in content
        assert 'hivelogin = "honeybee"' in content
        assert 'hivepass = "beehive123"' in content
        assert '[database]' in content
        assert 'backend = "sqlite"' in content
        assert 'path = "bots/honeypot.db"' in content
        assert 'pg_host = "localhost"' in content
        assert 'pg_port = 5432' in content
        assert 'pg_db = "honeypot"' in content
        assert 'pg_user = "postgres"' in content
        assert 'pg_password = "***"' in content
        assert '[security]' in content

    def test_creates_file_at_custom_path(self, tmp_path, monkeypatch):
        """generate_config_file writes to a custom path when specified."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='single',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )

        custom_path = tmp_path / 'custom' / 'config.toml'
        path = cfg.generate_config_file(path=custom_path)

        assert path == custom_path
        assert path.exists()
        assert 'honeyport = 80' in path.read_text()


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
        assert cfg.HONEYFOLDER == 'bots'

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
        """AUTHORISEDBEARS parsed from HONEY_AUTHORISED_BEARS env var."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_AUTHORISED_BEARS', 'bear1:key1;bear2:key2;bear3:key3')

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {
            'bear1': 'key1',
            'bear2': 'key2',
            'bear3': 'key3',
        }

    def test_authorised_bears_empty_env(self, monkeypatch):
        """Empty HONEY_AUTHORISED_BEARS env var returns default empty dict."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_AUTHORISED_BEARS', '')

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {}

    def test_authorised_bears_without_colon_ignored(self, monkeypatch):
        """Pairs without colon are ignored in authorised_bears parsing."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_AUTHORISED_BEARS', 'bear1:key1;invalid_no_colon;bear2:key2')

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {'bear1': 'key1', 'bear2': 'key2'}

    def test_authorised_bears_from_toml(self, tmp_path, monkeypatch):
        """AUTHORISEDBEARS can be set via TOML file."""
        toml_content = """
[security]
authorised_bears = "toml_bear:toml_key"
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)
            m.delenv('HONEY_AUTHORISED_BEARS', raising=False)

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {'toml_bear': 'toml_key'}

    def test_authorised_bears_env_overrides_toml(self, tmp_path, monkeypatch):
        """AUTHORISEDBEARS env var overrides TOML."""
        toml_content = """
[security]
authorised_bears = "toml_bear:toml_key"
"""
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)
            m.setenv('HONEY_AUTHORISED_BEARS', 'env_bear:env_key')

            cfg = Config.load()

        assert cfg.AUTHORISEDBEARS == {'env_bear': 'env_key'}


# ===================================================================
# arguments.py  –  parse()
# ===================================================================


class TestResolve:
    """Tests for the _resolve helper function."""

    def test_resolve_int_default(self):
        result = _resolve('honeyport', 80, 'honeypot', None, 'HONEY_')
        assert result == 80

    def test_resolve_int_from_toml(self):
        toml = {'honeypot.honeyport': 443}
        result = _resolve('honeyport', 80, 'honeypot', toml, 'HONEY_')
        assert result == 443

    def test_resolve_int_from_env(self, monkeypatch):
        monkeypatch.setenv('HONEY_HONEYPORT', '9090')
        result = _resolve('honeyport', 80, 'honeypot', None, 'HONEY_')
        assert result == 9090

    def test_resolve_str_default(self):
        result = _resolve('honeyfolder', 'bots', 'honeypot', None, 'HONEY_')
        assert result == 'bots'

    def test_resolve_str_from_toml(self):
        toml = {'honeypot.honeyfolder': 'malware'}
        result = _resolve('honeyfolder', 'bots', 'honeypot', toml, 'HONEY_')
        assert result == 'malware'

    def test_resolve_str_from_env(self, monkeypatch):
        monkeypatch.setenv('HONEY_HONEYFOLDER', 'env_folder')
        result = _resolve('honeyfolder', 'bots', 'honeypot', None, 'HONEY_')
        assert result == 'env_folder'

    def test_resolve_dict_default(self):
        result = _resolve('authorised_bears', {}, 'security', None, 'HONEY_')
        assert result == {}

    def test_resolve_dict_from_toml(self):
        toml = {'security.authorised_bears': 'bear1:key1'}
        result = _resolve('authorised_bears', {}, 'security', toml, 'HONEY_')
        assert result == {'bear1': 'key1'}

    def test_resolve_tuple_from_env(self, monkeypatch):
        monkeypatch.setenv('HONEY_BACKENDS', 'sqlite;postgresql')
        result = _resolve('backends', ('sqlite', 'postgresql'), 'database', None, 'HONEY_')
        assert result == ['sqlite', 'postgresql']

    def test_env_overrides_toml(self, monkeypatch):
        toml = {'honeypot.honeyport': 443}
        monkeypatch.setenv('HONEY_HONEYPORT', '9090')
        result = _resolve('honeyport', 80, 'honeypot', toml, 'HONEY_')
        assert result == 9090

    def test_toml_overrides_default(self):
        toml = {'honeypot.honeyport': 443}
        result = _resolve('honeyport', 80, 'honeypot', toml, 'HONEY_')
        assert result == 443


class TestEnvPrefix:
    """Tests for _env_prefix."""

    def test_default_prefix(self):
        assert _env_prefix() == 'HONEY_'


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
        assert result['honeypot.honeyport'] == 443
        assert result['honeypot.honeyfolder'] == 'test'
        assert result['hive.hiveport'] == 9999

    def test_load_toml_missing_file_raises(self, tmp_path):
        toml_path = tmp_path / 'nonexistent.toml'
        with pytest.raises(FileNotFoundError):
            _load_toml(toml_path)


# ===================================================================
# Port mode tests – Config.resolve_ports()
# ===================================================================


class TestConfigResolvePorts:
    """Tests for Config.resolve_ports() method."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        """Remove all HONEY_ env vars."""
        for key in list(os.environ.keys()):
            if key.startswith('HONEY_'):
                monkeypatch.delenv(key, raising=False)

    def test_resolve_ports_single_default(self):
        """Single mode returns [HONEYPORT]."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='single',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        assert cfg.resolve_ports() == [80]

    def test_resolve_ports_single_custom(self):
        """Single mode with custom HONEYPORT."""
        cfg = Config(
            HONEYPORT=443,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='single',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        assert cfg.resolve_ports() == [443]

    def test_resolve_ports_top_default(self):
        """Top mode returns the default top 50 ports."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='top',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert len(ports) == 50
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports

    def test_resolve_ports_top_custom(self):
        """Top mode with custom port list."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='top',
            HONEY_TOP_PORTS='80,443,8080,3306',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert ports == [80, 443, 3306, 8080]

    def test_resolve_ports_top_custom_with_spaces(self):
        """Top mode with custom port list containing spaces."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='top',
            HONEY_TOP_PORTS='80, 443, 8080',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert ports == [80, 443, 8080]

    def test_resolve_ports_all(self):
        """All mode returns all 65535 ports."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='all',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert len(ports) == 65535
        assert ports[0] == 1
        assert ports[-1] == 65535

    def test_resolve_ports_case_insensitive(self):
        """Port mode is case-insensitive."""
        cfg = Config(
            HONEYPORT=80,
            HONEYFOLDER='bots',
            HIVEHOST='127.0.0.1',
            HIVEPORT=8080,
            HIVELOGIN='honeybee',
            HIVEPASS='beehive123',
            DB_BACKEND='sqlite',
            DB_BACKENDS=('sqlite', 'postgresql'),
            DB_PATH='bots/honeypot.db',
            DB_PG_HOST='localhost',
            DB_PG_PORT=5432,
            DB_PG_DB='honeypot',
            DB_PG_USER='postgres',
            DB_PG_PASSWORD='***',
            AUTHORISEDBEARS={},
            HONEY_PORT_MODE='TOP',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert len(ports) == 50

    def test_resolve_ports_env_override(self, monkeypatch):
        """HONEY_PORT_MODE env var overrides config."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_PORT_MODE', 'top')
            m.setenv('HONEY_TOP_PORTS', '8080,9090')
            cfg = Config.load()
        assert cfg.HONEY_PORT_MODE == 'top'
        assert cfg.HONEY_TOP_PORTS == '8080,9090'
        ports = cfg.resolve_ports()
        assert ports == [8080, 9090]
