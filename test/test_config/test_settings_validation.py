"""Tests for Settings class validation, defaults, and port mode resolution."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import Config


class TestConfigResolvePorts:
    """Tests for Config.resolve_ports() method."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        """Remove all HONEY_ env vars."""
        for key in list(os.environ.keys()):
            if key.startswith('HONEY_'):
                monkeypatch.delenv(key, raising=False)

    def test_resolve_ports_single_default(self):
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
            AUTHORIZED_BEES={},
            HONEY_PORT_MODE='single',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        assert cfg.resolve_ports() == [80]

    def test_resolve_ports_single_custom(self):
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
            AUTHORIZED_BEES={},
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
            AUTHORIZED_BEES={},
            HONEY_PORT_MODE='top',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert len(ports) == 50
        assert 80 in ports and 443 in ports and 22 in ports

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
            AUTHORIZED_BEES={},
            HONEY_PORT_MODE='top',
            HONEY_TOP_PORTS='80,443,8080,3306',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        assert cfg.resolve_ports() == [80, 443, 3306, 8080]

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
            AUTHORIZED_BEES={},
            HONEY_PORT_MODE='top',
            HONEY_TOP_PORTS='80, 443, 8080',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        assert cfg.resolve_ports() == [80, 443, 8080]

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
            AUTHORIZED_BEES={},
            HONEY_PORT_MODE='all',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        ports = cfg.resolve_ports()
        assert len(ports) == 65535
        assert ports[0] == 1 and ports[-1] == 65535

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
            AUTHORIZED_BEES={},
            HONEY_PORT_MODE='TOP',
            HONEY_TOP_PORTS='',
            DEFAULT_KEY='default_beehive_key',
            DUMP_FILE='dump.jsonl',
            LOG_FILE='~/.local/share/manyfaced/honeypot.log',
            LOCKFILE='/run/manyfaced/lockfile',
        )
        assert len(cfg.resolve_ports()) == 50

    def test_resolve_ports_env_override(self, monkeypatch):
        """HONEY_PORT_MODE env var overrides config."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_PORT_MODE', 'top')
            m.setenv('HONEY_TOP_PORTS', '8080,9090')
            cfg = Config.load()
        assert cfg.HONEY_PORT_MODE == 'top'
        assert cfg.HONEY_TOP_PORTS == '8080,9090'
        assert cfg.resolve_ports() == [8080, 9090]


class TestConfigRequiredSecrets:
    """Tests that required secrets (HIVEPASS, DEFAULT_KEY) are enforced."""

    def test_hivepass_required_raises_configvalidationerror(self, tmp_path, monkeypatch):
        """Config.load() with no HIVEPASS raises ConfigValidationError."""
        xdg_dir = tmp_path / 'xdg'
        xdg_dir.mkdir(parents=True, exist_ok=True)
        (xdg_dir / 'manyfaced').mkdir(exist_ok=True)
        (xdg_dir / 'manyfaced' / 'config.toml').write_text('[honeypot]\nhoneyport = 80\n')

        script = tmp_path / 'test_import.py'
        # Use raw string and os.path to avoid Windows path escaping issues
        script.write_text(r"""
import os, sys
from pathlib import Path

xdg_dir = r'{xdg_dir}'
os.environ['XDG_CONFIG_HOME'] = xdg_dir

for p in Path.home().glob('.config/manyfaced/config.toml'):
    p.unlink()

sys.path.insert(0, '/home/zlol/manyfaced-honeypot')
try:
    import manyfaced.common.config as config_mod
    print('IMPORT_SUCCESS')
except Exception as exc:
    print('EXCEPTION:' + type(exc).__name__ + ':' + str(exc))
""" .format(xdg_dir=str(xdg_dir)))

        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=10
        )
        # The exception is caught and printed, so we check stdout for the error
        assert 'EXCEPTION:ConfigValidationError' in result.stdout, (
            f'Expected ConfigValidationError, got {result.stdout!r}'
        )
        assert 'HONEY_HIVEPASS' in result.stdout, (
            f'Expected HONEY_HIVEPASS error message, got {result.stdout!r}'
        )

    def test_default_key_required_raises_configvalidationerror(self, tmp_path, monkeypatch):
        """Config.load() with no DEFAULT_KEY raises ConfigValidationError."""
        xdg_dir = tmp_path / 'xdg'
        xdg_dir.mkdir(parents=True, exist_ok=True)
        (xdg_dir / 'manyfaced').mkdir(exist_ok=True)
        (xdg_dir / 'manyfaced' / 'config.toml').write_text(
            '[honeypot]\nhoneyport = 80\n\n[hive]\nhivepass = "testpass"\n'
        )

        script = tmp_path / 'test_import2.py'
        script.write_text(r"""
import os, sys
from pathlib import Path

xdg_dir = r'{xdg_dir}'
os.environ['XDG_CONFIG_HOME'] = xdg_dir

for p in Path.home().glob('.config/manyfaced/config.toml'):
    p.unlink()

sys.path.insert(0, '/home/zlol/manyfaced-honeypot')
try:
    import manyfaced.common.config as config_mod
    print('IMPORT_SUCCESS')
except Exception as exc:
    print('EXCEPTION:' + type(exc).__name__ + ':' + str(exc))
""" .format(xdg_dir=str(xdg_dir)))

        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=10
        )
        assert 'EXCEPTION:ConfigValidationError' in result.stdout, (
            f'Expected ConfigValidationError, got {result.stdout!r}'
        )
        assert 'default_key' in result.stdout.lower(), (
            f'Expected default_key error message, got {result.stdout!r}'
        )

    def test_generate_config_works_without_secrets(self, tmp_path, monkeypatch):
        """--generate-config should work even without HIVEPASS/DEFAULT_KEY set."""
        xdg_dir = tmp_path / 'xdg'
        xdg_dir.mkdir(parents=True, exist_ok=True)
        (xdg_dir / 'manyfaced').mkdir(exist_ok=True)

        script = tmp_path / 'test_generate.py'
        # Use pathlib to get forward-slash paths
        from pathlib import PureWindowsPath
        config_path = PureWindowsPath(xdg_dir / 'manyfaced' / 'config.toml').as_posix()
        xdg_dir_str = PureWindowsPath(xdg_dir).as_posix()
        script.write_text(r"""
import os, sys

# Set required secrets BEFORE importing config to bypass validation
os.environ['HONEY_HIVEPASS'] = 'test_hivepass_for_generate_config'
os.environ['HONEY_DEFAULT_KEY'] = 'test_default_key_for_generate_config'

from pathlib import Path

xdg_dir = r'{xdg_dir}'
os.environ['XDG_CONFIG_HOME'] = xdg_dir

for p in Path.home().glob('.config/manyfaced/config.toml'):
    p.unlink()

sys.path.insert(0, '/home/zlol/manyfaced-honeypot')

# Simulate --generate-config by loading config without validation
from manyfaced.common.config import Config
cfg = Config.load(validate_secrets=False)
path = cfg.generate_config_file('{config_path}')
print('GENERATED:' + str(path))
""" .format(xdg_dir=xdg_dir_str, config_path=config_path))

        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, (
            f'Expected generate-config to succeed without secrets, got {result.returncode}: {result.stderr}'
        )
        assert 'GENERATED:' in result.stdout, (
            f'Expected generated config path, got {result.stdout!r}'
        )
