"""Tests for TOML file loading, parsing, and discovery."""

import os
from pathlib import Path

import pytest

from .conftest import Config, _load_toml, _write_toml


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


class TestConfigDefaults:
    """Config with no TOML file, no env vars → returns defaults."""

    def test_defaults_no_toml_no_env(self, tmp_path, monkeypatch):
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
        assert cfg.AUTHORIZED_BEES == {}
        assert cfg.DEFAULT_KEY == 'default_beehive_key'


class TestConfigToml:
    """Config with TOML file overrides, verify TOML values take precedence."""

    def test_toml_overrides_defaults(self, tmp_path, monkeypatch):
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
authorized_bees = ""
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


class TestConfigGenerateConfigFile:
    """generate_config_file creates file at expected path with correct TOML content."""

    def test_creates_file_at_default_path(self, tmp_path, monkeypatch):
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
            AUTHORIZED_BEES={},
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
        for check in [
            '[honeypot]',
            'honeyport = 443',
            'honeyfolder = "bots"',
            '[hive]',
            'hivehost = "127.0.0.1"',
            'hiveport = 8080',
            'hivelogin = "honeybee"',
            'hivepass = "beehive123"',
            '[database]',
            'backend = "sqlite"',
            'path = "bots/honeypot.db"',
            'pg_host = "localhost"',
            'pg_port = 5432',
            'pg_db = "honeypot"',
            'pg_user = "postgres"',
            'pg_password = "***"',
            '[security]',
        ]:
            assert check in content

    def test_creates_file_at_custom_path(self, tmp_path):
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

        custom_path = tmp_path / 'custom' / 'config.toml'
        path = cfg.generate_config_file(path=custom_path)

        assert path == custom_path
        assert path.exists()
        assert 'honeyport = 80' in path.read_text()


class TestConfigLoadCustomPath:
    """load with explicit config_path."""

    def test_load_with_explicit_config_path(self, tmp_path):
        toml_content = '[honeypot]\nhoneyport = 8888\n'
        config_path = _write_toml(tmp_path, toml_content)
        cfg = Config.load(config_path=config_path)

        assert cfg.HONEYPORT == 8888
        assert cfg.HONEYFOLDER == 'bots'

    def test_load_with_string_path(self, tmp_path):
        toml_content = '[honeypot]\nhoneyport = 7777\n'
        config_path = str(_write_toml(tmp_path, toml_content))
        cfg = Config.load(config_path=config_path)

        assert cfg.HONEYPORT == 7777
