"""Tests for environment variable resolution and _resolve function."""

import os
from pathlib import Path

import pytest

from .conftest import Config, _env_prefix, _resolve, _write_toml


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
        result = _resolve('authorized_bees', {}, 'security', None, 'HONEY_')
        assert result == {}

    def test_resolve_dict_from_toml(self):
        toml = {'security.authorized_bees': 'bee1:key1'}
        result = _resolve('authorized_bees', {}, 'security', toml, 'HONEY_')
        assert result == {'bee1': 'key1'}

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


class TestConfigEnvVars:
    """Config with env vars override TOML and defaults."""

    def test_env_vars_override_toml(self, tmp_path, monkeypatch):
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
authorized_bees = ""
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
        """When no TOML and no env, all defaults apply EXCEPT HIVEPASS/DEFAULT_KEY."""
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


class TestConfigAuthorisedBears:
    """Parse semicolon-separated authorized_bees from env var."""

    def test_env_var_authorized_bees(self, monkeypatch):
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_AUTHORIZED_BEES', 'bee1:key1;bee2:key2;bee3:key3')
            cfg = Config.load()

        assert cfg.AUTHORIZED_BEES == {
            'bee1': 'key1',
            'bee2': 'key2',
            'bee3': 'key3',
        }

    def test_authorized_bees_empty_env(self, monkeypatch):
        """Empty HONEY_AUTHORIZED_BEES env var returns default empty dict."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_AUTHORIZED_BEES', '')
            cfg = Config.load()

        assert cfg.AUTHORIZED_BEES == {}

    def test_authorized_bees_without_colon_ignored(self, monkeypatch):
        """Pairs without colon are ignored in authorized_bees parsing."""
        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: None)
            m.setenv('HONEY_AUTHORIZED_BEES', 'bee1:key1;invalid_no_colon;bee2:key2')
            cfg = Config.load()

        assert cfg.AUTHORIZED_BEES == {'bee1': 'key1', 'bee2': 'key2'}

    def test_authorized_bees_from_toml(self, tmp_path, monkeypatch):
        """AUTHORIZED_BEES can be set via TOML file."""
        toml_content = '[security]\nauthorized_bees = "toml_bee:toml_key"\n'
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)
            m.delenv('HONEY_AUTHORIZED_BEES', raising=False)
            cfg = Config.load()

        assert cfg.AUTHORIZED_BEES == {'toml_bee': 'toml_key'}

    def test_authorized_bees_env_overrides_toml(self, tmp_path, monkeypatch):
        """AUTHORIZED_BEES env var overrides TOML."""
        toml_content = '[security]\nauthorized_bees = "toml_bee:toml_key"\n'
        config_path = _write_toml(tmp_path, toml_content)

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: config_path)
            m.setenv('HONEY_AUTHORIZED_BEES', 'env_bee:env_key')
            cfg = Config.load()

        assert cfg.AUTHORIZED_BEES == {'env_bee': 'env_key'}
