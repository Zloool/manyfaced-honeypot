"""Regression tests for CodeQL alert #174: generate_config_file must not persist
clear-text sensitive secrets (HIVEPASS, DB_PG_PASSWORD, DEFAULT_KEY).

These secrets are sourced from HONEY_* env vars at runtime (the highest precedence
layer), so writing them into the generated TOML is redundant clear-text storage. This
mirrors the dashboard-secret exclusion established in issue #659.

The test ``test_generate_config_file_does_not_persist_secrets`` fails on the
pre-fix code because the literal secret values are written into the generated file.
"""

from .conftest import Config


def _minimal_config(**overrides) -> Config:
    fields = dict(
        HONEYPORT=443,
        HONEYFOLDER='bots',
        HIVEHOST='127.0.0.1',
        HIVEPORT=8080,
        HIVELOGIN='honeybee',
        HIVEPASS='super_secret_hivepass',
        DB_BACKEND='postgresql',
        DB_BACKENDS=('sqlite', 'postgresql'),
        DB_PATH='bots/honeypot.db',
        DB_PG_HOST='localhost',
        DB_PG_PORT=5432,
        DB_PG_DB='honeypot',
        DB_PG_USER='postgres',
        DB_PG_PASSWORD='super_secret_pg_pass',
        DB_PG_SSLMODE='prefer',
        DB_PG_DSN='',
        AUTHORIZED_BEES={},
        HONEY_PORT_MODE='single',
        HONEY_TOP_PORTS='',
        DEFAULT_KEY='super_secret_default_key',
        DUMP_FILE='dump.jsonl',
        LOG_FILE='~/.local/share/manyfaced/honeypot.log',
        LOCKFILE='/run/manyfaced/lockfile',
    )
    fields.update(overrides)
    return Config(**fields)


class TestSecretsNotPersisted:
    def test_generate_config_file_does_not_persist_secrets(self, tmp_path):
        cfg = _minimal_config()
        path = cfg.generate_config_file(path=tmp_path / 'config.toml')
        content = path.read_text(encoding='utf-8')

        # No ACTIVE (non-comment) assignment of the three sensitive keys.
        active = [
            ln
            for ln in content.splitlines()
            if ln.strip().startswith(('hivepass =', 'pg_password =', 'default_key ='))
        ]
        assert active == [], f'unexpected persisted secret line(s): {active}'

        # The literal secret values must never appear in the generated file.
        for secret in (
            'super_secret_hivepass',
            'super_secret_pg_pass',
            'super_secret_default_key',
        ):
            assert secret not in content, f'clear-text secret leaked: {secret}'

        # Guidance to use the env vars must be present.
        assert 'HONEY_HIVEPASS' in content
        assert 'HONEY_PG_PASSWORD' in content
        assert 'HONEY_DEFAULT_KEY' in content

    def test_load_recovers_secrets_from_env(self, tmp_path, monkeypatch):
        """Loading the secret-free generated file still resolves secrets from env."""
        cfg = _minimal_config()
        path = cfg.generate_config_file(path=tmp_path / 'config.toml')

        with monkeypatch.context() as m:
            m.setattr('manyfaced.common.config._find_config_file', lambda: path)
            m.setenv('HONEY_HIVEPASS', 'super_secret_hivepass')
            m.setenv('HONEY_PG_PASSWORD', 'super_secret_pg_pass')
            m.setenv('HONEY_DEFAULT_KEY', 'super_secret_default_key')
            loaded = Config.load()

        assert loaded.HIVEPASS == 'super_secret_hivepass'
        assert loaded.DB_PG_PASSWORD == 'super_secret_pg_pass'
        assert loaded.DEFAULT_KEY == 'super_secret_default_key'
