"""Regression tests for issue #659: generate_config_file must not persist a
clear-text dashboard secret, and Config.load must fall back to an ephemeral
secret when none is configured (env or pinned TOML secret).
"""

from pathlib import Path

import pytest

from manyfaced.common.config import Config


def _minimal_config(**overrides) -> Config:
    fields = dict(
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
        DB_PG_SSLMODE='prefer',
        DB_PG_DSN='',
        AUTHORIZED_BEES={},
        HONEY_PORT_MODE='single',
        HONEY_TOP_PORTS='',
        DEFAULT_KEY='default_beehive_key',
        DUMP_FILE='dump.jsonl',
        LOG_FILE='~/.local/share/manyfaced/honeypot.log',
        LOCKFILE='/run/manyfaced/lockfile',
    )
    fields.update(overrides)
    return Config(**fields)


class TestDashboardSecretNotPersisted:
    def test_generate_config_file_does_not_persist_secret(self, tmp_path):
        cfg = _minimal_config()
        path = cfg.generate_config_file(path=tmp_path / 'config.toml')
        content = path.read_text(encoding='utf-8')
        # No ACTIVE (non-comment) dashboard secret assignment may be written.
        active = [ln for ln in content.splitlines() if ln.strip().startswith('secret =')]
        assert active == [], f'unexpected persisted secret line(s): {active}'
        # Documentation of the env var must be present.
        assert 'HONEY_DASHBOARD_SECRET' in content

    def test_load_generates_ephemeral_secret_when_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv('HONEY_DASHBOARD_SECRET', raising=False)
        cfg_path = tmp_path / 'config.toml'
        cfg_path.write_text('[honeypot]\nhoneyport = 8080\n', encoding='utf-8')
        cfg = Config.load(config_path=cfg_path)
        assert cfg.DASHBOARD_SECRET, 'expected an ephemeral dashboard secret when none configured'
