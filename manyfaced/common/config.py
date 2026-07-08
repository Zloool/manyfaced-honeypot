"""
manyfaced configuration – modern, industry-standard settings mechanism.

Three-layer precedence (lowest → highest):
  1. Code defaults (hardcoded below)
  2. TOML config file  ({XDG_CONFIG_HOME}/manyfaced/config.toml, or ~/.config/manyfaced/config.toml)
  3. Environment variables  (HONEY_HONEYPORT, HONEY_HIVEHOST, …)

Usage
---
From code (preferred):
    from manyfaced.common.config import settings
    port = settings.HONEYPORT

Import directly from this module:
    from manyfaced.common.config import settings
    port = settings.HONEYPORT

To change the TOML path at runtime:
    from manyfaced.common.config import Config
    settings = Config(config_path="/custom/path/settings.toml")

TOML config file layout (the file is auto-generated if run with --generate-config):
    [honeypot]
    honeyport = 80
    honeyfolder = "bots"

    [hive]
    hivehost = "127.0.0.1"
    hiveport = 666
    hivelogin = "CHORDCOLISION"
    hivepass = "test"

    [database]
    backend = "sqlite"
    path = "bots/honeypot.db"
    pg_host = "localhost"
    pg_port = 5432
    pg_db = "honeypot"
    pg_user = "postgres"
    pg_password = "postgres"

    [security]
    authorized_bees = ""  # semicolon-separated "bee_id:key" pairs for client sensors

    [ai]
    enabled = false
    endpoint = "http://127.0.0.1:8080/v1"
    model = "llama-3.1-8b-instruct"
    max_tokens = 500
    timeout = 5.0
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── defaults (layer 1 – code) ──────────────────────────────────────────────

_DEFAULT_HONEYPORT: int = 80
_DEFAULT_HONEYFOLDER: str = 'bots'
_DEFAULT_HIVEHOST: str = '127.0.0.1'
_DEFAULT_HIVEPORT: int = 8080
_DEFAULT_HIVELOGIN: str = 'honeybee'
_DEFAULT_HIVEPASS: str | None = None
_DEFAULT_DB_BACKEND: str = 'sqlite'
_DEFAULT_DB_BACKENDS: tuple[str, ...] = ('sqlite', 'postgresql')
_DEFAULT_DB_PATH: str = 'bots/honeypot.db'
_DEFAULT_DB_PG_HOST: str = 'localhost'
_DEFAULT_DB_PG_PORT: int = 5432
_DEFAULT_DB_PG_DB: str = 'honeypot'
_DEFAULT_DB_PG_USER: str = 'postgres'
_DEFAULT_DB_PG_PASSWORD: str = '***'
_DEFAULT_AUTHORIZED_BEES_DEFAULTS: dict[str, str] = {}

# ── port mode configuration (shared constants) ───────────────────────────────
from manyfaced.common.ports import DEFAULT_TOP_PORTS as _DEFAULT_TOP_PORTS  # noqa: E402, F401

# ── Security defaults ───────────────────────────────────────────────────────

_DEFAULT_DEFAULT_KEY: str | None = None
_DEFAULT_LOG_FILE: str = os.path.join(
    os.path.expanduser('~'), '.local', 'share', 'manyfaced', 'honeypot.log'
)
_DEFAULT_DUMP_FILE: str = 'dump.jsonl'
_DEFAULT_LOCKFILE: str = os.path.join('/opt/manyfaced/bots', 'lockfile')

# ── Dashboard defaults (issue #234) ────────────────────────────────────────
# The dashboard is OFF by default and bound to loopback. The access secret is
# auto-generated (secrets.token_urlsafe) and persisted to config.toml by
# generate_config_file(); it is NEVER a static default (unlike the legacy
# HONEY_HIVEPASS mistake). Bind address is defense-in-depth — the token is the
# real control.
_DEFAULT_DASHBOARD_ENABLED: bool = False
_DEFAULT_DASHBOARD_PORT: int = 8443
_DEFAULT_DASHBOARD_BIND: str = '127.0.0.1'
_DEFAULT_DASHBOARD_SECRET: str | None = None
_DEFAULT_DASHBOARD_TIME_RANGE: str = '24h'

# ── config file discovery (XDG base dirs) ──────────────────────────────────


def _find_config_file() -> Path | None:
    """Return the first existing user config file, or None if not found."""
    candidates: list[Path] = []
    xdg = os.environ.get('XDG_CONFIG_HOME')
    if xdg:
        candidates.append(Path(xdg) / 'manyfaced' / 'config.toml')
    # Always check fallback path (XDG is optional)
    candidates.append(Path.home() / '.config' / 'manyfaced' / 'config.toml')
    for c in candidates:
        if c.is_file():
            return c
    return None  # will be generated on-demand via --generate-config


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file and return a flat dict of section.key → value."""
    import tomllib

    with open(path, 'rb') as fh:
        raw = tomllib.load(fh)
    result: dict[str, Any] = {}
    for section, values in raw.items():
        if isinstance(values, dict):
            for key, val in values.items():
                result[f'{section}.{key}'] = val
    return result


from manyfaced.common.config_resolver import env_prefix, resolve_setting  # noqa: E402


@dataclass(frozen=True)
class Config:
    """Immutable configuration. Created lazily at module-level as the global ``settings``."""

    HONEYPORT: int
    HONEYFOLDER: str
    HIVEHOST: str
    HIVEPORT: int
    HIVELOGIN: str
    HIVEPASS: str
    DB_BACKEND: str
    DB_BACKENDS: tuple[str, ...]
    DB_PATH: str
    DB_PG_HOST: str
    DB_PG_PORT: int
    DB_PG_DB: str
    DB_PG_USER: str
    DB_PG_PASSWORD: str
    AUTHORIZED_BEES: dict[str, str]

    # Port mode configuration
    HONEY_PORT_MODE: str  # "single", "top", or "all"
    HONEY_TOP_PORTS: str  # comma-separated port list (used when mode="top" and user customizes)

    # Security
    DEFAULT_KEY: str  # default encryption key for unknown identifiers

    # Logging
    LOG_FILE: str  # path to the JSON log file

    # Dump file (fallback for failed DB writes)
    DUMP_FILE: str  # path to the JSONL dump file

    # Lockfile (prevents multiple instances)
    LOCKFILE: str  # path to the lockfile for instance management

    # Alerting: the raw [alerting] section from config.toml (webhook URL, SMTP
    # settings, log_only, enabled, ...). Exposed so alerting.py can read
    # operator TOML config end-to-end instead of requiring a separate
    # ALERT_CONFIG file path (issue #215). Environment variables (HONEY_ALERT_*)
    # still override individual keys in alerting.py.
    ALERTING: dict[str, Any] = field(default_factory=dict)

    # Dashboard (issue #234): read-only stats web view.
    DASHBOARD_ENABLED: bool = False
    DASHBOARD_PORT: int = _DEFAULT_DASHBOARD_PORT
    DASHBOARD_BIND: str = _DEFAULT_DASHBOARD_BIND
    # Auto-generated URL secret (secrets.token_urlsafe). Persisted to config.toml
    # by generate_config_file(); compared with hmac.compare_digest per request.
    # Never a static default — empty/None means "not yet generated".
    DASHBOARD_SECRET: str = ''
    # Default time range for the stats view: '24h', '7d', '30d', or 'all'.
    DASHBOARD_TIME_RANGE: str = _DEFAULT_DASHBOARD_TIME_RANGE

    @staticmethod
    def load(config_path: Path | None = None, validate_secrets: bool = False) -> Config:
        """Build a Config resolving defaults → TOML → env var.

        Args:
            config_path: Optional path to TOML config file. If None, uses XDG discovery.
            validate_secrets: If True, validates that HIVEPASS and DEFAULT_KEY
                are set. Defaults to False so that importing this module (which
                calls ``Config.load()`` at module level) never crashes when
                secrets are absent — ``--generate-config`` must work without
                them. The normal startup path calls ``validate_secrets()``
                explicitly from ``run()`` (issue #177).
        """
        if config_path is None:
            config_path = _find_config_file()

        toml: dict[str, Any] | None = None
        if config_path:
            toml = _load_toml(config_path)

        prefix = env_prefix()

        return Config(
            HONEYPORT=int(
                resolve_setting('honeyport', _DEFAULT_HONEYPORT, 'honeypot', toml, prefix)
            ),  # type: ignore[arg-type]
            HONEYFOLDER=str(
                resolve_setting('honeyfolder', _DEFAULT_HONEYFOLDER, 'honeypot', toml, prefix)
            ),
            HIVEHOST=str(resolve_setting('hivehost', _DEFAULT_HIVEHOST, 'hive', toml, prefix)),  # type: ignore[arg-type]
            HIVEPORT=int(resolve_setting('hiveport', _DEFAULT_HIVEPORT, 'hive', toml, prefix)),  # type: ignore[arg-type]
            HIVELOGIN=str(resolve_setting('hivelogin', _DEFAULT_HIVELOGIN, 'hive', toml, prefix)),  # type: ignore[arg-type]
            HIVEPASS=str(
                resolve_setting('hivepass', _DEFAULT_HIVEPASS or '', 'hive', toml, prefix)
            ),  # type: ignore[arg-type]
            DB_BACKEND=str(
                resolve_setting('backend', _DEFAULT_DB_BACKEND, 'database', toml, prefix)
            ),  # type: ignore[arg-type]
            DB_BACKENDS=tuple(
                resolve_setting('backends', _DEFAULT_DB_BACKENDS, 'database', toml, prefix)  # type: ignore[arg-type]
            ),
            DB_PATH=str(resolve_setting('path', _DEFAULT_DB_PATH, 'database', toml, prefix)),  # type: ignore[arg-type]
            DB_PG_HOST=str(
                resolve_setting('pg_host', _DEFAULT_DB_PG_HOST, 'database', toml, prefix)
            ),  # type: ignore[arg-type]
            DB_PG_PORT=int(
                resolve_setting('pg_port', _DEFAULT_DB_PG_PORT, 'database', toml, prefix)
            ),  # type: ignore[arg-type]
            DB_PG_DB=str(resolve_setting('pg_db', _DEFAULT_DB_PG_DB, 'database', toml, prefix)),  # type: ignore[arg-type]
            DB_PG_USER=str(
                resolve_setting('pg_user', _DEFAULT_DB_PG_USER, 'database', toml, prefix)
            ),  # type: ignore[arg-type]
            DB_PG_PASSWORD=str(
                resolve_setting('pg_password', _DEFAULT_DB_PG_PASSWORD, 'database', toml, prefix)
            ),
            AUTHORIZED_BEES={
                str(k): str(v)
                for k, v in (
                    resolve_setting(
                        'authorized_bees',
                        _DEFAULT_AUTHORIZED_BEES_DEFAULTS,
                        'security',
                        toml,
                        prefix,
                    )
                    or {}
                ).items()  # type: ignore[union-attr]
            },
            HONEY_PORT_MODE=str(resolve_setting('port_mode', 'single', 'honeypot', toml, prefix)),  # type: ignore[arg-type]
            HONEY_TOP_PORTS=str(resolve_setting('top_ports', '', 'honeypot', toml, prefix)),  # type: ignore[arg-type]
            DEFAULT_KEY=str(
                resolve_setting('default_key', _DEFAULT_DEFAULT_KEY or '', 'security', toml, prefix)
            ),
            LOG_FILE=str(resolve_setting('file', _DEFAULT_LOG_FILE, 'logging', toml, prefix)),  # type: ignore[arg-type]
            DUMP_FILE=str(resolve_setting('dump_file', _DEFAULT_DUMP_FILE, 'dump', toml, prefix)),  # type: ignore[arg-type]
            LOCKFILE=str(resolve_setting('lockfile', _DEFAULT_LOCKFILE, 'lockfile', toml, prefix)),  # type: ignore[arg-type]
            # Reconstruct the [alerting] section from the flattened TOML
            # (section.key -> value) so alerting.py can read operator config
            # end-to-end (issue #215).
            ALERTING={
                k.split('.', 1)[1]: v for k, v in (toml or {}).items() if k.startswith('alerting.')
            },
            # Dashboard config (issue #234) — [dashboard] section.
            # NOTE: env_name is set explicitly (HONEY_DASHBOARD_*) because the
            # bare key name 'port' would otherwise collide with HONEY_PORT
            # (e.g. the honeypot's HONEY_PORT_MODE=top would resolve as an int
            # and crash startup with int('top')). Field-named env keys avoid
            # the collision. TOML still uses the [dashboard] section.
            DASHBOARD_ENABLED=bool(
                resolve_setting(
                    'enabled',
                    _DEFAULT_DASHBOARD_ENABLED,
                    'dashboard',
                    toml,
                    prefix,
                    env_name='dashboard_enabled',
                )
            ),
            DASHBOARD_PORT=int(
                resolve_setting(
                    'port',
                    _DEFAULT_DASHBOARD_PORT,
                    'dashboard',
                    toml,
                    prefix,
                    env_name='dashboard_port',
                )
            ),
            DASHBOARD_BIND=str(
                resolve_setting(
                    'bind',
                    _DEFAULT_DASHBOARD_BIND,
                    'dashboard',
                    toml,
                    prefix,
                    env_name='dashboard_bind',
                )
            ),
            DASHBOARD_SECRET=str(
                resolve_setting(
                    'secret',
                    _DEFAULT_DASHBOARD_SECRET or '',
                    'dashboard',
                    toml,
                    prefix,
                    env_name='dashboard_secret',
                )
            ),
            DASHBOARD_TIME_RANGE=str(
                resolve_setting(
                    'time_range',
                    _DEFAULT_DASHBOARD_TIME_RANGE,
                    'dashboard',
                    toml,
                    prefix,
                    env_name='dashboard_time_range',
                )
            ),
        )

    def generate_config_file(self, path: Path | str | None = None) -> Path:
        """Write a config file example at the XDG location and return the path."""
        if path is None:
            # Resolve the default path the same way the loader does. We honor
            # $HOME explicitly (it may be set even where the platform's
            # home-resolution ignores it — e.g. Windows Path.home()/expanduser
            # read USERPROFILE, not HOME), then XDG_CONFIG_HOME, then the
            # platform home. This keeps the location consistent across
            # platforms and makes tests that monkeypatch HOME effective
            # everywhere (issue #266).
            home = os.environ.get('HOME')
            if home:
                base = Path(home)
            else:
                xdg = os.environ.get('XDG_CONFIG_HOME')
                base = Path(xdg) if xdg else Path(os.path.expanduser('~'))
            path = base / '.config' / 'manyfaced' / 'config.toml'
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            '# manyfaced configuration file',
            '# Generated by manyfaced at ' + str(Path(__file__).resolve()),
            '# Edit this file, or use environment variables (prefix HONEY_) to override.',
            '# Environment variables always take precedence over this file.',
            '',
            '[honeypot]',
            f'honeyport = {self.HONEYPORT}',
            f'honeyfolder = "{self.HONEYFOLDER}"',
            '# Port listening mode: "single", "top", or "all"',
            f'port_mode = "{self.HONEY_PORT_MODE}"',
            '# Comma-separated ports for top mode (empty = use defaults)',
            f'top_ports = "{self.HONEY_TOP_PORTS}"',
            '',
            '[hive]',
            f'hivehost = "{self.HIVEHOST}"',
            f'hiveport = {self.HIVEPORT}',
            f'hivelogin = "{self.HIVELOGIN}"',
            f'hivepass = "{self.HIVEPASS}"',
            '',
            '[database]',
            f'backend = "{self.DB_BACKEND}"',
            f'path = "{self.DB_PATH}"',
            f'pg_host = "{self.DB_PG_HOST}"',
            f'pg_port = {self.DB_PG_PORT}',
            f'pg_db = "{self.DB_PG_DB}"',
            f'pg_user = "{self.DB_PG_USER}"',
            f'pg_password = "{self.DB_PG_PASSWORD}"',
            '',
            '[security]',
            '# semicolon-separated bee_id:key pairs for client sensors; e.g. "sensor1:key1;sensor2:key2"',
            'authorized_bees = ""',
            '# Default encryption key for unknown identifiers — MUST be set before starting',
            f'default_key = "{self.DEFAULT_KEY}"',
            '',
            '[logging]',
            '# Path to the JSON log file',
            f'file = "{self.LOG_FILE}"',
            '',
            '[dump]',
            '# Path to the JSONL dump file (fallback for failed DB writes)',
            f'dump_file = "{self.DUMP_FILE}"',
            '',
            '[lockfile]',
            '# Path to the lockfile (prevents multiple instances)',
            f'lockfile = "{self.LOCKFILE}"',
            '',
            '[alerting]',
            '# Alerting / notification config (issue #215). Env vars HONEY_ALERT_* override these.',
            '# log_only = true  -> only log alerts, no external delivery',
            '# enabled = false  -> alerting disabled',
            'log_only = true',
            'enabled = false',
            '# telegram_bot_token = ""',
            '# telegram_chat_id = ""',
            '# smtp_host = "localhost"',
            '# smtp_port = 587',
            '# smtp_user = ""',
            '# smtp_password = ""',
            '# from_email = ""',
            '# to_emails = ""',
            '# webhook_url = ""',
            '',
            '[dashboard]',
            '# Read-only stats web dashboard (issue #234). OFF by default.',
            '# The access secret is auto-generated below (secrets.token_urlsafe) —',
            '# there is no static default. Visit http://<bind>:<port>/?token=<secret>',
            'enabled = false',
            f'port = {self.DASHBOARD_PORT}',
            f'bind = "{self.DASHBOARD_BIND}"',
            '# Auto-generated on first --generate-config; rotate by deleting this line.',
            f'secret = "{self._generated_dashboard_secret()}"',
            f'time_range = "{self.DASHBOARD_TIME_RANGE}"',
            '',
        ]
        path.write_text('\n'.join(lines))
        return path

    def _generated_dashboard_secret(self) -> str:
        """Return a fresh unguessable dashboard secret for config generation.

        Uses secrets.token_urlsafe (cryptographically strong, no static
        fallback) so generated configs never ship with a known default token.
        """
        import secrets

        return secrets.token_urlsafe(32)

    def resolve_ports(self) -> list[int]:
        """Return the list of ports to listen on based on the port mode.

        Returns:
            List of port numbers to bind to.
        """
        mode = self.HONEY_PORT_MODE.lower()

        if mode == 'top':
            # Use custom top ports if provided, otherwise use defaults
            if self.HONEY_TOP_PORTS:
                try:
                    return sorted(
                        {int(p.strip()) for p in self.HONEY_TOP_PORTS.split(',') if p.strip()}
                    )
                except ValueError:
                    # Malformed port list (non-integer entry) — fall back to defaults
                    # rather than crashing startup on a bad config value.
                    pass
            return list(_DEFAULT_TOP_PORTS)
        elif mode == 'all':
            return list(range(1, 65536))
        else:  # single (default)
            return [self.HONEYPORT]


# ── global settings instance ─────────────────────────────────────────────────

settings: Config = Config.load()


class ConfigValidationError(Exception):
    """Raised when required configuration secrets are missing."""

    pass


def validate_secrets(cfg: Config | None = None) -> None:
    """Validate that HIVEPASS and DEFAULT_KEY are set.

    Raises ConfigValidationError if either secret is missing.

    Called explicitly from the normal startup path (``run()``). It is NOT run
    at module import time, so ``--generate-config`` can run without secrets —
    the import that previously executed this unconditionally crashed the tool
    before the CLI flag was ever inspected (issue #177).
    """
    if cfg is None:
        cfg = settings
    errors = []
    if not cfg.HIVEPASS:
        errors.append(
            'HONEY_HIVEPASS is not set and no [hive]hivepass was found in config.toml. '
            'The honeypot cannot start without a secret encryption key. '
            'Set it via the HONEY_HIVEPASS environment variable or in config.toml.'
        )
    if not cfg.DEFAULT_KEY:
        errors.append(
            'security.default_key is not set and no [security]default_key was found in '
            'config.toml. The honeypot cannot start without a default encryption key. '
            'Set it via the HONEY_DEFAULT_KEY environment variable or in config.toml.'
        )

    if errors:
        import logging

        for error in errors:
            logging.getLogger().critical(error)
        raise ConfigValidationError(
            'Missing required secrets:\n' + '\n'.join(f'  - {e}' for e in errors)
        )


# NOTE: secret validation is intentionally NOT run at module import (issue #177).
# ``run()`` calls ``validate_secrets()`` explicitly after handling
# ``--generate-config`` (which must work without secrets).
