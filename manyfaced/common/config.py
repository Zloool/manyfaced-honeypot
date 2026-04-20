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

From code (legacy compat, still works):
    from manyfaced.common.settings import HONEYPORT  → still works, delegates to config

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
    authorised_bears = ""  # semicolon-separated "bear_id:key" pairs
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ── defaults (layer 1 – code) ──────────────────────────────────────────────

_DEFAULT_HONEYPORT = 80
_DEFAULT_HONEYFOLDER = "bots"
_DEFAULT_HIVEHOST = "127.0.0.1"
_DEFAULT_HIVEPORT = 8080
_DEFAULT_HIVELOGIN = "honeybee"
_DEFAULT_HIVEPASS = "beehive123"
_DEFAULT_DB_BACKEND = "sqlite"
_DEFAULT_DB_BACKENDS = ("sqlite", "postgresql")
_DEFAULT_DB_PATH = "bots/honeypot.db"
_DEFAULT_DB_PG_HOST = "localhost"
_DEFAULT_DB_PG_PORT = 5432
_DEFAULT_DB_PG_DB = "honeypot"
_DEFAULT_DB_PG_USER = "postgres"
_DEFAULT_DB_PG_PASSWORD = "***"
_DEFAULT_AUTHORISEDBEARS_DEFAULTS: dict[str, str] = {}

# ── config file discovery (XDG base dirs) ──────────────────────────────────

def _find_config_file() -> Path | None:
    """Return the first existing config file, or None if not found anywhere."""
    candidates: list[Path] = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / "manyfaced" / "config.toml")
        candidates.extend([
            Path.home() / ".config" / "manyfaced" / "config.toml",
            Path(__file__).resolve().parent.parent / "settings.toml.example",  # in-package fallback
        ])
    for c in candidates:
        if c.is_file():
            return c
    return None  # will be generated on-demand


def _load_toml(path: Path) -> dict:
    """Load a TOML file and return a flat dict of section.key → value."""
    import tomllib
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    result: dict = {}
    for section, values in raw.items():
        if isinstance(values, dict):
            for key, val in values.items():
                result[f"{section}.{key}"] = val
    return result


def _env_prefix() -> str:
    return "HONEY_"


# ── helpers ─────────────────────────────────────────────────────────────────

def _resolve(name: str, default, section: str, toml: dict | None, env_prefix: str):
    toml_key = f"{section}.{name}"
    env_key = f"{env_prefix}{name.upper()}"

    # 3 – env var
    env_val = os.environ.get(env_key)
    if env_val is not None:
        # Coerce types
        if isinstance(default, int):
            return int(env_val)
        if isinstance(default, bool):
            return env_val.lower() in ("1", "true", "yes")
        if isinstance(default, dict):
            # semicolon-separated key:value pairs
            d: dict = {}
            for pair in (env_val or "").split(";"):
                pair = pair.strip()
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    d[k.strip()] = v.strip()
            return d or default
        if isinstance(default, (list, tuple)):
            return [v.strip() for v in env_val.split(";") if v.strip()] or default
        return env_val

    # 2 – TOML
    if toml and toml_key in toml:
        val = toml[toml_key]
        if isinstance(default, int) and isinstance(val, str):
            return int(val)
        return val

    # 1 – default
    return default


# ── Config singleton (lazy) ─────────────────────────────────────────────────

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
    AUTHORISEDBEARS: dict[str, str]

    @staticmethod
    def load(config_path: Path | None = None) -> Config:
        """Build a Config resolving defaults → TOML → env var."""
        if config_path is None:
            config_path = _find_config_file()

        toml: dict | None = None
        if config_path:
            toml = _load_toml(config_path)

        prefix = _env_prefix()

        return Config(
            HONEYPORT=int(_resolve("honeyport", _DEFAULT_HONEYPORT, "honeypot", toml, prefix)),
            HONEYFOLDER=str(_resolve("honeyfolder", _DEFAULT_HONEYFOLDER, "honeypot", toml, prefix)),
            HIVEHOST=str(_resolve("hivehost", _DEFAULT_HIVEHOST, "hive", toml, prefix)),
            HIVEPORT=int(_resolve("hiveport", _DEFAULT_HIVEPORT, "hive", toml, prefix)),
            HIVELOGIN=str(_resolve("hivelogin", _DEFAULT_HIVELOGIN, "hive", toml, prefix)),
            HIVEPASS=str(_resolve("hivepass", _DEFAULT_HIVEPASS, "hive", toml, prefix)),
            DB_BACKEND=str(_resolve("backend", _DEFAULT_DB_BACKEND, "database", toml, prefix)),
            DB_BACKENDS=tuple(_resolve("backends", _DEFAULT_DB_BACKENDS, "database", toml, prefix)),
            DB_PATH=str(_resolve("path", _DEFAULT_DB_PATH, "database", toml, prefix)),
            DB_PG_HOST=str(_resolve("pg_host", _DEFAULT_DB_PG_HOST, "database", toml, prefix)),
            DB_PG_PORT=int(_resolve("pg_port", _DEFAULT_DB_PG_PORT, "database", toml, prefix)),
            DB_PG_DB=str(_resolve("pg_db", _DEFAULT_DB_PG_DB, "database", toml, prefix)),
            DB_PG_USER=str(_resolve("pg_user", _DEFAULT_DB_PG_USER, "database", toml, prefix)),
            DB_PG_PASSWORD=str(_resolve("pg_password", _DEFAULT_DB_PG_PASSWORD, "database", toml, prefix)),
            AUTHORISEDBEARS=dict(_resolve("authorised_bears", _DEFAULT_AUTHORISEDBEARS_DEFAULTS, "security", toml, prefix)),
        )

    def generate_config_file(self, path: Path | str | None = None) -> Path:
        """Write a config file example at the XDG location and return the path."""
        if path is None:
            path = Path.home() / ".config" / "manyfaced" / "config.toml"
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# manyfaced configuration file",
            "# Generated by manyfaced at " + str(Path(__file__).resolve()),
            "# Edit this file, or use environment variables (prefix HONEY_) to override.",
            "# Environment variables always take precedence over this file.",
            "",
            "[honeypot]",
            f"honeyport = {self.HONEYPORT}",
            f'  honeyfolder = "{self.HONEYFOLDER}"',
            "",
            "[hive]",
            f'  hivehost = "{self.HIVEHOST}"',
            f"  hiveport = {self.HIVEPORT}",
            f'  hivelogin = "{self.HIVELOGIN}"',
            f'  hivepass = "{self.HIVEPASS}"',
            "",
            "[database]",
            f'  backend = "{self.DB_BACKEND}"',
            f'  path = "{self.DB_PATH}"',
            f'  pg_host = "{self.DB_PG_HOST}"',
            f"  pg_port = {self.DB_PG_PORT}",
            f'  pg_db = "{self.DB_PG_DB}"',
            f'  pg_user = "{self.DB_PG_USER}"',
            f'  pg_password = "{self.DB_PG_PASSWORD}"',
            "",
            "[security]",
            '  # semicolon-separated bearid:key pairs; e.g. "bear1:key1;bear2:key2"',
            '  authorised_bears = ""',
            "",
        ]
        path.write_text("\n".join(lines))
        return path


# ── global settings instance ─────────────────────────────────────────────────

settings: Config = Config.load()

# ── backward-compat module-level aliases ─────────────────────────────────────
# These let old code ``from manyfaced.common.settings import HONEYPORT`` still work.

HONEYPORT = settings.HONEYPORT
HONEYFOLDER = settings.HONEYFOLDER
HIVEHOST = settings.HIVEHOST
HIVEPORT = settings.HIVEPORT
HIVELOGIN = settings.HIVELOGIN
HIVEPASS = settings.HIVEPASS
DB_BACKEND = settings.DB_BACKEND
DB_BACKENDS = settings.DB_BACKENDS
DB_PATH = settings.DB_PATH
DB_PG_HOST = settings.DB_PG_HOST
DB_PG_PORT = settings.DB_PG_PORT
DB_PG_DB = settings.DB_PG_DB
DB_PG_USER = settings.DB_PG_USER
DB_PG_PASSWORD = settings.DB_PG_PASSWORD
AUTHORISEDBEARS = settings.AUTHORISEDBEARS
