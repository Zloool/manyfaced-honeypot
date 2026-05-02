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
    authorised_bears = ""  # semicolon-separated "bear_id:key" pairs

    [ai]
    enabled = false
    endpoint = "http://127.0.0.1:8080/v1"
    model = "llama-3.1-8b-instruct"
    max_tokens = 500
    timeout = 5.0
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


# ── defaults (layer 1 – code) ──────────────────────────────────────────────

_DEFAULT_HONEYPORT = 80
_DEFAULT_HONEYFOLDER = "bots"
_DEFAULT_HIVEHOST = "127.0.0.1"
_DEFAULT_HIVEPORT = 8080
_DEFAULT_HIVELOGIN = "honeybee"
_DEFAULT_HIVEPASS = None
_DEFAULT_DB_BACKEND = "sqlite"
_DEFAULT_DB_BACKENDS = ("sqlite", "postgresql")
_DEFAULT_DB_PATH = "bots/honeypot.db"
_DEFAULT_DB_PG_HOST = "localhost"
_DEFAULT_DB_PG_PORT = 5432
_DEFAULT_DB_PG_DB = "honeypot"
_DEFAULT_DB_PG_USER = "postgres"
_DEFAULT_DB_PG_PASSWORD = "***"
_DEFAULT_AUTHORISEDBEARS_DEFAULTS: dict[str, str] = {}

# ── port mode configuration ─────────────────────────────────────────────────
# Port modes for CLIENT honeypot:
#   "single"  – listen on a single port (HONEYPORT, default 80)
#   "top"     – listen on the top 50 most popular/scanned ports
#   "all"     – listen on all 65535 TCP ports

_TOP_50_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    5901,
    6379,
    8080,
    8443,
    9200,
    11211,
    27017,
    5672,
    15672,
    4369,
    2181,
    9090,
    8888,
    7001,
    7002,
    11300,
    11301,
    11302,
    11303,
    11304,
    11305,
    11306,
    11307,
    11308,
    11309,
    11310,
    11311,
    5000,
]

_PORT_MODES = ("single", "top", "all")

# ── AI responder configuration ──────────────────────────────────────────────
# AI responder provides LLM-powered, interactive HTTP responses to probe bots.
# Disabled by default (AI_ENABLED=false).

_DEFAULT_AI_ENABLED = False
_DEFAULT_AI_ENDPOINT = "http://127.0.0.1:8080/v1"
_DEFAULT_AI_MODEL = "llama-3.1-8b-instruct"
_DEFAULT_AI_MAX_TOKENS = 500
_DEFAULT_AI_TIMEOUT = 5.0
_DEFAULT_DEFAULT_KEY = None
_DEFAULT_LOG_FILE = os.path.join(
    os.path.expanduser("~"), ".local", "share", "manyfaced", "honeypot.log"
)
_DEFAULT_DUMP_FILE = "/var/lib/manyfaced/dump.jsonl"
_DEFAULT_LOCKFILE = os.path.join(
    os.environ.get("XDG_RUNTIME_DIR", "/run"), "manyfaced", "lockfile"
)

# ── config file discovery (XDG base dirs) ──────────────────────────────────


def _find_config_file() -> Path | None:
    """Return the first existing config file, or None if not found anywhere."""
    candidates: list[Path] = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / "manyfaced" / "config.toml")
    # Always check fallback paths (XDG is optional)
    candidates.extend(
        [
            Path.home() / ".config" / "manyfaced" / "config.toml",
            Path(__file__).resolve().parent.parent
            / "settings.toml.example",  # in-package fallback
        ]
    )
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
        if isinstance(default, dict) and isinstance(val, str):
            # semicolon-separated key:value pairs (same as env var handling)
            d: dict = {}
            for pair in (val or "").split(";"):
                pair = pair.strip()
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    d[k.strip()] = v.strip()
            return d or default
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

    # Port mode configuration
    HONEY_PORT_MODE: str  # "single", "top", or "all"
    HONEY_TOP_PORTS: (
        str  # comma-separated port list (used when mode="top" and user customizes)
    )

    # AI responder configuration
    AI_ENABLED: bool  # enable AI-powered response generation
    AI_ENDPOINT: str  # LLM API endpoint (OpenAI-compatible)
    AI_MODEL: str  # LLM model name
    AI_MAX_TOKENS: int  # maximum tokens in generated response
    AI_TIMEOUT: float  # request timeout in seconds

    # Security
    DEFAULT_KEY: str  # default encryption key for unknown identifiers

    # Logging
    LOG_FILE: str  # path to the JSON log file

    # Dump file (fallback for failed DB writes)
    DUMP_FILE: str  # path to the JSONL dump file

    # Lockfile (prevents multiple instances)
    LOCKFILE: str  # path to the lockfile for instance management

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
            HONEYPORT=int(
                _resolve("honeyport", _DEFAULT_HONEYPORT, "honeypot", toml, prefix)
            ),
            HONEYFOLDER=str(
                _resolve("honeyfolder", _DEFAULT_HONEYFOLDER, "honeypot", toml, prefix)
            ),
            HIVEHOST=str(_resolve("hivehost", _DEFAULT_HIVEHOST, "hive", toml, prefix)),
            HIVEPORT=int(_resolve("hiveport", _DEFAULT_HIVEPORT, "hive", toml, prefix)),
            HIVELOGIN=str(
                _resolve("hivelogin", _DEFAULT_HIVELOGIN, "hive", toml, prefix)
            ),
            HIVEPASS=str(_resolve("hivepass", _DEFAULT_HIVEPASS, "hive", toml, prefix)),
            DB_BACKEND=str(
                _resolve("backend", _DEFAULT_DB_BACKEND, "database", toml, prefix)
            ),
            DB_BACKENDS=tuple(
                _resolve("backends", _DEFAULT_DB_BACKENDS, "database", toml, prefix)
            ),
            DB_PATH=str(_resolve("path", _DEFAULT_DB_PATH, "database", toml, prefix)),
            DB_PG_HOST=str(
                _resolve("pg_host", _DEFAULT_DB_PG_HOST, "database", toml, prefix)
            ),
            DB_PG_PORT=int(
                _resolve("pg_port", _DEFAULT_DB_PG_PORT, "database", toml, prefix)
            ),
            DB_PG_DB=str(
                _resolve("pg_db", _DEFAULT_DB_PG_DB, "database", toml, prefix)
            ),
            DB_PG_USER=str(
                _resolve("pg_user", _DEFAULT_DB_PG_USER, "database", toml, prefix)
            ),
            DB_PG_PASSWORD=str(
                _resolve(
                    "pg_password", _DEFAULT_DB_PG_PASSWORD, "database", toml, prefix
                )
            ),
            AUTHORISEDBEARS=dict(
                _resolve(
                    "authorised_bears",
                    _DEFAULT_AUTHORISEDBEARS_DEFAULTS,
                    "security",
                    toml,
                    prefix,
                )
            ),
            HONEY_PORT_MODE=str(
                _resolve("port_mode", "single", "honeypot", toml, prefix)
            ),
            HONEY_TOP_PORTS=str(_resolve("top_ports", "", "honeypot", toml, prefix)),
            AI_ENABLED=bool(
                _resolve("ai_enabled", _DEFAULT_AI_ENABLED, "ai", toml, prefix)
            ),
            AI_ENDPOINT=str(
                _resolve("ai_endpoint", _DEFAULT_AI_ENDPOINT, "ai", toml, prefix)
            ),
            AI_MODEL=str(_resolve("ai_model", _DEFAULT_AI_MODEL, "ai", toml, prefix)),
            AI_MAX_TOKENS=int(
                _resolve("ai_max_tokens", _DEFAULT_AI_MAX_TOKENS, "ai", toml, prefix)
            ),
            AI_TIMEOUT=float(
                _resolve("ai_timeout", _DEFAULT_AI_TIMEOUT, "ai", toml, prefix)
            ),
            DEFAULT_KEY=str(
                _resolve("default_key", _DEFAULT_DEFAULT_KEY, "security", toml, prefix)
            ),
            LOG_FILE=str(_resolve("file", _DEFAULT_LOG_FILE, "logging", toml, prefix)),
            DUMP_FILE=str(
                _resolve("dump_file", _DEFAULT_DUMP_FILE, "dump", toml, prefix)
            ),
            LOCKFILE=str(
                _resolve("lockfile", _DEFAULT_LOCKFILE, "lockfile", toml, prefix)
            ),
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
            f'honeyfolder = "{self.HONEYFOLDER}"',
            '# Port listening mode: "single", "top", or "all"',
            f'port_mode = "{self.HONEY_PORT_MODE}"',
            "# Comma-separated ports for top mode (empty = use defaults)",
            f'top_ports = "{self.HONEY_TOP_PORTS}"',
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
            "[ai]",
            "  # AI responder for interactive bot engagement",
            f"  enabled = {self.AI_ENABLED}",
            f'  endpoint = "{self.AI_ENDPOINT}"',
            f'  model = "{self.AI_MODEL}"',
            f"  max_tokens = {self.AI_MAX_TOKENS}",
            f"  timeout = {self.AI_TIMEOUT}",
            "",
            "[logging]",
            "  # Path to the JSON log file",
            f'  file = "{self.LOG_FILE}"',
            "",
            "[dump]",
            "  # Path to the JSONL dump file (fallback for failed DB writes)",
            f'  dump_file = "{self.DUMP_FILE}"',
            "",
            "[lockfile]",
            "  # Path to the lockfile (prevents multiple instances)",
            f'  lockfile = "{self.LOCKFILE}"',
            "",
        ]
        path.write_text("\n".join(lines))
        return path

    def resolve_ports(self) -> list[int]:
        """Return the list of ports to listen on based on the port mode.

        Returns:
            List of port numbers to bind to.
        """
        mode = self.HONEY_PORT_MODE.lower()

        if mode == "top":
            # Use custom top ports if provided, otherwise use defaults
            if self.HONEY_TOP_PORTS:
                try:
                    return sorted(
                        {
                            int(p.strip())
                            for p in self.HONEY_TOP_PORTS.split(",")
                            if p.strip()
                        }
                    )
                except ValueError:
                    pass
            return list(_TOP_50_PORTS)
        elif mode == "all":
            return list(range(1, 65536))
        else:  # single (default)
            return [self.HONEYPORT]


# ── global settings instance ─────────────────────────────────────────────────

settings: Config = Config.load()

# ── Validate required secrets ────────────────────────────────────────────────
# HIVEPASS and DEFAULT_KEY must be explicitly configured.
# Shipping a default secret is a security risk — anyone who reads the README
# can encrypt forged reports and submit them under any identifier.
if not settings.HIVEPASS:
    import logging

    logging.getLogger().critical(
        "HONEY_HIVEPASS is not set and no [hive]hivepass was found in config.toml. "
        "The honeypot cannot start without a secret encryption key. "
        "Set it via the HONEY_HIVEPASS environment variable or in config.toml."
    )
    raise SystemExit(1)

if not settings.DEFAULT_KEY:
    import logging

    logging.getLogger().critical(
        "security.default_key is not set and no [security]default_key was found in "
        "config.toml. The honeypot cannot start without a default encryption key. "
        "Set it via the HONEY_DEFAULT_KEY environment variable or in config.toml."
    )
    raise SystemExit(1)
