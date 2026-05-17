"""Configuration resolution logic – TOML + environment variable precedence.

Three-layer precedence (lowest → highest):
  1. Code defaults (hardcoded in config.py)
  2. TOML config file ({XDG_CONFIG_HOME}/manyfaced/config.toml, or ~/.config/manyfaced/config.toml)
  3. Environment variables (HONEY_HONEYPORT, HONEY_HIVEHOST, …)

This module is imported by manyfaced.common.config to keep that module lean.
"""

from __future__ import annotations

import os


def _parse_dict_env(env_val: str) -> dict[str, str]:
    """Parse a semicolon-separated ``key:value`` string into a dict."""
    d: dict[str, str] = {}
    for pair in (env_val or '').split(';'):
        pair = pair.strip()
        if ':' in pair:
            k, v = pair.split(':', 1)
            d[k.strip()] = v.strip()
    return d


def _parse_dict_toml(val) -> dict[str, str]:
    """Parse a TOML string value (semicolon-separated ``key:value``) into a dict."""
    if not isinstance(val, str):
        return val  # already a dict from TOML
    d: dict[str, str] = {}
    for pair in (val or '').split(';'):
        pair = pair.strip()
        if ':' in pair:
            k, v = pair.split(':', 1)
            d[k.strip()] = v.strip()
    return d or {}


def resolve_setting(
    name: str,
    default,
    section: str,
    toml_dict: dict | None,
    env_prefix: str,
):
    """Resolve a single configuration setting with TOML → env var precedence.

    Resolution order (highest priority first):
      1. Environment variable ``{env_prefix}{NAME.upper()}``
      2. TOML key ``{section}.{name}``
      3. Python default value

    Type coercion is applied based on the *default* type:
      - ``int`` → env string is converted via ``int()``
      - ``bool`` → env string checked against ('1', 'true', 'yes')
      - ``dict`` → semicolon-separated ``key:value`` pairs parsed
      - ``list | tuple`` → semicolon-separated values split into a list

    Args:
        name: The setting name (e.g. ``'honeyport'``).
        default: The fallback value if neither TOML nor env provides one.
        section: The TOML section name (e.g. ``'honeypot'``).
        toml_dict: Flat dict of ``section.key → value`` from a loaded TOML file, or None.
        env_prefix: Environment variable prefix (e.g. ``'HONEY_'``).

    Returns:
        The resolved value with appropriate type coercion.
    """
    toml_key = f'{section}.{name}'
    env_key = f'{env_prefix}{name.upper()}'

    # ── 3 – environment variable (highest priority) ────────────────────────
    env_val = os.environ.get(env_key)
    if env_val is not None:
        if isinstance(default, int):
            return int(env_val)
        if isinstance(default, bool):
            return env_val.lower() in ('1', 'true', 'yes')
        if isinstance(default, dict):
            parsed = _parse_dict_env(env_val)
            return parsed or default
        if isinstance(default, (list, tuple)):
            result = [v.strip() for v in env_val.split(';') if v.strip()]
            return result or default
        return env_val

    # ── 2 – TOML config file ───────────────────────────────────────────────
    if toml_dict and toml_key in toml_dict:
        val = toml_dict[toml_key]
        if isinstance(default, int) and isinstance(val, str):
            return int(val)
        if isinstance(default, dict) and isinstance(val, str):
            parsed = _parse_dict_toml(val)
            return parsed or default
        return val

    # ── 1 – code default (lowest priority) ─────────────────────────────────
    return default


def env_prefix() -> str:
    """Return the environment variable prefix used for config overrides."""
    return 'HONEY_'
