"""Configuration resolution logic – TOML + environment variable precedence.

Three-layer precedence (lowest → highest):
  1. Code defaults (hardcoded in config.py)
  2. TOML config file ({XDG_CONFIG_HOME}/manyfaced/config.toml, or ~/.config/manyfaced/config.toml)
  3. Environment variables (HONEY_HONEYPORT, HONEY_HIVEHOST, …)

This module is imported by manyfaced.common.config to keep that module lean.
"""

from __future__ import annotations

import os
from typing import Any


def _parse_dict_env(env_val: str) -> dict[str, str]:
    """Parse a semicolon-separated ``key:value`` string into a dict."""
    d: dict[str, str] = {}
    for pair in (env_val or '').split(';'):
        pair = pair.strip()
        if ':' in pair:
            k, v = pair.split(':', 1)
            d[k.strip()] = v.strip()
    return d


def _parse_dict_toml(val: Any) -> dict[str, str] | Any:
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
    default: Any,
    section: str,
    toml_dict: dict[str, Any] | None,
    env_prefix: str,
    env_name: str | None = None,
) -> Any:
    """Resolve a single configuration setting with TOML → env var precedence.

    Resolution order (highest priority first):
      1. Environment variable ``{env_prefix}{ENV_NAME.upper()}``
      2. TOML key ``{section}.{name}``
      3. Python default value

    Type coercion is applied based on the *default* type:
      - ``int`` → env string is converted via ``int()``
      - ``bool`` → env string checked against ('1', 'true', 'yes')
      - ``dict`` → semicolon-separated ``key:value`` pairs parsed
      - ``list | tuple`` → semicolon-separated values split into a list

    Args:
        name: The TOML setting name (e.g. ``'honeyport'``) — used for the
            ``{section}.{name}`` TOML lookup.
        default: The fallback value if neither TOML nor env provides one.
        section: The TOML section name (e.g. ``'honeypot'``).
        toml_dict: Flat dict of ``section.key → value`` from a loaded TOML file, or None.
        env_prefix: Environment variable prefix (e.g. ``'HONEY_'``).
        env_name: Optional explicit env var *suffix* (without prefix). When
            given, the env var is ``{env_prefix}{ENV_NAME.upper()}`` instead of
            ``{env_prefix}{name.upper()}``. This is required when two sections
            share a bare key name (e.g. ``honeypot.port`` vs ``dashboard.port``
            would both otherwise map to ``HONEY_PORT`` and collide). For the
            dashboard the field is named ``DASHBOARD_PORT``, so ``env_name`` is
            ``'dashboard_port'`` → ``HONEY_DASHBOARD_PORT``. Defaults to ``name``
            to preserve the historical ``HONEY_<FIELD>`` convention.

    Returns:
        The resolved value with appropriate type coercion.
    """
    import logging

    toml_key = f'{section}.{name}'
    env_key = f'{env_prefix}{(env_name or name).upper()}'

    # ── 3 – environment variable (highest priority) ────────────────────────
    env_val = os.environ.get(env_key)
    if env_val is not None:
        # NOTE: bool is a subclass of int in Python, so the bool check MUST
        # come before the int check — otherwise `int('true')` raises and the
        # bool branch is never reached.
        if isinstance(default, bool):
            return env_val.lower() in ('1', 'true', 'yes')
        if isinstance(default, int):
            try:
                return int(env_val)
            except (TypeError, ValueError):
                logging.getLogger(__name__).warning(
                    'Env var %s=%r is not a valid int; ignoring and using default %r',
                    env_key,
                    env_val,
                    default,
                )
                return default
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
            try:
                return int(val)
            except ValueError:
                logging.getLogger(__name__).warning(
                    'TOML key %s=%r is not a valid int; ignoring and using default %r',
                    toml_key,
                    val,
                    default,
                )
                return default
        if isinstance(default, dict) and isinstance(val, str):
            parsed = _parse_dict_toml(val)
            return parsed or default
        return val

    # ── 1 – code default (lowest priority) ─────────────────────────────────
    return default


def env_prefix() -> str:
    """Return the environment variable prefix used for config overrides."""
    return 'HONEY_'
