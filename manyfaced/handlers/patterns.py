"""Pattern detection constants for BotProfile.

This module contains pattern lists used by BotProfile._analyze_request() to detect
SQL injection, LFI/RFI, RCE, enumeration, and scanner/tool signatures.
Imported by bot_profile.py (which re-exports them for backward compat).
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Pattern detection constants (module-level lists)
# ---------------------------------------------------------------------------

SQLI_PATTERNS: list[str] = [
    'union',
    'select',
    'drop',
    'insert',
    'delete',
    'update',
    'or 1=1',
    'and 1=1',
    'sleep(',
    'benchmark(',
    'or+1=1',
    'and+1=1',
    "admin'--",
    '1=1--',
]

LFI_PATTERNS: list[str] = [
    '../',
    '..\\',
    '/etc/passwd',
    '/etc/shadow',
    'php://',
    'expect://',
    'data://',
]

RCE_PATTERNS: list[str] = [
    '; ls',
    '| cat',
    '&& wget',
    '$(curl',
    '`nc`',
    'eval(',
    'exec(',
    '| cat ',
    '; cat ',
    '&& cat ',
    'cat /etc',
    'wget http',
    'curl http',
]

ENUM_PATHS: list[str] = [
    '/admin',
    '/wp-admin',
    '/phpmyadmin',
    '/server-status',
    '/.git',
    '/.env',
    '/config',
    '/backup',
    '/manager',
]

SCANNER_KEYWORDS: list[str] = [
    'nikto',
    'sqlmap',
    'nmap',
    'dirbuster',
    'gobuster',
    'wfuzz',
    'burp',
    'hydra',
    'medusa',
    'masscan',
]

TOOL_KEYWORDS: list[str] = [
    'python-requests',
    'curl',
    'wget',
    'java',
    'go-http',
]
