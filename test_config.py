#!/usr/bin/env python3
"""Test settings and config system."""

from manyfaced.common.settings import (
    HONEYPORT, HONEYFOLDER, HIVEHOST, HIVEPORT,
    HIVELOGIN, HIVEPASS, DB_BACKEND, DB_PATH,
    AUTHORISEDBEARS
)
from manyfaced.common.config import settings, Config

print("=" * 40)
print("=== settings object ===")
print(f"HONEYPORT = {settings.HONEYPORT}")
print(f"HONEYFOLDER = {settings.HONEYFOLDER}")
print(f"HIVEHOST = {settings.HIVEHOST}")
print(f"HIVEPORT = {settings.HIVEPORT}")
print(f"HIVELOGIN = {settings.HIVELOGIN}")
print(f"HIVEPASS = {settings.HIVEPASS}")
print(f"DB_BACKEND = {settings.DB_BACKEND}")
print(f"DB_PATH = {settings.DB_PATH}")
print(f"AUTHORISEDBEARS = {settings.AUTHORISEDBEARS}")

print()
print("=" * 40)
print("=== module-level compat ===")
print(f"HONEYPORT = {HONEYPORT}")
print(f"HIVEPORT = {HIVEPORT}")
print(f"AUTHORISEDBEARS = {AUTHORISEDBEARS}")

print()
print("=" * 40)
print("=== Config class ===")
print("All imports successful!")
print(f"Config.load() method exists: {hasattr(Config, 'load')}")
print(f"settings type: {type(settings).__name__}")

# Test env var override
import os
os.environ['HONEY_HONEYPORT'] = '9999'
os.environ['HONEY_HIVEPORT'] = '8888'

# Create a fresh Config to test env override
config2 = Config.load()
print()
print("=" * 40)
print("=== Env override test ===")
print(f"HONEYPORT after env set = {config2.HONEYPORT}")
print(f"HIVEPORT after env set = {config2.HIVEPORT}")
if config2.HONEYPORT == 9999 and config2.HIVEPORT == 8888:
    print("ENV OVERRIDE: WORKING!")
else:
    print("ENV OVERRIDE: BROKEN!")
