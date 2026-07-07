#!/usr/bin/env bash
# verify_deploy.sh — post-deploy verification that recording actually works.
#
# The port-only health check in the deploy workflow can pass while the
# honeypot writes nothing (schema drift, swallowed insert errors, broken
# report path). This script closes that gap (#165 / #168):
#   1. Reconcile the SQLite schema with the code (idempotent migration).
#   2. Push a synthetic bot request through the honeyport and assert a row
#      lands in the DB.
#
# Usage (run on the droplet as the deploy user):
#   bash /opt/manyfaced/scripts/verify_deploy.sh
#
# Exits non-zero if recording is broken, so the workflow can roll back.

set -euo pipefail

CURRENT_TARGET="$(readlink -f /opt/manyfaced/current)"
echo "Current release: ${CURRENT_TARGET}"

# 1. Reconcile schema (adds any columns missing vs CREATE_TABLE_SQL).
# Prefer the script shipped with the active release; fall back to the
# canonical /opt/manyfaced/scripts copy so older releases still reconcile.
MIGRATE="${CURRENT_TARGET}/scripts/migrate_db.py"
if [ ! -f "${MIGRATE}" ]; then
    MIGRATE="/opt/manyfaced/scripts/migrate_db.py"
fi
/opt/manyfaced/venv/bin/python3 "${MIGRATE}" \
    --db /opt/manyfaced/bots/honeypot.sqlite

# 2. Verify an actual write lands.
set -a
. /opt/manyfaced/honeypot.env
set +a

/opt/manyfaced/venv/bin/python3 - <<'PY'
import os, socket, sqlite3, time

DB = '/opt/manyfaced/bots/honeypot.sqlite'


def newest():
    return sqlite3.connect(DB).execute(
        'SELECT MAX(timestamp) FROM honeypot_bears'
    ).fetchone()[0]


before = newest()

s = socket.socket()
s.settimeout(5)
s.connect(('127.0.0.1', int(os.environ.get('HONEY_HONEYPORT', '8080'))))
s.sendall(b'GET /deploy-health-check HTTP/1.1\r\nHost: ci\r\n\r\n')
try:
    s.recv(4096)
except Exception:
    pass
s.close()

time.sleep(4)
after = newest()

if after == before:
    raise SystemExit('DB write verification FAILED: no row recorded after deploy')

print(f'DB write verification OK: {after}')
PY

echo "verify_deploy: recording confirmed working"
