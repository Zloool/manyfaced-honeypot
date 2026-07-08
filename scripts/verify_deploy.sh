#!/usr/bin/env bash
# verify_deploy.sh — post-deploy verification that recording actually works.
#
# The port-only health check (deploy.yml) only proves the sockets listen; it
# does NOT prove DB writes succeed. This caught the 2026-07 silent-stop: schema
# drift made inserts fail while ports stayed green. So after a deploy we
# (1) reconcile the live schema to the code's expected schema, and (2) prove a
# row can actually be written through the real storage path (the exact path a
# captured bot report uses), not just a synthetic client request (the honeypot
# client deliberately drops internal/loopback source IPs, so a loopback request
# is never recorded).
#
# Exits 0 if recording is healthy, 1 if not. Run on the droplet as root.

set -euo pipefail

# Source the deployment env so DB_PATH/keys resolve exactly as the running service does.
if [ -f /opt/manyfaced/honeypot.env ]; then
  set -a; . /opt/manyfaced/honeypot.env; set +a
fi

# 0) Guard: the resolved DB path MUST be absolute. A relative path under the
# systemd CWD (the orphaned `current` symlink) would split recording onto a
# deploy-orphaned file while operators inspect the real DB — the 2026-07
# silent-stop (issue #188). The code rewrites relative->absolute defensively,
# but a deploy onto a misconfigured droplet must FAIL here rather than ship
# silent data loss.
#
# This absolute-path concept is SQLite-only; for PostgreSQL there is no file
# path, so skip the guard when HONEY_DB_BACKEND=postgresql (issue #243 #7).
echo "== Verifying DB path is absolute =="
BACKEND="${HONEY_DB_BACKEND:-sqlite}"
if [ "$BACKEND" = "postgresql" ]; then
  echo "OK: backend is postgresql (no file path to validate)"
else
  "$VENV" - <<'PY'
from manyfaced.db.storage import validate_db_path_absolute

if not validate_db_path_absolute():
    print("ERROR: configured DB path is NOT absolute (relative to CWD).")
    print("A relative HONEY_DB_PATH/database.path under the systemd CWD (the")
    print("orphaned 'current' symlink) splits recording onto a deploy-orphaned")
    print("file while operators inspect the real DB (issue #188). Set it to an")
    print("absolute, long-lived path such as /opt/manyfaced/bots/honeypot.sqlite.")
    raise SystemExit(1)
print("OK: DB path is absolute")
PY
fi

CURRENT_TARGET="$(readlink -f /opt/manyfaced/current 2>/dev/null || echo /opt/manyfaced/releases/current)"
VENV="${CURRENT_TARGET}/venv/bin/python3"
[ -x "$VENV" ] || VENV="/opt/manyfaced/venv/bin/python3"

# 1) Reconcile schema (non-destructive; only adds missing columns).
echo "== Reconciling schema =="
"$VENV" "${CURRENT_TARGET}/scripts/migrate_db.py"

# 2) Prove a write lands through the real storage path.
echo "== Verifying a record can be written =="
"$VENV" - <<'PY'
import datetime
from manyfaced.db.storage import get_storage

storage = get_storage()
rec = {
    'ip': '127.0.0.1',
    'raw_request': 'GET /deploy-health-check HTTP/1.1\r\nHost: verify\r\n\r\n',
    'timestamp': datetime.datetime.utcnow().isoformat(sep=' '),
    'parsed_request': {'command': 'GET', 'path': '/deploy-health-check'},
    'is_detected': 0,
    'HIVELOGIN': '',
}
backend_name = type(storage).__name__
try:
    storage.insert(rec)
    if backend_name == 'SQLiteStorage':
        # Verify it persisted by reading back through the same connection/file.
        import sqlite3
        conn = sqlite3.connect(storage._db_path)
        n = conn.execute(
            "SELECT COUNT(*) FROM honeypot_bears WHERE request_path='/deploy-health-check'"
        ).fetchone()[0]
        if n < 1:
            print("ERROR: write did not persist (0 rows found)")
            raise SystemExit(1)
        # Remove the probe row so it doesn't pollute real data.
        conn.execute("DELETE FROM honeypot_bears WHERE request_path='/deploy-health-check'")
        conn.commit()
        conn.close()
        print(f"OK: write landed and persisted ({n} probe row verified, then removed)")
    elif backend_name == 'PostgreSQLStorage':
        # Read back + delete via an independent raw psycopg2 connection using the
        # same HONEY_PG_* env the service uses (mirrors the SQLite branch's
        # independent read-back through a fresh connect) — issue #243 #7.
        import os
        import psycopg2  # requires psycopg2-binary (installed via [postgres] extra)
        dsn = os.environ.get('HONEY_PG_DSN')
        kwargs = {'sslmode': os.environ.get('HONEY_PG_SSLMODE', 'prefer')}
        if dsn:
            conn = psycopg2.connect(dsn=dsn, **kwargs)
        else:
            conn = psycopg2.connect(
                host=os.environ.get('HONEY_PG_HOST', '127.0.0.1'),
                port=int(os.environ.get('HONEY_PG_PORT', '5432')),
                database=os.environ.get('HONEY_PG_DB', 'honeypot'),
                user=os.environ.get('HONEY_PG_USER', 'postgres'),
                password=os.environ.get('HONEY_PG_PASSWORD', 'postgres'),
                **kwargs,
            )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM honeypot_bears WHERE request_path='/deploy-health-check'"
            )
            n = cur.fetchone()[0]
            if n < 1:
                print("ERROR: write did not persist (0 rows found)")
                conn.close()
                raise SystemExit(1)
            cur.execute("DELETE FROM honeypot_bears WHERE request_path='/deploy-health-check'")
            conn.commit()
        conn.close()
        print(f"OK: write landed and persisted ({n} probe row verified, then removed)")
    else:
        print(f"ERROR: unknown storage backend {backend_name}")
        raise SystemExit(1)
except Exception as e:  # noqa: BLE001
    print(f"ERROR: write verification failed: {e!r}")
    raise SystemExit(1)
PY

echo "== Deploy verification PASSED =="
