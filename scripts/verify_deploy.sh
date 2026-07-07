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

CURRENT_TARGET="$(readlink -f /opt/manyfaced/current 2>/dev/null || echo /opt/manyfaced/releases/current)"
VENV="${CURRENT_TARGET}/venv/bin/python3"
[ -x "$VENV" ] || VENV="/opt/manyfaced/venv/bin/python3"

# 1) Reconcile schema (non-destructive; only adds missing columns).
echo "== Reconciling schema =="
"$VENV" "${CURRENT_TARGET}/scripts/migrate_db.py"

# 2) Prove a write lands through the real storage path.
echo "== Verifying a record can be written =="
"$VENV" - <<'PY'
import sqlite3
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
try:
    storage.insert(rec)
    # Verify it persisted by reading back through the same connection/file.
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
except Exception as e:  # noqa: BLE001
    print(f"ERROR: write verification failed: {e!r}")
    raise SystemExit(1)
PY

echo "== Deploy verification PASSED =="
