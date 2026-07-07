#!/usr/bin/env bash
# cleanup-manyfaced.sh — Kill orphaned manyfaced processes and restart service.
#
# This script should be run as root on the production server.
# It kills all manyfaced python processes (excluding this script and the
# SSH session running it), reconciles the DB schema with the code, then
# restarts the service cleanly.
#
# Use case: After a deploy that changed the DB schema, or when the honeypot
# has accumulated multiple instances (e.g., 8+ processes instead of 3) due
# to crashes or failed restarts.

set -euo pipefail

SELF_PID=$$

echo "=== Manyfaced Process Cleanup ==="
echo

# 1. Kill manyfaced python processes, excluding our own shell/SSH session.
echo "[1/4] Killing manyfaced python processes..."
pkill -9 -f 'manyfaced.mfh' 2>/dev/null || true
sleep 2

REMAINING=$(ps -eo pid,args | grep 'manyfaced.mfh' | grep -v grep | grep -v "$$" | wc -l)
if [ "$REMAINING" -gt 0 ]; then
    echo "  WARNING: $REMAINING processes still running, force killing..."
    ps -eo pid,args | grep 'manyfaced.mfh' | grep -v grep | grep -v "$$" | awk '{print $1}' | xargs -r kill -9 2>/dev/null || true
    sleep 1
fi
echo "  Done. Remaining manyfaced.mfh processes: $(ps -eo pid,args | grep 'manyfaced.mfh' | grep -v grep | grep -v "$$" | wc -l)"
echo

# 2. Clean up lockfile if stale
echo "[2/4] Cleaning up stale lockfile..."
if [ -f /opt/manyfaced/bots/lockfile ]; then
    LOCK_PID=$(cat /opt/manyfaced/bots/lockfile 2>/dev/null || echo "")
    if [ -n "$LOCK_PID" ] && ! kill -0 "$LOCK_PID" 2>/dev/null; then
        rm -f /opt/manyfaced/bots/lockfile
        echo "  Removed stale lockfile (PID $LOCK_PID was not running)"
    else
        echo "  Lockfile exists and PID $LOCK_PID is still running — keeping it"
    fi
else
    echo "  No lockfile found"
fi
echo

# 3. Migrate DB schema BEFORE restart (reconciles columns with the code).
#    Must run while the service is stopped so there is a single DB writer.
echo "[3/4] Migrating database schema (if needed)..."
if [ -x /opt/manyfaced/venv/bin/python3 ] && [ -f /opt/manyfaced/scripts/migrate_db.py ]; then
    /opt/manyfaced/venv/bin/python3 /opt/manyfaced/scripts/migrate_db.py \
        --db /opt/manyfaced/bots/honeypot.sqlite || echo "  WARNING: migration reported an error"
else
    echo "  migrate_db.py not found at /opt/manyfaced/scripts/migrate_db.py — skipping"
fi
echo

# 4. Restart service
echo "[4/4] Restarting manyfaced service..."
systemctl restart manyfaced
sleep 3

# Verify
if systemctl is-active --quiet manyfaced; then
    echo "  Service is running"
    echo "  Processes:"
    ps -eo pid,args | grep 'manyfaced.mfh' | grep -v grep | awk '{print "    " $1 " " $2}'
    echo "  Listening ports (python):"
    ss -tlnp 2>/dev/null | grep -c python3 | xargs -I{} echo "    {} ports"
    echo "  Server (8888) listening:"; ss -tlnp 2>/dev/null | grep -q ':8888' && echo "    yes" || echo "    NO"
else
    echo "  Service failed to start. Check: systemctl status manyfaced"
    echo "  Recent logs:"
    journalctl -u manyfaced --no-pager -n 10
    exit 1
fi

echo
echo "=== Cleanup complete ==="
