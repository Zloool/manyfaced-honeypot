#!/usr/bin/env bash
# cleanup-manyfaced.sh — Kill orphaned manyfaced processes and restart service.
#
# This script should be run as root on the production server.
# It kills ALL manyfaced processes (not just the systemd-managed ones),
# then restarts the service cleanly.
#
# Use case: When the honeypot has accumulated multiple instances
# (e.g., 8+ processes instead of 3) due to crashes or failed restarts.

set -euo pipefail

echo "=== Manyfaced Process Cleanup ==="
echo

# 1. Kill ALL manyfaced processes
echo "[1/3] Killing all manyfaced processes..."
pkill -9 -f 'python3.*manyfaced' 2>/dev/null || true
sleep 2

# Verify nothing remains
REMAINING=$(ps aux | grep 'manyfaced' | grep -v grep | wc -l)
if [ "$REMAINING" -gt 0 ]; then
    echo "  WARNING: $REMAINING processes still running, force killing..."
    pkill -9 -f 'manyfaced' 2>/dev/null || true
    sleep 1
fi
echo "  Done. Remaining processes: $(ps aux | grep 'manyfaced' | grep -v grep | wc -l)"
echo

# 2. Clean up lockfile if stale
echo "[2/3] Cleaning up stale lockfile..."
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

# 3. Restart service
echo "[3/3] Restarting manyfaced service..."
systemctl restart manyfaced
sleep 3

# Verify
if systemctl is-active --quiet manyfaced; then
    echo "  ✓ Service is running"
    echo "  Processes:"
    ps aux | grep 'manyfaced' | grep -v grep | awk '{print "    " $2 " " $11 " " $12}'
    echo "  Listening ports:"
    ss -tlnp | grep python | wc -l | xargs -I{} echo "    {} ports"
else
    echo "  ✗ Service failed to start. Check: systemctl status manyfaced"
    echo "  Recent logs:"
    journalctl -u manyfaced --no-pager -n 10
    exit 1
fi

echo
echo "=== Cleanup complete ==="
