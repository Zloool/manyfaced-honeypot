#!/usr/bin/env bash
# backup-db.sh — Daily database backup for manyfaced honeypot
#
# Usage:
#   # Add to crontab (run as honeypot user):
#   0 3 * * * /opt/manyfaced/scripts/backup-db.sh
#
# Or manually:
#   sudo -u honeypot /opt/manyfaced/scripts/backup-db.sh

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR:-/opt/manyfaced/bots}"
DB_PATH="${DB_PATH:-/opt/manyfaced/bots/honeypot.sqlite}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/honeypot.sqlite.${TIMESTAMP}"

# ── Functions ─────────────────────────────────────────────────────────────────
log()    { echo "[backup-db] $(date '+%Y-%m-%d %H:%M:%S') $*"; }
warn()   { echo "[backup-db] $(date '+%Y-%m-%d %H:%M:%S') WARNING: $*"; }
err()    { echo "[backup-db] $(date '+%Y-%m-%d %H:%M:%S') ERROR: $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
[[ -f "$DB_PATH" ]] || err "Database not found at $DB_PATH"
[[ -d "$BACKUP_DIR" ]] || err "Backup directory not found at $BACKUP_DIR"

# ── Backup ────────────────────────────────────────────────────────────────────
log "Backing up $DB_PATH → $BACKUP_FILE"

# Use sqlite3's backup mode for consistency (no lock issues)
if command -v sqlite3 &>/dev/null; then
    sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"
else
    # Fallback: cp with fsync
    cp "$DB_PATH" "$BACKUP_FILE"
    sync
fi

# Compress the backup
log "Compressing..."
gzip "$BACKUP_FILE"
BACKUP_FILE="${BACKUP_FILE}.gz"

# Verify the backup
if [[ -f "$BACKUP_FILE" ]]; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log "Backup saved: $BACKUP_FILE ($SIZE)"
else
    err "Backup failed!"
fi

# ── Cleanup old backups ──────────────────────────────────────────────────────
log "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "honeypot.sqlite.*.gz" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
log "Cleanup complete."
