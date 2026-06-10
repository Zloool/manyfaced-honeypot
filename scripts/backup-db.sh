#!/usr/bin/env bash
# backup-db.sh — Daily SQLite database backup with rotation
# Usage: scripts/backup-db.sh [db_path] [retention_count]
#   db_path:        Path to honeypot.sqlite (default: bots/honeypot.sqlite)
#   retention_count: Number of backups to keep (default: 7)

set -euo pipefail

DB_PATH="${1:-bots/honeypot.sqlite}"
RETENTION="${2:-7}"
BACKUP_DIR="$(dirname "$DB_PATH")/backups"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/honeypot-${TIMESTAMP}.sqlite"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Check source DB exists
if [ ! -f "$DB_PATH" ]; then
    echo "[backup-db] No database found at ${DB_PATH}, skipping." >&2
    exit 0
fi

# Verify the DB is readable (quick integrity check)
if ! sqlite3 "$DB_PATH" "PRAGMA integrity_check;" >/dev/null 2>&1; then
    echo "[backup-db] Database integrity check failed, skipping backup." >&2
    exit 1
fi

# Perform backup using SQLite's native .backup command for consistency
sqlite3 "$DB_PATH" ".backup '${BACKUP_FILE}'"

echo "[backup-db] Backed up ${DB_PATH} -> ${BACKUP_FILE}"

# Rotate old backups (keep only RETENTION most recent)
cd "$BACKUP_DIR"
ls -1t honeypot-*.sqlite 2>/dev/null | tail -n +"$((RETENTION + 1))" | xargs -r rm -f

REMAINING=$(ls -1 honeypot-*.sqlite 2>/dev/null | wc -l)
echo "[backup-db] Retained ${REMAINING} backup(s)" >&2
