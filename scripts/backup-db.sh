#!/usr/bin/env bash
# backup-db.sh — Daily database backup with rotation (backend-aware, issue #243).
#
# Usage: scripts/backup-db.sh [db_path] [retention_count]
#   db_path:        Path to honeypot.sqlite (default: bots/honeypot.sqlite)
#   retention_count: Number of backups to keep (default: 7)
#
# For SQLite it checkpoints WAL then copies the .sqlite file. For PostgreSQL
# (when HONEY_DB_BACKEND=postgresql) it shells out to `pg_dump -Fc` with the
# password passed via the PGPASSWORD env var, and rotates the .dump files.
#
# set -euo pipefail

BACKEND="${HONEY_DB_BACKEND:-sqlite}"

# SQLite: requires a db_path argument.
DB_PATH="${1:-bots/honeypot.sqlite}"
RETENTION="${2:-7}"

if [ "$BACKEND" = "postgresql" ]; then
  echo "[backup-db] PostgreSQL backend: running pg_dump"
  BACKUP_DIR="${HONEY_PG_BACKUP_DIR:-${DB_PATH%/*}/backups}"
  BACKUP_DIR="${BACKUP_DIR:-./backups}"
  mkdir -p "$BACKUP_DIR"
  TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
  BACKUP_FILE="${BACKUP_DIR}/honeypot-${TIMESTAMP}.dump"

  # Build an explicit arg list; password via env, never interpolated.
  PGARGS=(pg_dump -Fc -f "$BACKUP_FILE")
  if [ -n "${HONEY_PG_DSN:-}" ]; then
    PGARGS+=(--dbname "$HONEY_PG_DSN")
    [ -n "${HONEY_PG_SSLMODE:-}" ] && PGARGS+=(--sslmode "$HONEY_PG_SSLMODE")
  else
    PGARGS+=(--host "${HONEY_PG_HOST:-127.0.0.1}" --port "${HONEY_PG_PORT:-5432}")
    PGARGS+=(--username "${HONEY_PG_USER:-postgres}" --dbname "${HONEY_PG_DB:-honeypot}")
    [ -n "${HONEY_PG_SSLMODE:-}" ] && PGARGS+=(--sslmode "$HONEY_PG_SSLMODE")
  fi

  PGPASSWORD="${HONEY_PG_PASSWORD:-postgres}" "${PGARGS[@]}" \
    || { echo "[backup-db] pg_dump failed" >&2; exit 1; }

  echo "[backup-db] Backed up PostgreSQL -> ${BACKUP_FILE}"
  cd "$BACKUP_DIR"
  ls -1t honeypot-*.dump 2>/dev/null | tail -n +"$((RETENTION + 1))" | xargs -r rm -f
  REMAINING=$(ls -1 honeypot-*.dump 2>/dev/null | wc -l)
  echo "[backup-db] Retained ${REMAINING} backup(s)" >&2
  exit 0
fi

# ── SQLite path ─────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$DB_PATH")/backups"
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
