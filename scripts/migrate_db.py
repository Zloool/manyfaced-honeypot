"""SQLite schema migration for manyfaced.

The production database was originally created by an older schema.  When the
code adds a new column (e.g. ``bot_profile_data``) it ships a
``CREATE TABLE IF NOT EXISTS`` statement, which *never* alters an existing
table.  As a result the running DB silently falls out of sync with the code
and every ``INSERT`` fails with
``sqlite3.OperationalError: table honeypot_bears has no column named ...``.

This script reconciles the live table with the code's declared schema by
adding any missing columns.  It is:

* **Idempotent** — safe to run on every deploy; it only adds columns that are
  actually missing.
* **Non-destructive** — it never drops or renames columns, and it runs a WAL
  checkpoint first so no uncommitted transactions are lost.
* **Self-backing** — by default it writes a timestamped ``.bak`` copy of the
  live DB (with WAL sidecars) before altering the schema, so a migration can
  always be reverted.  Pass ``--no-backup`` to skip this.

Usage:
    python scripts/migrate_db.py [--db /path/to/honeypot.sqlite] [--no-backup]

Exit codes:
    0  migration applied successfully (or nothing to do)
    1  unrecoverable error
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import shutil
import sqlite3
import sys

from manyfaced.db.sql_builder import CREATE_TABLE_SQL


def _parse_target_columns(create_sql: str) -> list[str]:
    """Extract the column names declared in a CREATE TABLE statement.

    Handles ``INTEGER PRIMARY KEY AUTOINCREMENT`` and trailing ``UNIQUE(...)``
    constraints without treating them as columns.
    """
    # Grab the section between the first '(' and the matching final ')'.
    start = create_sql.index('(')
    depth = 0
    end = None
    for i in range(start, len(create_sql)):
        if create_sql[i] == '(':
            depth += 1
        elif create_sql[i] == ')':
            depth -= 1
            if depth == 0:
                end = i
                break
    body = create_sql[start + 1 : end]

    columns: list[str] = []
    for line in body.splitlines():
        token = line.strip()
        if not token or token.startswith('UNIQUE') or token.startswith('PRIMARY KEY'):
            continue
        # Column name is the first whitespace-delimited token.
        name = token.split()[0].strip('`"[]')
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
            continue
        columns.append(name)
    return columns


def _backup(db_path: str) -> str | None:
    """Copy the live DB (and WAL sidecars) to a timestamped ``.bak`` beside it.

    SQLite in WAL mode keeps uncommitted data in the ``.sqlite-wal`` /
    ``.sqlite-shm`` sidecars, so a backup must include them — or checkpoint
    first and copy the main file.  We checkpoint into the main file, then copy
    just the main file (plus any residual sidecars for safety) so the backup is
    self-contained.

    Returns the backup path, or None if the source does not exist.
    """
    if not os.path.exists(db_path):
        return None
    stamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    backup_path = f'{db_path}.{stamp}.bak'
    try:
        src = sqlite3.connect(db_path)
        src.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        src.close()
    except sqlite3.Error as exc:
        print(
            f'[migrate] WARNING: pre-backup checkpoint failed ({exc}); copying as-is.',
            file=sys.stderr,
        )
    try:
        shutil.copy2(db_path, backup_path)
        for sidecar in (f'{db_path}-wal', f'{db_path}-shm'):
            if os.path.exists(sidecar):
                shutil.copy2(sidecar, f'{backup_path}{sidecar[len(db_path) :]}')
    except OSError as exc:
        print(
            f'[migrate] WARNING: backup copy failed ({exc}); proceeding without backup.',
            file=sys.stderr,
        )
        return None
    print(f'[migrate] backup written: {backup_path}')
    return backup_path


def migrate(db_path: str, backup: bool = True) -> int:
    if backup:
        _backup(db_path)
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        # Flush any WAL-sidecar transactions before touching the schema.
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')

        target_cols = _parse_target_columns(CREATE_TABLE_SQL)
        cursor = conn.cursor()
        existing = {
            row[1] for row in cursor.execute('PRAGMA table_info(honeypot_bears)').fetchall()
        }

        missing = [c for c in target_cols if c not in existing]
        if not missing:
            print(f'[migrate] schema already up to date ({len(existing)} columns).')
            return 0

        print(f'[migrate] missing columns: {missing}')
        for col in missing:
            cursor.execute(f'ALTER TABLE honeypot_bears ADD COLUMN {col} TEXT')
            print(f'[migrate] added column: {col}')
        conn.commit()
        print('[migrate] migration complete.')
        return 0
    except sqlite3.Error as exc:
        if conn is not None:
            conn.rollback()
        print(f'[migrate] ERROR: {exc}', file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description='Migrate manyfaced SQLite schema.')
    parser.add_argument(
        '--db',
        default='/opt/manyfaced/bots/honeypot.sqlite',
        help='Path to the honeypot SQLite database.',
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip the timestamped .bak copy written before migrating.',
    )
    args = parser.parse_args()
    return migrate(args.db, backup=not args.no_backup)


if __name__ == '__main__':
    raise SystemExit(main())
