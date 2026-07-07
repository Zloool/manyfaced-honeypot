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

Usage:
    python scripts/migrate_db.py [--db /path/to/honeypot.sqlite]

Exit codes:
    0  migration applied successfully (or nothing to do)
    1  unrecoverable error
"""

from __future__ import annotations

import argparse
import re
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


def migrate(db_path: str) -> int:
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
    args = parser.parse_args()
    return migrate(args.db)


if __name__ == '__main__':
    raise SystemExit(main())
