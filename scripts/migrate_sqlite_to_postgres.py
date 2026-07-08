#!/usr/bin/env python3
"""One-off ETL: copy honeypot_bears rows from SQLite into PostgreSQL.

This is a *one-time* migration tool, not a recurring migrator. It reads rows
from the SQLite ``honeypot_bears`` table in batches (keyset pagination on ``id``)
and inserts them via :class:`~manyfaced.db.storage.PostgreSQLStorage`, which
reuses the existing ``ON CONFLICT(bot_ip, timestamp) DO NOTHING`` dedup — so the
copy is safely re-runnable / resumable after an interruption.

Run BEFORE flipping ``HONEY_DB_BACKEND=postgresql`` in production (and while the
service is stopped, so no writes split across the two DBs). See issue #243 for
the full migration runbook.

Usage:
    python scripts/migrate_sqlite_to_postgres.py \
        [--sqlite /opt/manyfaced/bots/honeypot.sqlite] \
        [--batch 1000] [--limit N]

Environment:
    HONEY_PG_HOST / HONEY_PG_PORT / HONEY_PG_DB / HONEY_PG_USER /
    HONEY_PG_PASSWORD (or a HONEY_PG_DSN) must point at the target Postgres.

Exit codes:
    0  migration completed (or nothing to do)
    1  unrecoverable error
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys

# Allow running as a standalone script from the repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from manyfaced.db.storage import PostgreSQLStorage  # noqa: E402


def _connect_sqlite(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def migrate(sqlite_path: str, batch_size: int = 1000, limit: int | None = None) -> int:
    """Copy rows from SQLite to PostgreSQL. Returns the number of rows copied."""
    if not os.path.exists(sqlite_path):
        print(f'[etl] SQLite DB not found at {sqlite_path}; nothing to do.', file=sys.stderr)
        return 0

    src = _connect_sqlite(sqlite_path)
    try:
        # Detect the id column; older/edge schemas may not have one.
        cols = {r[1] for r in src.execute('PRAGMA table_info(honeypot_bears)').fetchall()}
        has_id = 'id' in cols
        if not has_id:
            print(
                '[etl] WARNING: honeypot_bears has no `id` column; '
                'falling back to a single unbounded read (not resumable).',
                file=sys.stderr,
            )
    finally:
        src.close()

    storage = PostgreSQLStorage()
    if storage._conn is None:
        print('[etl] ERROR: could not connect to PostgreSQL; aborting.', file=sys.stderr)
        return 1

    total_copied = 0
    last_id = 0
    scanned = 0

    while True:
        src = _connect_sqlite(sqlite_path)
        try:
            if has_id:
                rows = src.execute(
                    'SELECT * FROM honeypot_bears WHERE id > ? ORDER BY id ASC LIMIT ?',
                    (last_id, batch_size),
                ).fetchall()
            else:
                rows = src.execute(
                    'SELECT * FROM honeypot_bears ORDER BY rowid ASC LIMIT ? OFFSET ?',
                    (batch_size, scanned),
                ).fetchall()
        finally:
            src.close()

        if not rows:
            break

        for row in rows:
            rec = dict(row)
            # PostgreSQLStorage.insert() handles field extraction + dedup, so we
            # pass the raw row dict through. Strip the SQLite `id` (let PG assign
            # a fresh SERIAL) and any keys that aren't part of the record schema.
            rec.pop('id', None)
            storage.insert(rec)
            total_copied += 1
            if has_id:
                last_id = int(row['id'])
            scanned += 1

        print(f'[etl] copied {total_copied} row(s) so far...')

        if limit is not None and total_copied >= limit:
            break
        if not has_id and len(rows) < batch_size:
            break

    storage.close()
    print(f'[etl] done: {total_copied} row(s) copied to PostgreSQL.')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Migrate honeypot_bears from SQLite to PostgreSQL (one-time ETL).'
    )
    parser.add_argument(
        '--sqlite',
        default='/opt/manyfaced/bots/honeypot.sqlite',
        help='Path to the source SQLite database.',
    )
    parser.add_argument(
        '--batch',
        type=int,
        default=1000,
        help='Rows per batch (default 1000).',
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Maximum number of rows to copy (default: all).',
    )
    args = parser.parse_args()
    return migrate(args.sqlite, batch_size=args.batch, limit=args.limit)


if __name__ == '__main__':
    raise SystemExit(main())
