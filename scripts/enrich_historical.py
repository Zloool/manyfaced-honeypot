"""Retro-enrich historical honeypot captures with benign-source classification.

Issue #271 ships a live classification path (new rows land pre-classified), but
the millions of rows already in ``honeypot_bears`` have ``classification IS
NULL``. This script backfills them:

1. **Migrate** — add the ``bot_asn``/``bot_org``/``classification``/
   ``benign_source`` columns if absent (idempotent; the new-column migration is
   the same bounded-backup pattern as ``migrate_db.py``).
2. **Backfill** in batches over rows where ``classification IS NULL``:
   - reverse-DNS + UA are already in the row → classify immediately, no network.
   - ASN/org are missing for old rows → resolve via the existing
     ``geolocate.lookup_ip_geolocation`` batch helper (45 req/min limit),
     **cached by IP** so rows sharing an IP are not re-queried.
   - A row keeps ``NULL`` until it is successfully processed, so an interrupt
     leaves it re-processable on the next run (resumable).

The script is **idempotent** (re-running is a no-op once every row is
classified) and supports ``--dry-run`` to report the benign/unknown split
without writing.

Usage:
    python scripts/enrich_historical.py [--db PATH] [--batch N] [--dry-run]
                                        [--no-backup] [--limit N] [--sleep S]

Exit codes:
    0  backfill applied (or dry-run reported) successfully
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
import time

# Allow running as a script: ``python scripts/enrich_historical.py`` from repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from manyfaced.common.classification import classify  # noqa: E402
from manyfaced.common.geolocate import lookup_ip_geolocation  # noqa: E402
from manyfaced.db.storage import get_storage  # noqa: E402

# Columns this script guarantees exist before backfilling.
_NEW_COLUMNS = ('bot_asn', 'bot_org', 'classification', 'benign_source')


# ---------------------------------------------------------------------------
# Backup (bounded, mirrors migrate_db.py — issue #238 disk-safety lesson)
# ---------------------------------------------------------------------------


def _prune_backups(db_path: str, keep: int) -> None:
    """Delete oldest timestamped .bak copies so at most ``keep`` remain."""
    if keep < 0:
        return
    directory = os.path.dirname(db_path) or '.'
    pattern = re.compile(re.escape(db_path) + r'\.\d{14}\.bak$')
    backups = sorted(
        os.path.join(directory, p)
        for p in os.listdir(directory)
        if pattern.match(os.path.join(directory, p))
    )
    excess = backups[:-keep] if keep > 0 else backups
    for old in excess:
        try:
            os.remove(old)
            for suffix in ('-wal', '-shm'):
                sc = old + suffix
                if os.path.exists(sc):
                    os.remove(sc)
        except OSError as exc:
            print(f'[enrich] WARNING: could not remove old backup {old}: {exc}', file=sys.stderr)


def _backup(db_path: str, keep: int = 1) -> str | None:
    """Copy the live DB (and WAL sidecars) to a timestamped .bak beside it."""
    if not os.path.exists(db_path):
        return None
    # Free space FIRST: drop oldest backups so the new copy can fit on a small
    # droplet (mirrors the migrate_db.py fix — issue 2026-07 disk-full deploy).
    if keep < 0:
        pass
    elif keep == 0:
        _prune_backups(db_path, 0)
        return None
    else:
        _prune_backups(db_path, keep - 1)
    stamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    backup_path = f'{db_path}.{stamp}.bak'
    try:
        src = sqlite3.connect(db_path)
        src.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        src.close()
    except sqlite3.Error as exc:
        print(
            f'[enrich] WARNING: pre-backup checkpoint failed ({exc}); copying as-is.',
            file=sys.stderr,
        )
    try:
        shutil.copy2(db_path, backup_path)
        for sidecar in (f'{db_path}-wal', f'{db_path}-shm'):
            if os.path.exists(sidecar):
                shutil.copy2(sidecar, f'{backup_path}{sidecar[len(db_path) :]}')
    except OSError as exc:
        print(f'[enrich] ERROR: backup copy failed ({exc}); aborting.', file=sys.stderr)
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except OSError as exc:
                print(
                    f'[enrich] WARNING: could not remove failed backup {backup_path}: {exc}',
                    file=sys.stderr,
                )
        raise
    return backup_path


# ---------------------------------------------------------------------------
# Migrate
# ---------------------------------------------------------------------------


def migrate(db_path: str, backup: bool = True, keep: int = 3) -> int:
    """Add the classification columns if missing (idempotent)."""
    if backup:
        try:
            _backup(db_path, keep)
        except OSError as exc:
            print(f'[enrich] ERROR: {exc}', file=sys.stderr)
            return 1
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        existing = {r[1] for r in conn.execute('PRAGMA table_info(honeypot_bears)').fetchall()}
        missing = [c for c in _NEW_COLUMNS if c not in existing]
        if not missing:
            print('[enrich] columns already present; nothing to migrate.')
            return 0
        for col in missing:
            conn.execute(f'ALTER TABLE honeypot_bears ADD COLUMN {col} TEXT')
            print(f'[enrich] added column: {col}')
        conn.commit()
        return 0
    except sqlite3.Error as exc:
        if conn is not None:
            conn.rollback()
        print(f'[enrich] ERROR: {exc}', file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------


def _classify_row(
    row: dict[str, str],
    asn_cache: dict[str, tuple[str, str]],
) -> tuple[str, str, str, str]:
    """Classify one row, resolving ASN/org via cache/geo lookup if missing.

    Returns (asn, org, classification, benign_source).
    """
    ip = row.get('bot_ip') or ''
    asn = row.get('bot_asn') or ''
    org = row.get('bot_org') or ''

    # Only hit the network when both network signals are absent AND we have an
    # IP to resolve. Reverse-DNS/UA are always already on the row. Cache by IP
    # so rows sharing an attacker IP are not re-queried (the slow part).
    if ip and not asn and not org:
        if ip not in asn_cache:
            _country, _continent, r_asn, r_org = lookup_ip_geolocation(ip, timeout=5.0)
            asn_cache[ip] = (r_asn, r_org)
        asn, org = asn_cache[ip]

    classification, benign_source = classify(
        reverse_dns=row.get('bot_dns_name') or '',
        org=org,
        asn=asn,
        user_agent=row.get('bot_user_agent') or '',
    )
    return asn, org, classification, benign_source


def backfill(
    db_path: str,
    batch_size: int = 5000,
    dry_run: bool = False,
    limit: int | None = None,
    sleep: float = 0.0,
) -> int:
    """Classify **every** row where ``classification IS NULL``.

    Full catch-up: the NULL set is drained across the *whole* table (no recent-
    time-window or hard row cap), one commit-sized batch at a time, until zero
    NULL rows remain.

    Idempotent + resumable: a row only leaves the NULL set once its UPDATE
    commits, so re-running only ever touches rows that are still NULL. An
    interrupt mid-run leaves the remainder reprocessable, and a run after full
    completion selects nothing and is a no-op — already-classified rows are
    never recomputed or rewritten.

    Each committed batch logs how many NULL rows remain so an operator can watch
    progress and spot a stuck job.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        def _pending(limit_clause: str) -> list[sqlite3.Row]:
            return conn.execute(
                'SELECT id, bot_ip, bot_asn, bot_org, bot_dns_name, bot_user_agent '
                f'FROM honeypot_bears WHERE classification IS NULL {limit_clause}'
            ).fetchall()

        def _null_remaining() -> int:
            return conn.execute(
                'SELECT COUNT(*) FROM honeypot_bears WHERE classification IS NULL'
            ).fetchone()[0]

        total = _null_remaining()
        if total == 0:
            print('[enrich] nothing to backfill (all rows classified).')
            return 0

        print(f'[enrich] {total} row(s) pending classification{" (dry-run)" if dry_run else ""}.')
        asn_cache: dict[str, tuple[str, str]] = {}
        _seen_ids: set[int] = set()
        counts = {'benign': 0, 'unknown': 0, 'malicious': 0}
        processed = 0

        # Drain the NULL set in commit-sized batches. Each batch is one
        # transaction: classify up to ``batch_size`` NULL rows, UPDATE them, then
        # commit — so an interrupt only loses the uncommitted current batch and a
        # re-run resumes from the still-NULL remainder. ``limit`` caps the TOTAL
        # rows processed (used to simulate a partial run for resumability
        # testing); otherwise the loop runs until no NULL rows remain.
        while True:
            if limit is not None and processed >= limit:
                break
            rows = _pending(f'ORDER BY id LIMIT {batch_size}')
            if not rows:
                break

            # In dry-run mode rows are never written, so they remain in the
            # NULL set and would otherwise be re-selected forever. Only process
            # rows we have not seen this run; if a whole batch is already seen,
            # there is no new work and we terminate (avoids an infinite loop).
            new_rows = [r for r in rows if r['id'] not in _seen_ids]
            if not new_rows:
                break
            for r in new_rows:
                if limit is not None and processed >= limit:
                    break
                _seen_ids.add(r['id'])
                asn, org, classification, benign_source = _classify_row(
                    {
                        k: r[k]
                        for k in ('bot_ip', 'bot_asn', 'bot_org', 'bot_dns_name', 'bot_user_agent')
                    },
                    asn_cache,
                )
                counts[classification] = counts.get(classification, 0) + 1
                processed += 1
                if not dry_run:
                    conn.execute(
                        'UPDATE honeypot_bears SET bot_asn=?, bot_org=?, '
                        'classification=?, benign_source=? WHERE id=?',
                        (asn, org, classification, benign_source, r['id']),
                    )

            # Commit the batch, then report how many NULL rows are still left so
            # operators can see catch-up progress / detect a stuck job. In
            # dry-run nothing is written, so derive the remainder from processed.
            if not dry_run:
                conn.commit()
                remaining = _null_remaining()
            else:
                remaining = max(total - processed, 0)
            print(
                f'[enrich] processed {processed}/{total} '
                f'(benign={counts["benign"]}, unknown={counts["unknown"]}); '
                f'{remaining} NULL row(s) remain'
            )
            if sleep:
                time.sleep(sleep)

        if not dry_run:
            conn.commit()
        print(
            f'[enrich] done: {processed} row(s) '
            f'benign={counts["benign"]} unknown={counts["unknown"]} '
            f'malicious={counts["malicious"]}' + (' [dry-run, no writes]' if dry_run else '')
        )
        return 0
    except sqlite3.Error as exc:
        if conn is not None:
            conn.rollback()
        print(f'[enrich] ERROR: {exc}', file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()


def _backfill_pg(
    batch_size: int = 5000,
    dry_run: bool = False,
    limit: int | None = None,
) -> int:
    """PostgreSQL twin of :func:`backfill` — drains every ``classification IS
    NULL`` row using the live storage backend (issue #349 prod path).

    The daemon's PostgreSQL backend is the source of truth in production; the
    SQLite path above only handles the legacy local ``.sqlite``. This reuses
    ``_classify_row`` and the same commit-sized, resumable drain loop, but
    speaks psycopg2 (``%s`` params) against ``get_storage()._conn``.

    Returns 0 on success, 1 on unrecoverable error.
    """
    import psycopg2  # local import: only needed for the PG path

    store = get_storage()
    if store.__class__.__name__ != 'PostgreSQLStorage':
        print(
            '[enrich] --pg requested but get_storage() is not PostgreSQL; aborting.',
            file=sys.stderr,
        )
        return 1
    conn = store.connection  # psycopg2 connection (process-wide singleton)
    try:

        def _pending(limit_clause: str) -> list:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT id, bot_ip, bot_asn, bot_org, bot_dns_name, bot_user_agent '
                    'FROM honeypot_bears WHERE classification IS NULL ' + limit_clause
                )
                return cur.fetchall()

        def _null_remaining() -> int:
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) FROM honeypot_bears WHERE classification IS NULL')
                return cur.fetchone()[0]

        total = _null_remaining()
        if total == 0:
            print('[enrich] nothing to backfill (all rows classified).')
            return 0

        print(f'[enrich] {total} row(s) pending classification{" (dry-run)" if dry_run else ""}.')
        asn_cache: dict[str, tuple[str, str]] = {}
        counts = {'benign': 0, 'unknown': 0, 'malicious': 0}
        processed = 0

        while True:
            if limit is not None and processed >= limit:
                break
            rows = _pending(f'ORDER BY id LIMIT {batch_size}')
            if not rows:
                break
            for r in rows:
                if limit is not None and processed >= limit:
                    break
                asn, org, classification, benign_source = _classify_row(
                    {
                        'bot_ip': r[1],
                        'bot_asn': r[2],
                        'bot_org': r[3],
                        'bot_dns_name': r[4],
                        'bot_user_agent': r[5],
                    },
                    asn_cache,
                )
                counts[classification] = counts.get(classification, 0) + 1
                processed += 1
                if not dry_run:
                    with conn.cursor() as cur:
                        cur.execute(
                            'UPDATE honeypot_bears SET bot_asn=%s, bot_org=%s, '
                            'classification=%s, benign_source=%s WHERE id=%s',
                            (asn, org, classification, benign_source, r[0]),
                        )
            if not dry_run:
                conn.commit()
                remaining = _null_remaining()
            else:
                remaining = max(total - processed, 0)
            print(
                f'[enrich] processed {processed}/{total} '
                f'(benign={counts["benign"]}, unknown={counts["unknown"]}); '
                f'{remaining} NULL row(s) remain'
            )

        if not dry_run:
            conn.commit()
        print(
            f'[enrich] done: {processed} row(s) '
            f'benign={counts["benign"]} unknown={counts["unknown"]} '
            f'malicious={counts["malicious"]}' + (' [dry-run, no writes]' if dry_run else '')
        )
        return 0
    except psycopg2.Error as exc:
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        print(f'[enrich] ERROR: {exc}', file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description='Backfill benign-source classification.')
    parser.add_argument('--db', default='/opt/manyfaced/bots/honeypot.sqlite')
    parser.add_argument(
        '--batch', type=int, default=5000, help='Rows per commit-sized batch/transaction.'
    )
    parser.add_argument('--dry-run', action='store_true', help='Report split without writing.')
    parser.add_argument('--no-backup', action='store_true', help='Skip the .bak backup.')
    parser.add_argument('--limit', type=int, default=None, help='Cap rows processed (testing).')
    parser.add_argument(
        '--sleep', type=float, default=0.0, help='Seconds to sleep between batches.'
    )
    parser.add_argument('--keep', type=int, default=3, help='Backups to retain.')
    parser.add_argument(
        '--pg',
        action='store_true',
        help='Backfill the live PostgreSQL backend (get_storage()) instead of the '
        'legacy SQLite file. Use on production where honeypot_bears lives in PG.',
    )
    args = parser.parse_args()

    if args.pg:
        # PostgreSQL is the source of truth in production; the columns already
        # exist (created by PostgreSQLStorage._init_db), so skip the SQLite
        # migrate/_backup step and drain NULL rows via the live connection.
        return _backfill_pg(
            batch_size=args.batch,
            dry_run=args.dry_run,
            limit=args.limit,
        )

    if migrate(args.db, backup=not args.no_backup, keep=args.keep) != 0:
        return 1
    return backfill(
        args.db,
        batch_size=args.batch,
        dry_run=args.dry_run,
        limit=args.limit,
        sleep=args.sleep,
    )


if __name__ == '__main__':
    raise SystemExit(main())
