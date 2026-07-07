"""Handler-replay corpus + snapshot harness (issue #163).

Deterministic offline validation of "given a raw probe, what does each face
return?". Feeds every fixture under ``test/corpus/`` through
``HTTPHandler.handle_request`` and snapshots the normalized response. A handler
or route-table change surfaces as a snapshot diff — no live bots, fully
deterministic, no network.

Snapshot storage: ``test/corpus/snapshots/<scenario>.json``. On a mismatch the
test fails with a readable diff. To intentionally update the golden snapshots
after a legitimate behavior change:

    REGEN_SNAPSHOTS=1 pytest test/test_handler_replay.py

The PR should then include the snapshot diff as the reviewable evidence of the
behavior change.

Normalization: responses may carry volatile headers (``Date:``, ``Set-Cookie:``
with session ids, server-generated nonces). We strip those and normalize line
endings/whitespace so a snapshot reflects handler *logic*, not server clock or
random bytes.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from manyfaced.common.protocol import detect_protocol
from manyfaced.handlers.http_handler import HTTPHandler

CORPUS_DIR = Path(__file__).resolve().parent / 'corpus'
SNAPSHOT_DIR = CORPUS_DIR / 'snapshots'
REGEN = os.environ.get('REGEN_SNAPSHOTS') == '1'

# Headers whose values are non-deterministic (server clock, random session id).
_VOLATILE_HEADERS = ('date', 'set-cookie', 'expires', 'last-modified', 'server')
# The SSH banner embeds a randomly-chosen fake implementation+version
# (OpenSSH_x.y, libssh2_x.y.z, ...); the whole banner line is the version
# string, so mask it entirely to a stable placeholder.
_SSH_BANNER_RE = re.compile(r'SSH-2\.0-[^\r\n]*')


def _normalize_response(raw_bytes: bytes) -> str:
    """Decode + strip volatile headers + normalize whitespace for stable snapshots."""
    text = raw_bytes.decode('latin-1', errors='replace')
    lines = []
    for line in text.splitlines():
        low = line.lower()
        if any(low.startswith(h + ':') for h in _VOLATILE_HEADERS):
            continue
        line = _SSH_BANNER_RE.sub('SSH-2.0-<banner>', line)
        lines.append(line.rstrip())
    # Drop trailing blank lines.
    while lines and lines[-1] == '':
        lines.pop()
    return '\n'.join(lines)


def _discover_corpus():
    return sorted(p.name for p in CORPUS_DIR.glob('*.raw'))


CORPUS_FILES = _discover_corpus()


def _snapshot_path(name: str) -> Path:
    return SNAPSHOT_DIR / (name + '.json')


@pytest.mark.parametrize('probe', CORPUS_FILES)
def test_handler_replay_snapshot(probe):
    name = probe[:-4]  # strip .raw
    raw = (CORPUS_DIR / probe).read_bytes()

    handler = HTTPHandler(
        __import__('unittest.mock', fromlist=['MagicMock']).MagicMock(),
        __import__('unittest.mock', fromlist=['MagicMock']).MagicMock(),
    )
    out = handler.handle_request(raw, bot_ip='127.0.0.1')

    # HTTP path returns bytes; SSH/non-HTTP returns (bytes, BearStorage).
    response_bytes = out[0] if isinstance(out, tuple) else out
    assert isinstance(response_bytes, bytes), f'{name}: expected bytes response'

    protocol = detect_protocol(response_bytes) or detect_protocol(raw) or 'http'
    normalized = _normalize_response(response_bytes)

    snapshot = {
        'scenario': name,
        'protocol': protocol,
        'normalized_response': normalized,
    }

    snap_path = _snapshot_path(name)
    if REGEN or not snap_path.exists():
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        snap_path.write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + '\n', encoding='utf-8'
        )
        pytest.skip(f'Snapshot written for {name} (regen mode or missing)')

    expected = json.loads(snap_path.read_text(encoding='utf-8'))
    assert snapshot == expected, (
        f'Snapshot mismatch for {name}.\n'
        f'If this is an intentional behavior change, run:\n'
        f'  REGEN_SNAPSHOTS=1 pytest test/test_handler_replay.py\n'
        f'and commit the updated test/corpus/snapshots/{name}.json.'
    )


def test_corpus_is_nonempty():
    assert CORPUS_FILES, 'corpus must contain at least one .raw probe'
