"""Best-effort decoding of captured request payloads (issue #368).

A large fraction of real exploit payloads are base64 / URL-encoded, and the
dashboard's Payloads panel + C2-host extraction historically scanned the
*raw* bytes — so the IOCs hidden inside (`wget http://1.2.3.4/x`,
`../../etc/passwd`, `.env` file probes) were invisible. This module decodes a
payload into a human-readable form used for (a) the split-view Payloads panel
and (b) IOC/C2 extraction.

Decoding is **best-effort + failsafe**: a payload that isn't encoded (or is
malformed) returns unchanged, never blanks. All steps are bounded so an
adversarial giant payload can't stall the panel.

Coverage (verified against prod captures):
* URL-decode ``%xx`` — including the malformed dot/slash escapes scanners use
  to dodge naive decoders: ``.%2e`` -> ``..``, ``%2e%2e%2f`` -> ``../``,
  ``.%2f`` -> ``./``, ``..%2f`` -> ``../``. ``+`` -> space.
* base64-decode detected tokens (length >= ``_B64_MIN_LEN``), with padding
  repair + strict validation so random high-entropy strings aren't force-
  decoded into garbage.
* Recurse when the decoded layer is itself encoded (nested/double encoding),
  up to ``_MAX_DECODE_PASSES``.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import unquote

# Bounded work so a hostile/adversarial payload can't stall the panel.
_MAX_DECODE_PASSES = 3
# Only attempt base64 on runs at least this long — short runs are noise.
_B64_MIN_LEN = 16
# A base64 token: A-Za-z0-9+/ with 0-2 trailing padding chars.
_B64_RE = re.compile(r'[A-Za-z0-9+/]{' + str(_B64_MIN_LEN) + r',}={0,2}')
# A token that still looks encoded after a pass (triggers another pass).
_RESIDUAL_ENCODED_RE = re.compile(
    r'%[0-9A-Fa-f]{2}|[A-Za-z0-9+/]{' + str(_B64_MIN_LEN) + r',}={0,2}'
)


def _try_b64(token: str) -> str | None:
    """Decode ``token`` as base64 if it validates and yields printable text.

    Returns the decoded *text* or ``None`` when the token is not real base64
    (random high-entropy strings must not be force-decoded into garbage).
    """
    pad = (-len(token)) % 4
    candidate = token + ('=' * pad)
    try:
        raw = base64.b64decode(candidate, validate=True)
    except Exception:  # noqa: BLE001 — any failure means "not base64"
        return None
    try:
        text = raw.decode('utf-8')
    except Exception:  # noqa: BLE001 — non-text payload, not our target
        return None
    if not text.strip():
        return None
    # Require a high printable ratio so binary/garbage isn't surfaced as text.
    printable = sum(32 <= ord(c) < 127 or c in '\n\r\t' for c in text)
    if printable / max(1, len(text)) < 0.85:
        return None
    return text


def decode_payload(raw: str) -> str:
    """Return a best-effort decoded view of ``raw``.

    Failsafe: on any empty/invalid input returns the input unchanged.
    """
    if not raw:
        return raw

    cur = raw
    for _ in range(_MAX_DECODE_PASSES):
        # 1) URL-decode (handles %xx incl. malformed dot/slash escapes, +->space).
        url_decoded = unquote(cur)
        # 2) base64-decode any detected token in the current layer.
        parts: list[str] = []
        last = 0
        for m in _B64_RE.finditer(url_decoded):
            parts.append(url_decoded[last : m.start()])
            decoded = _try_b64(m.group(0))
            parts.append(decoded if decoded is not None else m.group(0))
            last = m.end()
        parts.append(url_decoded[last:])
        layer = ''.join(parts)

        # Stop when a full pass makes no progress.
        if layer == cur:
            break
        cur = layer
        # One more pass only if the layer still looks encoded.
        if not _RESIDUAL_ENCODED_RE.search(cur):
            break

    return cur
