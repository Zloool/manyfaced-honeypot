"""BotProfile — per-bot state tracker for honeypot handlers.

This module contains only the BotProfile class which tracks per-bot state including
request history, detected behaviors, escalation level, captured credentials, and full
dialogue (request/response pairs).

Pattern detection constants live in patterns.py.

Usage::

    from manyfaced.handlers.bot_profile import BotProfile

    profile = BotProfile('1.2.3.4')
    profile.record_request({'path': '/wp-login.php', 'method': 'POST', ...})
    report = profile.get_full_report()
"""

from __future__ import annotations

import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Any

from manyfaced.handlers.patterns import (
    ENUM_PATHS,
    LFI_PATTERNS,
    RCE_PATTERNS,
    SCANNER_KEYWORDS,
    SQLI_PATTERNS,
    TOOL_KEYWORDS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BotProfile class
# ---------------------------------------------------------------------------


class BotProfile:
    """Tracks per-bot state for a handler's service.

    Each bot that interacts with a specific service gets a BotProfile that
    tracks request history, detected behaviors, escalation level, and full
    dialogue (request/response pairs).

    The dialogue is the most valuable artifact – it captures the complete
    interaction with the attacker, including exploit attempts, scanning
    patterns, and any credentials submitted.

    Memory bounds:
        - Per-profile ``request_history`` and ``dialogue`` are capped at
          ``MAX_HISTORY`` entries (oldest evicted on append).
        - The handler-level profile cache uses an LRU with a configurable
          max size; when full, the least-recently-used profile is discarded.
    """

    # Escalation levels
    IDLE = 0
    SCANNING = 1
    PROBE = 2
    EXPLOIT_ATTEMPT = 3
    COMPROMISE = 4
    DEEP_EXPLOIT = 5

    ESCALATION_LABELS: dict[int, str] = {
        IDLE: 'idle',
        SCANNING: 'scanning',
        PROBE: 'probing',
        EXPLOIT_ATTEMPT: 'exploiting',
        COMPROMISE: 'compromised',
        DEEP_EXPLOIT: 'deep_exploiting',
    }

    # Memory bounds — per-profile caps
    MAX_HISTORY = 500  # request_history entries
    MAX_DIALOGUE = 500  # dialogue entries

    def __init__(self, bot_ip: str) -> None:
        self.bot_ip = bot_ip
        self.session_id = hashlib.sha256(
            f'{bot_ip}:{datetime.now(timezone.utc).isoformat()}:{id(self)}'.encode()
        ).hexdigest()[:16]
        self.created_at = datetime.now(timezone.utc)
        self.last_updated = self.created_at
        self.request_history: list[dict[str, Any]] = []
        self.detected_behaviors: set[str] = set()
        self.escalation_level: int = self.IDLE
        self.escalation_label: str | None = None  # Custom label override (set by handlers)
        self._response_count: int = 0  # Request/response count (set by handlers)
        self.captured_credentials: list[dict[str, str]] = []

        # Dialogue tracking – the most valuable artifact
        self.dialogue: list[dict[str, Any]] = []  # Full request/response pairs
        self.metadata: dict[str, Any] = {}  # Extracted from first request

        self._lock = threading.RLock()

    def record_request(self, request: dict[str, Any]) -> None:
        """Record a request made by this bot."""
        with self._lock:
            self.request_history.append(request)
            # Evict oldest entries to stay within bounds
            while len(self.request_history) > self.MAX_HISTORY:
                self.request_history.pop(0)
            self.last_updated = datetime.now(timezone.utc)
            self._analyze_request(request)
            # Extract metadata from first request
            if not self.metadata and request.get('raw'):
                self._extract_metadata(request['raw'])

    def record_interaction(
        self,
        request: dict[str, Any],
        response: bytes,
        detected: int,
    ) -> None:
        """Record a full request/response interaction (dialogue entry).

        This is the primary method for building the dialogue artifact.
        Each call appends a complete interaction to self.dialogue.

        Args:
            request: The request dict (with 'path', 'method', 'raw', 'headers', etc.)
            response: The raw HTTP response bytes sent to the bot
            detected: The detected flag from the handler
        """
        with self._lock:
            # Truncate raw request/response for storage (keep first 5KB)
            raw_req = request.get('raw', '')
            max_raw = 5000
            if len(raw_req) > max_raw:
                raw_req = (
                    raw_req[:max_raw]
                    + f'\n... (truncated, {len(request.get("raw", ""))} total bytes)'
                )

            raw_resp = (
                response.decode('iso-8859-1', errors='replace')
                if isinstance(response, bytes)
                else str(response)
            )
            if len(raw_resp) > max_raw:
                raw_resp = (
                    raw_resp[:max_raw]
                    + f'\n... (truncated, {len(response) if isinstance(response, bytes) else len(str(response))} total bytes)'
                )

            dialogue_entry = {
                'sequence': len(self.dialogue) + 1,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request': {
                    'path': request.get('path', ''),
                    'method': request.get('method', ''),
                    'raw': raw_req,
                    'headers': request.get('headers', {}),
                },
                'response': {
                    'raw': raw_resp,
                    'size': len(response) if isinstance(response, bytes) else len(str(response)),
                    'detected': detected,
                },
            }
            self.dialogue.append(dialogue_entry)
            # Evict oldest entries to stay within bounds
            while len(self.dialogue) > self.MAX_DIALOGUE:
                self.dialogue.pop(0)
            logger.info(
                'Recorded dialogue entry #%d for %s (path=%s, method=%s)',
                dialogue_entry['sequence'],
                self.bot_ip,
                request.get('path', ''),
                request.get('method', ''),
            )

    def _extract_metadata(self, raw_request: str) -> None:
        """Extract metadata from the first request.

        Parses the HTTP request to extract User-Agent, Host, Accept,
        Content-Type, and other useful headers.
        """
        lines = raw_request.split('\r\n')
        if not lines:
            return

        # First line is the request line
        request_line = lines[0]
        parts = request_line.split(' ', 2)
        if len(parts) >= 2:
            self.metadata['method'] = parts[0]
            self.metadata['path'] = parts[1]
            if len(parts) >= 3:
                self.metadata['http_version'] = parts[2]

        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key.lower() == 'user-agent':
                    self.metadata['user_agent'] = value
                elif key.lower() == 'host':
                    self.metadata['host'] = value
                elif key.lower() == 'accept':
                    self.metadata['accept'] = value
                elif key.lower() == 'content-type':
                    self.metadata['content_type'] = value
                elif key.lower() == 'content-length':
                    self.metadata['content_length'] = value
                elif key.lower() == 'referer':
                    self.metadata['referer'] = value
                elif key.lower() == 'x-forwarded-for':
                    self.metadata['x_forwarded_for'] = value
                elif key.lower() == 'x-real-ip':
                    self.metadata['x_real_ip'] = value

        # Detect if it looks like a known scanner/tool
        ua = self.metadata.get('user_agent', '').lower()
        if any(kw in ua for kw in SCANNER_KEYWORDS):
            self.metadata['scanner_detected'] = True
            self.metadata['scanner_name'] = ua
        elif any(kw in ua for kw in TOOL_KEYWORDS):
            self.metadata['tool_detected'] = True
            self.metadata['tool_name'] = ua

    def _analyze_request(self, request: dict[str, Any]) -> None:
        """Analyze a request to detect attack patterns."""
        path = str(request.get('path', '')).lower()
        method = str(request.get('method', 'GET')).upper()
        raw = str(request.get('raw', '')).lower()

        # Detect SQL injection patterns
        for pattern in SQLI_PATTERNS:
            if pattern in path or pattern in raw:
                self.detected_behaviors.add('sql_injection')
                break

        # Detect LFI/RFI patterns
        for pattern in LFI_PATTERNS:
            if pattern in path or pattern in raw:
                self.detected_behaviors.add('lfi_rfi')
                break

        # Detect RCE patterns
        for pattern in RCE_PATTERNS:
            if pattern in raw:
                self.detected_behaviors.add('rce')
                break

        # Detect directory traversal
        if path.count('..') >= 2:
            self.detected_behaviors.add('directory_traversal')

        # Detect credential stuffing
        if method == 'POST' and any(
            kw in path for kw in ['login', 'admin', 'auth', 'wp-login', 'index.php']
        ):
            self.detected_behaviors.add('credential_stuffing')

        # Detect enumeration
        if any(path.startswith(p) for p in ENUM_PATHS):
            self.detected_behaviors.add('enumeration')

        self._update_escalation()

    def _update_escalation(self) -> None:
        """Update escalation level based on detected behaviors."""
        if 'rce' in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, self.DEEP_EXPLOIT)
        elif 'sql_injection' in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, self.EXPLOIT_ATTEMPT)
        elif 'lfi_rfi' in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, self.EXPLOIT_ATTEMPT)
        elif 'credential_stuffing' in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, self.EXPLOIT_ATTEMPT)
        elif 'directory_traversal' in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, self.PROBE)
        elif 'enumeration' in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, self.SCANNING)

    def capture_credentials(self, credentials: dict[str, str]) -> None:
        """Capture login credentials from a bot."""
        with self._lock:
            credentials['captured_at'] = datetime.now(timezone.utc).isoformat()
            credentials['session_id'] = self.session_id
            self.captured_credentials.append(credentials)
            self.detected_behaviors.add('credential_stuffing')
            self.escalation_level = max(self.escalation_level, self.EXPLOIT_ATTEMPT)
            logger.info(
                'Captured credentials from %s (session=%s): %s',
                self.bot_ip,
                self.session_id,
                {k: '***' if k == 'password' else v for k, v in credentials.items()},
            )

    def get_dialogue(self) -> list[dict[str, Any]]:
        """Get the full dialogue with this bot.

        Returns:
            List of dialogue entries (request/response pairs)
        """
        with self._lock:
            return list(self.dialogue)

    def get_full_report(self) -> dict[str, Any]:
        """Get a complete report including dialogue, metadata, and stats.

        Returns:
            Dict with bot_ip, session_id, metadata, dialogue, stats
        """
        with self._lock:
            return {
                'bot_ip': self.bot_ip,
                'session_id': self.session_id,
                'created_at': self.created_at.isoformat(),
                'last_updated': self.last_updated.isoformat(),
                'metadata': dict(self.metadata),
                'escalation_level': self.escalation_level,
                'escalation_label': self.escalation_label
                or self.ESCALATION_LABELS.get(self.escalation_level, 'unknown'),
                'detected_behaviors': list(self.detected_behaviors),
                'request_count': len(self.request_history),
                'dialogue_count': len(self.dialogue),
                'credential_attempts': len(self.captured_credentials),
                'captured_credentials': list(self.captured_credentials),
                'explored_paths': [r.get('path', '') for r in self.request_history],
                # Persist the raw request log (incl. handler-extracted C2 hosts,
                # exploit vectors and attack flags recorded via record_request).
                # Without this, handler-surfaced C2 IoCs (issue #520) never
                # reach the DB's bot_profile_data JSON and the dashboard IoC
                # panel can't surface them.
                'request_history': list(self.request_history),
                'dialogue': list(self.dialogue),
            }

    def get_stats(self) -> dict[str, Any]:
        """Get handler statistics for this bot."""
        with self._lock:
            return {
                'bot_ip': self.bot_ip,
                'session_id': self.session_id,
                'escalation_level': self.escalation_level,
                'escalation_label': self.escalation_label
                or self.ESCALATION_LABELS.get(self.escalation_level, 'unknown'),
                'detected_behaviors': list(self.detected_behaviors),
                'request_count': len(self.request_history),
                'dialogue_count': len(self.dialogue),
                'credential_attempts': len(self.captured_credentials),
                'explored_paths': [r.get('path', '') for r in self.request_history],
            }

    def __repr__(self) -> str:
        return (
            f'BotProfile(bot_ip={self.bot_ip!r}, session={self.session_id!r}, '
            f'level={self.ESCALATION_LABELS.get(self.escalation_level, "?")}, '
            f'behaviors={len(self.detected_behaviors)}, dialogue={len(self.dialogue)})'
        )
