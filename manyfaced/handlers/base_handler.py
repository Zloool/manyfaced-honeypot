"""Abstract base classes for honeypot handlers.

Two handler hierarchies exist:

1. **BaseHandler** (server-side) — receives encrypted messages from the client,
   decrypts them, and processes the bot data. Used by ``ServerHandler`` in
   ``server/server.py``.

2. **HTTPHandlerBase** (client-side) — receives raw HTTP requests from bots,
   routes them to service-specific handlers (WordPress, phpMyAdmin, etc.),
   generates realistic honeypot responses, and captures credentials.

Usage – server side::

    handler = ServerHandler(args, update_event)
    response = handler.handle_request(encrypted_message)

Usage – client side::

    handler = WordPressHandler()
    response_bytes, detected = handler.generate_response(
        path="/wp-login.php",
        raw_request="GET /wp-login.php HTTP/1.1...",
        bot_ip="1.2.3.4",
    )
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
import hashlib
import json
import logging
import threading
from abc import abstractmethod
from typing import Any

from manyfaced.common.myenc import AESCipher

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Server-side BaseHandler (encrypted messages from client)
# ---------------------------------------------------------------------------


class BaseHandler(abc.ABC):
    """Abstract handler for server-side encrypted message processing.

    Subclasses implement ``get_key()`` and ``process_request()``.

    Pipeline::

        handle_request(message)
          -> parse_message()      # Split on ":" into (identifier, encrypted)
          -> decrypt_message()    # AES decrypt with key from get_key()
          -> parse_json()          # Deserialize JSON data
          -> process_request()     # Abstract — implemented by subclass
    """

    def __init__(self, args: Any, update_event: Any) -> None:
        self.args = args
        self.update_event = update_event

    def handle_request(self, message: str) -> Any:
        """Decrypt and route a message to process_request."""
        request = self.parse_message(message)
        decrypted = self.decrypt_message(request)
        data = self.parse_json(decrypted)
        return self.process_request(data)

    def parse_message(self, message: str):
        """Parse a message into identifier and encrypted data.

        Args:
            message: The raw message string from the socket

        Returns:
            Tuple of (identifier, encrypted_data)

        Raises:
            ValueError: If message format is invalid
        """
        request = message.split(':', 1)
        if len(request) != 2:
            raise ValueError('Invalid message format')
        return request

    def decrypt_message(self, request) -> bytes:
        """Decrypt the second part of request using the key for identifier."""
        key = self.get_key(request[0])
        decipher = AESCipher(key)
        return decipher.decrypt(request[1])

    def parse_json(self, decrypted_data: bytes) -> dict[str, Any]:
        try:
            data = json.loads(decrypted_data.decode('utf-8'))
            return data
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f'Invalid JSON format: {e}')

    @abstractmethod
    def get_key(self, identifier) -> str:
        """Return the decryption key for the given bear identifier."""
        ...

    @abstractmethod
    def process_request(self, data: dict[str, Any]) -> Any:
        """Process decrypted request data. Subclasses must implement."""
        ...

    def _common_processing(self, data: dict[str, Any]) -> None:
        """Common processing logic. Override in subclasses as needed."""
        pass

    def process_request_safe(self, data: dict[str, Any]) -> Any:
        """Wrapper that catches exceptions during processing."""
        try:
            self._common_processing(data)
        except Exception as e:
            print(f'Error processing request: {e}')


class BotProfile:
    """Tracks per-bot state for a handler's service.

    Each bot that interacts with a specific service gets a BotProfile that
    tracks request history, detected behaviors, escalation level, and full
    dialogue (request/response pairs).

    The dialogue is the most valuable artifact – it captures the complete
    interaction with the attacker, including exploit attempts, scanning
    patterns, and any credentials submitted.
    """

    # Escalation levels
    IDLE = 0
    SCANNING = 1
    PROBE = 2
    EXPLOIT_ATTEMPT = 3
    COMPROMISE = 4
    DEEP_EXPLOIT = 5

    ESCALATION_LABELS = {
        IDLE: 'idle',
        SCANNING: 'scanning',
        PROBE: 'probing',
        EXPLOIT_ATTEMPT: 'exploiting',
        COMPROMISE: 'compromised',
        DEEP_EXPLOIT: 'deep_exploiting',
    }

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
        self.captured_credentials: list[dict[str, str]] = []

        # Dialogue tracking – the most valuable artifact
        self.dialogue: list[dict[str, Any]] = []  # Full request/response pairs
        self.metadata: dict[str, Any] = {}  # Extracted from first request

        self._lock = threading.RLock()

    def record_request(self, request: dict[str, Any]) -> None:
        """Record a request made by this bot."""
        with self._lock:
            self.request_history.append(request)
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
        if any(
            kw in ua
            for kw in [
                'nikto',
                'sqlmap',
                'nmap',
                'dirbuster',
                'gobuster',
                'wfuzz',
                'burp',
                'hydra',
                'medusa',
                'masscan',
            ]
        ):
            self.metadata['scanner_detected'] = True
            self.metadata['scanner_name'] = ua
        elif any(kw in ua for kw in ['python-requests', 'curl', 'wget', 'java', 'go-http']):
            self.metadata['tool_detected'] = True
            self.metadata['tool_name'] = ua

    def _analyze_request(self, request: dict[str, Any]) -> None:
        """Analyze a request to detect attack patterns."""
        path = str(request.get('path', '')).lower()
        method = str(request.get('method', 'GET')).upper()
        raw = str(request.get('raw', '')).lower()

        # Detect SQL injection patterns
        sqli_patterns = [
            'union',
            'select',
            'drop',
            'insert',
            'delete',
            'update',
            'or 1=1',
            'and 1=1',
            'sleep(',
            'benchmark(',
            'or+1=1',
            'and+1=1',
            "admin'--",
            '1=1--',
        ]
        for pattern in sqli_patterns:
            if pattern in path or pattern in raw:
                self.detected_behaviors.add('sql_injection')
                break

        # Detect LFI/RFI patterns
        lfi_patterns = [
            '../',
            '..\\',
            '/etc/passwd',
            '/etc/shadow',
            'php://',
            'expect://',
            'data://',
        ]
        for pattern in lfi_patterns:
            if pattern in path or pattern in raw:
                self.detected_behaviors.add('lfi_rfi')
                break

        # Detect RCE patterns
        rce_patterns = [
            '; ls',
            '| cat',
            '&& wget',
            '$(curl',
            '`nc`',
            'eval(',
            'exec(',
            '| cat ',
            '; cat ',
            '&& cat ',
            'cat /etc',
            'wget http',
            'curl http',
        ]
        for pattern in rce_patterns:
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
        enum_paths = [
            '/admin',
            '/wp-admin',
            '/phpmyadmin',
            '/server-status',
            '/.git',
            '/.env',
            '/config',
            '/backup',
            '/manager',
        ]
        if any(path.startswith(p) for p in enum_paths):
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
                'escalation_label': self.ESCALATION_LABELS.get(self.escalation_level, 'unknown'),
                'detected_behaviors': list(self.detected_behaviors),
                'request_count': len(self.request_history),
                'dialogue_count': len(self.dialogue),
                'credential_attempts': len(self.captured_credentials),
                'captured_credentials': list(self.captured_credentials),
                'explored_paths': [r.get('path', '') for r in self.request_history],
                'dialogue': list(self.dialogue),
            }

    def get_stats(self) -> dict[str, Any]:
        """Get handler statistics for this bot."""
        with self._lock:
            return {
                'bot_ip': self.bot_ip,
                'session_id': self.session_id,
                'escalation_level': self.escalation_level,
                'escalation_label': self.ESCALATION_LABELS.get(self.escalation_level, 'unknown'),
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


class HTTPHandlerBase(abc.ABC):
    """Abstract base class for HTTP honeypot handlers.

    Each handler manages a specific service/domain. Subclasses implement:
    - generate_response(): Generate a realistic HTTP response
    - handle_login(): (Optional) Process login attempts and capture credentials

    Path matching is handled by the Router / route table — individual
    handlers are pure response generators with no routing logic.
    """

    # Service domain identifier (e.g., "wordpress", "phpmyadmin")
    domain: str = 'base'

    # Detected ID value for this service
    DETECTED_ID: int = 1

    def __init__(self) -> None:
        self.bot_profiles: dict[str, BotProfile] = {}
        self._lock = threading.RLock()
        self._response_count: int = 0

    @abc.abstractmethod
    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate an HTTP response for the given request.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag)
        """

    def get_or_create_profile(self, bot_ip: str) -> BotProfile:
        """Get existing profile or create a new one for the bot."""
        with self._lock:
            if bot_ip not in self.bot_profiles:
                profile = BotProfile(bot_ip=bot_ip)
                self.bot_profiles[bot_ip] = profile
                logger.info(
                    'Created new BotProfile for %s (session=%s, domain=%s)',
                    bot_ip,
                    profile.session_id,
                    self.domain,
                )
            return self.bot_profiles[bot_ip]

    def handle_login(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str],
    ) -> tuple[dict[str, str] | None, bytes, int]:
        """Process a login attempt and capture credentials.

        Subclasses can override this to customize credential extraction.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers

        Returns:
            Tuple of (credentials_dict_or_None, response_bytes, detected_flag)
        """
        credentials = self._extract_credentials(raw_request, headers)
        if credentials:
            profile = self.get_or_create_profile(bot_ip)
            profile.capture_credentials(credentials)
            # Return a "success" response to encourage further probing
            response = self._login_success_response()
            return credentials, response, self.DETECTED_ID
        return None, b'', self.DETECTED_ID

    def _extract_credentials(
        self,
        raw_request: str,
        headers: dict[str, str],
    ) -> dict[str, str] | None:
        """Extract credentials from a POST request.

        Looks for common credential field names in the request body.

        Args:
            raw_request: The raw HTTP request string
            headers: Request headers

        Returns:
            Dict with 'username' and 'password' keys, or None
        """
        # Split headers from body
        parts = raw_request.split('\r\n\r\n', 1)
        if len(parts) < 2:
            return None
        body = parts[1]

        # Normalize field names: strip trailing '=' so we can append it once
        # This fixes the bug where fields like "log=" became "log=="
        username_fields = [
            'log',
            'user',
            'username',
            'login',
            'user_login',
            'USER_LOGIN',
            'j_username',
            'uid',
            'email',
            'pma_username',
            'server[0][user]',
        ]
        password_fields = [
            'pwd',
            'pass',
            'password',
            'login_password',
            'j_password',
            'passwort',
            'user_pass',
            'USER_PASSWORD',
            'pma_password',
            'server[0][password]',
        ]

        # URL-decode the body
        body = body.replace('+', ' ')
        body = body.replace('%40', '@')
        body = body.replace('%3D', '=')
        body = body.replace('%26', '&')
        body = body.replace('%23', '#')
        body = body.replace('%25', '%')
        body = body.replace('%27', "'")
        body = body.replace('%22', '"')
        body = body.replace('%2F', '/')
        body = body.replace('%3A', ':')
        body = body.replace('%3F', '?')

        username = None
        password = None

        for field in username_fields:
            prefix = field + '='
            if prefix in body:
                value = body.split(prefix, 1)[1].split('&', 1)[0]
                if value:
                    username = value
                    break

        for field in password_fields:
            prefix = field + '='
            if prefix in body:
                value = body.split(prefix, 1)[1].split('&', 1)[0]
                if value:
                    password = value
                    break

        if username and password:
            return {'username': username, 'password': password}
        return None

    def _login_success_response(self) -> bytes:
        """Return a fake login success response."""
        return b'HTTP/1.1 302 Found\r\nLocation: /wp-admin/\r\n\r\n'

    def get_profile(self, bot_ip: str) -> BotProfile | None:
        """Get the bot's profile, or None if not found."""
        with self._lock:
            return self.bot_profiles.get(bot_ip)

    def get_all_profiles(self) -> list[BotProfile]:
        """Get all bot profiles."""
        with self._lock:
            return list(self.bot_profiles.values())

    def clear_profile(self, bot_ip: str) -> None:
        """Clear a bot's profile."""
        with self._lock:
            if bot_ip in self.bot_profiles:
                del self.bot_profiles[bot_ip]
                logger.info('Cleared profile for %s (domain=%s)', bot_ip, self.domain)

    def get_stats(self) -> dict[str, Any]:
        """Get handler statistics."""
        with self._lock:
            return {
                'domain': self.domain,
                'active_profiles': len(self.bot_profiles),
                'total_responses': self._response_count,
                'total_credential_captures': sum(
                    len(p.captured_credentials) for p in self.bot_profiles.values()
                ),
                'profiles': {ip: p.get_stats() for ip, p in self.bot_profiles.items()},
            }

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(domain={self.domain!r})'
