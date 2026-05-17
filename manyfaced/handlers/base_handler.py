"""Abstract base classes for honeypot handlers.

Two handler hierarchies exist:

1. **BaseHandler** (server-side) — receives encrypted messages from the client,
   decrypts them, and processes the bot data. Used by ``ServerHandler`` in
   ``server/server.py``.

2. **HTTPHandlerBase** (client-side) — receives raw HTTP requests from bots,
   routes them to service-specific handlers (WordPress, phpMyAdmin, etc.),
   generates realistic honeypot responses, and captures credentials.

BotProfile is defined in bot_profile.py for modularity.
"""

from __future__ import annotations

import abc
import json
import logging
import threading
from abc import abstractmethod
from typing import Any

from manyfaced.common.myenc import AESCipher
from manyfaced.handlers.bot_profile import BotProfile  # noqa: F401 — re-exported for backward compat

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


# ---------------------------------------------------------------------------
# HTTPHandlerBase (client-side — receives raw HTTP from bots)
# ---------------------------------------------------------------------------

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
            'log', 'user', 'username', 'login', 'user_login',
            'USER_LOGIN', 'j_username', 'uid', 'email',
            'pma_username', 'server[0][user]',
        ]
        password_fields = [
            'pwd', 'pass', 'password', 'login_password', 'j_password',
            'passwort', 'user_pass', 'USER_PASSWORD',
            'pma_password', 'server[0][password]',
        ]

        # URL-decode the body
        for old, new in [('+', ' '), ('%40', '@'), ('%3D', '='), ('%26', '&'),
                         ('%23', '#'), ('%25', '%'), ("'%", "'"),
                         ('%22', '"'), ('%2F', '/'), ('%3A', ':'), ('%3F', '?')]:
            body = body.replace(old, new)

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
