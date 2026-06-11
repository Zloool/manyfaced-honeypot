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
from collections import OrderedDict
from typing import Any

from manyfaced.common.myenc import AESCipher
from manyfaced.common.credential_extractor import extract_http_credentials
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

    def process_request_safe(self, data: dict[str, Any]) -> Any | None:
        """Wrapper that catches exceptions during processing and logs them properly.

        Calls the abstract process_request() method with error handling.
        Returns None if an exception occurs (prevents crashes in production).
        """
        try:
            return self.process_request(data)
        except Exception as e:
            logger.error('Error processing request: %s', e, exc_info=True)
            return None


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

    # Maximum number of bot profiles per handler (LRU eviction when exceeded)
    MAX_PROFILES: int = 1000

    def __init__(self) -> None:
        # OrderedDict-based LRU cache — most recently used item is at the end
        self.bot_profiles: OrderedDict[str, BotProfile] = OrderedDict()
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
        """Get existing profile or create a new one for the bot.

        Uses an LRU cache with a configurable max size (MAX_PROFILES). When the
        cache is full, the least-recently-used profile is evicted to prevent
        unbounded memory growth.
        """
        with self._lock:
            if bot_ip in self.bot_profiles:
                # Move to end (most recently used) — only for OrderedDict
                if hasattr(self.bot_profiles, 'move_to_end'):
                    self.bot_profiles.move_to_end(bot_ip)
                return self.bot_profiles[bot_ip]

            # Evict least-recently-used profile if at capacity
            while len(self.bot_profiles) >= self.MAX_PROFILES:
                evicted_ip, evicted_profile = self.bot_profiles.popitem(last=False)
                logger.info(
                    'Evicted LRU BotProfile for %s (domain=%s, cache_size=%d)',
                    evicted_ip,
                    self.domain,
                    len(self.bot_profiles),
                )

            profile = BotProfile(bot_ip=bot_ip)
            self.bot_profiles[bot_ip] = profile
            logger.info(
                'Created new BotProfile for %s (session=%s, domain=%s)',
                bot_ip,
                profile.session_id,
                self.domain,
            )
            return profile

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

        Delegates to the unified credential extractor for consistent behavior.

        Args:
            raw_request: The raw HTTP request string
            headers: Request headers

        Returns:
            Dict with 'username' and/or 'password' keys, or None if not found.
        """
        return extract_http_credentials(raw_request, headers)

    def _login_success_response(self) -> bytes:
        """Return a fake login success response."""
        return b'HTTP/1.1 302 Found\r\nLocation: /wp-admin/\r\n\r\n'

    def get_profile(self, bot_ip: str) -> BotProfile | None:
        """Get the bot's profile, or None if not found.

        Moves the profile to end (most recently used) for LRU tracking.
        """
        with self._lock:
            if bot_ip in self.bot_profiles:
                # Move to end (most recently used) — only for OrderedDict
                if hasattr(self.bot_profiles, 'move_to_end'):
                    self.bot_profiles.move_to_end(bot_ip)
                return self.bot_profiles[bot_ip]
            return None

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
