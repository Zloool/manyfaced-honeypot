"""HandlerRegistry – manages and routes HTTP requests to specialized handlers.

Maintains a registry of HTTP handlers and routes incoming requests to the
appropriate handler based on path patterns.

When a path matches multiple handlers (e.g., /admin matches both WordPress
and Drupal), the registry mashes all responses together so the bot sees
a confused, multi-service environment – this is more realistic and
encourages deeper probing.

Usage:
    from manyfaced.handlers.registry import HandlerRegistry
    from manyfaced.handlers.wordpress_handler import WordPressHandler
    from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler

    registry = HandlerRegistry()
    registry.register(WordPressHandler())
    registry.register(PhpMyAdminHandler())

    # Route a request
    handler = registry.get_handler("/wp-login.php")
    if handler:
        response_bytes, detected = handler.generate_response(
            path="/wp-login.php",
            raw_request="...",
            bot_ip="1.2.3.4",
        )
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class HandlerRegistry:
    """Manages and routes HTTP requests to specialized handlers.

    Attributes:
        handlers: Dict of domain -> HTTPHandlerBase
        _lock: Thread lock for handler management
    """

    def __init__(self) -> None:
        self.handlers: dict[str, HTTPHandlerBase] = {}
        self._lock = threading.Lock()

    def register(self, handler: HTTPHandlerBase) -> None:
        """Register a handler.

        Args:
            handler: The handler to register
        """
        with self._lock:
            domain = handler.domain
            if domain in self.handlers:
                logger.warning(
                    "Handler for domain '%s' already registered – replacing",
                    domain,
                )
            self.handlers[domain] = handler
            logger.info("Registered handler: %s (domain=%s)", handler, domain)

    def unregister(self, domain: str) -> None:
        """Unregister a handler by domain.

        Args:
            domain: The domain of the handler to unregister
        """
        with self._lock:
            if domain in self.handlers:
                del self.handlers[domain]
                logger.info("Unregistered handler: %s", domain)

    def get_handler(self, path: str) -> HTTPHandlerBase | None:
        """Get the first handler for a given path.

        Iterates through registered handlers in registration order and
        returns the first one whose matches_path() returns True.

        Args:
            path: The URL path to match

        Returns:
            The matching handler, or None if no handler matches
        """
        with self._lock:
            for handler in self.handlers.values():
                if handler.matches_path(path):
                    return handler
        return None

    def get_all_matching_handlers(self, path: str) -> list[HTTPHandlerBase]:
        """Get all handlers that match a given path.

        Unlike get_handler(), this returns ALL matching handlers so their
        responses can be mashed together.

        Args:
            path: The URL path to match

        Returns:
            List of all matching handlers (may be empty)
        """
        with self._lock:
            return [h for h in self.handlers.values() if h.matches_path(path)]

    def get_all_handlers(self) -> list[HTTPHandlerBase]:
        """Get all registered handlers.

        Returns:
            List of all HTTPHandlerBase instances
        """
        with self._lock:
            return list(self.handlers.values())

    @staticmethod
    def _mash_responses(
        results: list[tuple[bytes, int]],
    ) -> tuple[bytes, int]:
        """Mash multiple handler responses into a single response.

        Takes the HTTP headers from the first response, and combines
        the HTML bodies from all responses. The detected flag is set
        if ANY handler detected the request.

        Args:
            results: List of (response_bytes, detected_flag) tuples

        Returns:
            Tuple of (mashed_response_bytes, detected_flag)
        """
        if not results:
            return b"", 0

        # Extract headers from first response and bodies from all
        first_headers = b""
        all_bodies = []
        detected = 0

        for response_bytes, detected_flag in results:
            # Split headers from body (headers end at first \r\n\r\n)
            header_end = response_bytes.find(b"\r\n\r\n")
            if header_end == -1:
                # No headers/body split – treat entire response as body
                all_bodies.append(response_bytes)
                detected = max(detected, detected_flag)
            else:
                header_part = response_bytes[:header_end + 4]
                body_part = response_bytes[header_end + 4:]

                if not first_headers:
                    first_headers = header_part
                all_bodies.append(body_part)
                detected = max(detected, detected_flag)

        # Combine: headers from first response, all bodies concatenated
        if first_headers:
            mashed = first_headers + b"".join(all_bodies)
        else:
            mashed = b"".join(all_bodies)

        return mashed, detected

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int] | None:
        """Generate a response using all matching handlers.

        When multiple handlers match the path (e.g., /admin matches both
        WordPress and Drupal), all their responses are mashed together
        so the bot sees a confused, multi-service environment.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag) or None if no handler matches
        """
        matching_handlers = self.get_all_matching_handlers(path)

        if not matching_handlers:
            return None

        # Generate responses from all matching handlers
        results = []
        for handler in matching_handlers:
            try:
                response_bytes, detected_flag = handler.generate_response(
                    path=path,
                    raw_request=raw_request,
                    bot_ip=bot_ip,
                    headers=headers,
                )
                results.append((response_bytes, detected_flag))
                logger.debug(
                    "Handler %s generated response for %s (detected=%d, size=%d)",
                    handler.domain, path, detected_flag, len(response_bytes),
                )
            except Exception as e:
                logger.warning(
                    "Handler %s failed for %s: %s", handler.domain, path, e
                )

        if not results:
            return None

        # Mash all responses together
        return self._mash_responses(results)

    def get_bot_profiles(self, bot_ip: str) -> list[dict[str, Any]]:
        """Get all profiles for a given bot IP across all handlers.

        Args:
            bot_ip: The bot's IP address

        Returns:
            List of profile dicts
        """
        profiles = []
        for handler in self.get_all_handlers():
            profile = handler.get_profile(bot_ip)
            if profile:
                profiles.append(profile.get_stats())
        return profiles

    def clear_bot_profiles(self, bot_ip: str) -> None:
        """Clear all profiles for a given bot IP across all handlers.

        Args:
            bot_ip: The bot's IP address
        """
        for handler in self.get_all_handlers():
            handler.clear_profile(bot_ip)

    def get_stats(self) -> dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dict with registry stats
        """
        with self._lock:
            return {
                "total_handlers": len(self.handlers),
                "handlers": {
                    domain: handler.get_stats()
                    for domain, handler in self.handlers.items()
                },
            }

    def __repr__(self) -> str:
        return f"HandlerRegistry(handlers={len(self.handlers)})"
