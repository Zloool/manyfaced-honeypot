"""
ResponderRegistry – manages and routes to modular responders.

Maintains a registry of responders and routes incoming requests to the
appropriate responder based on path patterns.

Usage:
    from manyfaced.common.responder.registry import ResponderRegistry
    from manyfaced.common.responder.phpmyadmin_responder import PhpMyAdminResponder
    from manyfaced.common.responder.wordpress_responder import WordPressResponder

    registry = ResponderRegistry(ai_responder=ai_responder)
    registry.register(PhpMyAdminResponder())
    registry.register(WordPressResponder())

    # Route a request
    responder = registry.get_responder("/phpmyadmin/")
    if responder:
        response_bytes, detected = responder.generate_response(
            path="/phpmyadmin/",
            raw_request="...",
            bot_ip="1.2.3.4",
        )
"""

from __future__ import annotations

import threading
from typing import Any

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.responder.responder_base import ResponderBase

logger = get_logger(__name__)


class ResponderRegistry:
    """Manages and routes to modular responders.

    Attributes:
        responders: Dict of domain -> ResponderBase
        ai_responder: Optional AIResponder for AI-powered responses
        _lock: Thread lock for responder management
    """

    def __init__(self, ai_responder=None):
        """Initialize the registry.

        Args:
            ai_responder: Optional AIResponder instance for AI-powered responses
        """
        self.responders: dict[str, ResponderBase] = {}
        self.ai_responder = ai_responder
        self._lock = threading.Lock()

    def register(self, responder: ResponderBase) -> None:
        """Register a responder.

        Args:
            responder: The responder to register
        """
        with self._lock:
            domain = responder.domain
            if domain in self.responders:
                logger.warning(
                    "Responder for domain '%s' already registered – replacing",
                    domain,
                )
            self.responders[domain] = responder
            logger.info("Registered responder: %s (domain=%s)", responder, domain)

    def unregister(self, domain: str) -> None:
        """Unregister a responder by domain.

        Args:
            domain: The domain of the responder to unregister
        """
        with self._lock:
            if domain in self.responders:
                del self.responders[domain]
                logger.info("Unregistered responder: %s", domain)

    def get_responder(self, path: str) -> ResponderBase | None:
        """Get the responder for a given path.

        Args:
            path: The URL path to match

        Returns:
            The matching responder, or None if no responder matches
        """
        with self._lock:
            for responder in self.responders.values():
                if responder.matches_path(path):
                    return responder
        return None

    def get_all_responders(self) -> list[ResponderBase]:
        """Get all registered responders.

        Returns:
            List of all ResponderBase instances
        """
        with self._lock:
            return list(self.responders.values())

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict | None = None,
    ) -> tuple[bytes, int] | None:
        """Generate a response using the appropriate responder.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag) or None if no responder matches
        """
        responder = self.get_responder(path)
        if responder:
            return responder.generate_response(
                path=path,
                raw_request=raw_request,
                bot_ip=bot_ip,
                headers=headers,
            )
        return None

    def get_bot_profiles(self, bot_ip: str) -> list[dict[str, Any]]:
        """Get all profiles for a given bot IP across all responders.

        Args:
            bot_ip: The bot's IP address

        Returns:
            List of profile dicts
        """
        profiles = []
        for responder in self.get_all_responders():
            profile = responder.get_profile(bot_ip)
            if profile:
                profiles.append(profile.to_dict())
        return profiles

    def clear_bot_profiles(self, bot_ip: str) -> None:
        """Clear all profiles for a given bot IP across all responders.

        Args:
            bot_ip: The bot's IP address
        """
        for responder in self.get_all_responders():
            responder.clear_profile(bot_ip)

    def get_stats(self) -> dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dict with registry stats
        """
        with self._lock:
            return {
                "total_responders": len(self.responders),
                "responders": {
                    domain: responder.get_stats()
                    for domain, responder in self.responders.items()
                },
            }

    def __repr__(self) -> str:
        return f"ResponderRegistry(responders={len(self.responders)})"
