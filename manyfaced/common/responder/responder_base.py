"""
Base Responder class – interface for modular responders.

All responder modules inherit from this base class and implement:
- generate_response(): Generate an HTTP response for a given request
- update_after_interaction(): Update based on bot's previous interactions
- get_response_template(): Return the response template/context

The base class handles:
- Bot profile management (create, update, retrieve)
- AI prompt generation with personalization
- Fallback to static responses
- Thread safety
"""

from __future__ import annotations

import abc
import threading
from typing import Any

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.responder.bot_profile import BotProfile

logger = get_logger(__name__)


class ResponderBase(abc.ABC):
    """Abstract base class for modular responders.

    Each responder handles a specific service/domain (e.g., phpMyAdmin, WordPress).
    Responders are thread-safe and maintain per-bot profiles.

    Attributes:
        domain: The service domain this responder handles (e.g., "phpmyadmin")
        bot_profiles: Dict of bot_ip -> BotProfile
        _lock: Thread lock for profile management
        ai_responder: Optional AIResponder for AI-powered responses
        enabled: Whether this responder is active
    """

    # Class-level domain identifier – must be set by subclasses
    domain: str = "base"

    def __init__(
        self,
        ai_responder=None,
        enabled: bool = True,
    ):
        """Initialize the responder.

        Args:
            ai_responder: Optional AIResponder instance for AI-powered responses
            enabled: Whether this responder is active
        """
        self.ai_responder = ai_responder
        self.enabled = enabled
        self.bot_profiles: dict[str, BotProfile] = {}
        self._lock = threading.RLock()
        self._response_count: int = 0

    @abc.abstractmethod
    def matches_path(self, path: str) -> bool:
        """Check if this responder should handle the given path.

        Args:
            path: The URL path from the bot's request

        Returns:
            True if this responder should handle the request
        """

    @abc.abstractmethod
    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict | None = None,
    ) -> tuple[bytes, int]:
        """Generate an HTTP response for the given request.

        This method is called for each incoming bot request. It should:
        1. Get or create the bot's profile
        2. Record the request in the profile
        3. Generate a response (AI-powered or static)
        4. Record the response in the profile

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag)
        """

    @abc.abstractmethod
    def get_response_template(self) -> str:
        """Return the response template/prompt for AI generation.

        Returns:
            Template string with placeholders for personalization
        """

    def get_or_create_profile(self, bot_ip: str) -> BotProfile:
        """Get existing profile or create a new one for the bot.

        Args:
            bot_ip: The bot's IP address

        Returns:
            BotProfile for the given IP
        """
        with self._lock:
            if bot_ip not in self.bot_profiles:
                profile = BotProfile(bot_ip=bot_ip)
                self.bot_profiles[bot_ip] = profile
                logger.info(
                    "Created new BotProfile for %s (session=%s)",
                    bot_ip,
                    profile.session_id,
                )
            return self.bot_profiles[bot_ip]

    def update_after_interaction(
        self,
        bot_ip: str,
        request: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        """Update the bot's profile after an interaction.

        Args:
            bot_ip: The bot's IP address
            request: Request dict
            response: Response dict
        """
        with self._lock:
            profile = self.get_or_create_profile(bot_ip)
            profile.record_request(request)
            profile.record_response(response)
            self._response_count += 1

    def get_profile(self, bot_ip: str) -> BotProfile | None:
        """Get the bot's profile, or None if not found.

        Args:
            bot_ip: The bot's IP address

        Returns:
            BotProfile or None
        """
        with self._lock:
            return self.bot_profiles.get(bot_ip)

    def get_all_profiles(self) -> list[BotProfile]:
        """Get all bot profiles.

        Returns:
            List of all BotProfile instances
        """
        with self._lock:
            return list(self.bot_profiles.values())

    def clear_profile(self, bot_ip: str) -> None:
        """Clear a bot's profile (for session reset).

        Args:
            bot_ip: The bot's IP address
        """
        with self._lock:
            if bot_ip in self.bot_profiles:
                del self.bot_profiles[bot_ip]
                logger.info("Cleared profile for %s", bot_ip)

    def _try_ai_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict | None = None,
    ) -> tuple[bytes, int] | None:
        """Try to generate an AI-powered response.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag) or None if AI unavailable
        """
        if not self.ai_responder or not self.ai_responder.is_available():
            return None

        try:
            profile = self.get_or_create_profile(bot_ip)
            context = profile.get_personalization_context()

            # Build personalized prompt
            prompt = self._build_personalized_prompt(path, raw_request, context)

            response_text = self.ai_responder.generate_response(
                request_path=path,
                raw_request=raw_request,
                bot_ip=bot_ip,
                known_face=self.domain,
            )

            return response_text, 1

        except Exception as e:
            logger.warning("AI response failed for %s %s: %s", bot_ip, path, e)
            return None

    def _build_personalized_prompt(
        self,
        path: str,
        raw_request: str,
        context: dict[str, Any],
    ) -> str:
        """Build a personalized AI prompt using the bot's profile context.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            context: Personalization context from BotProfile

        Returns:
            Formatted prompt string
        """
        template = self.get_response_template()
        return template.format(
            path=path,
            raw_request=raw_request[:2000],
            bot_ip=context["bot_ip"],
            escalation_level=context["escalation_level"],
            escalation_label=context["escalation_label"],
            detected_behaviors=", ".join(context["detected_behaviors"]) or "none",
            request_count=context["request_count"],
            bot_personality=context["bot_personality"],
            response_count=context["response_count"],
            explored_paths=", ".join(context["explored_paths"][-5:]) or "none",
        )

    def get_stats(self) -> dict[str, Any]:
        """Get responder statistics.

        Returns:
            Dict with responder stats
        """
        with self._lock:
            return {
                "domain": self.domain,
                "enabled": self.enabled,
                "active_profiles": len(self.bot_profiles),
                "total_responses": self._response_count,
                "profiles": {
                    ip: profile.to_dict()
                    for ip, profile in self.bot_profiles.items()
                },
            }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(domain={self.domain!r}, enabled={self.enabled})"
