"""
Modular responder system for manyfaced honeypot.

Provides:
- BotProfile: Per-bot state tracking and personalization
- ResponderBase: Abstract base class for responders
- ResponderRegistry: Manages and routes to responders
- Individual responder modules (phpmyadmin, wordpress, webdav, etc.)

Usage:
    from manyfaced.common.responder import ResponderRegistry

    registry = ResponderRegistry(ai_responder=ai_responder)
    registry.register_phpmyadmin()
    registry.register_wordpress()
    registry.register_webdav()

    # Get responder for a path
    responder = registry.get_responder("/phpmyadmin/")
    if responder:
        response_bytes, detected = responder.generate_response(
            path="/phpmyadmin/",
            raw_request="...",
            bot_ip="1.2.3.4",
        )
"""

from manyfaced.common.responder.bot_profile import BotProfile, EscalationLevel
from manyfaced.common.responder.phpmyadmin_responder import PhpMyAdminResponder
from manyfaced.common.responder.registry import ResponderRegistry
from manyfaced.common.responder.responder_base import ResponderBase
from manyfaced.common.responder.wordpress_responder import WordPressResponder
from manyfaced.common.responder.webdav_responder import WebDAVResponder

__all__ = [
    "BotProfile",
    "EscalationLevel",
    "PhpMyAdminResponder",
    "ResponderBase",
    "ResponderRegistry",
    "WordPressResponder",
    "WebDAVResponder",
]
