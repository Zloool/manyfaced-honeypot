"""
BotProfile – per-bot state tracking and personalization.

Each bot that interacts with the honeypot gets a BotProfile that tracks:
- Request history (paths, methods, headers, timestamps)
- Detected vulnerability attempts (SQLi, LFI, RCE, etc.)
- Escalation level (how deep the bot has probed: 0=simple scan, 5=deep exploit)
- Personalized knowledge (what the bot already knows about the target)
- Response history (what the honeypot has already told this bot)

The profile is used to generate increasingly personalized responses that
adapt to the bot's behavior and encourage deeper exploitation.
"""

from __future__ import annotations

import datetime
import threading
from dataclasses import dataclass, field
from typing import Any


# ── Escalation levels ────────────────────────────────────────────────────────

class EscalationLevel:
    """Defines the stages of bot interaction depth."""
    IDLE = 0           # First contact, basic probe
    SCANNING = 1       # Enumerating paths/services
    PROBE = 2          # Testing specific vulnerabilities
    EXPLOIT_ATTEMPT = 3  # Active exploitation attempts
    COMPROMISE = 4     # Bot believes it has found something
    DEEP_EXPLOIT = 5   # Deep exploitation, post-exploitation


# ── BotProfile ────────────────────────────────────────────────────────────────

@dataclass
class BotProfile:
    """Tracks per-bot state for personalized response generation.

    Attributes:
        bot_ip: The bot's IP address
        created_at: When this profile was first created
        last_updated: Last interaction timestamp
        request_history: List of all requests made by this bot
        detected_behaviors: Set of detected attack patterns
        escalation_level: Current depth of exploitation (0-5)
        personalized_knowledge: What the bot 'knows' about the target
        response_history: Previous responses sent to this bot
        session_id: Unique session identifier
        _lock: Thread lock for thread safety
    """

    bot_ip: str
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    last_updated: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    request_history: list[dict[str, Any]] = field(default_factory=list)
    detected_behaviors: set[str] = field(default_factory=set)
    escalation_level: int = field(default=EscalationLevel.IDLE)
    personalized_knowledge: dict[str, Any] = field(default_factory=dict)
    response_history: list[dict[str, Any]] = field(default_factory=list)
    session_id: str = field(default_factory=lambda: _generate_session_id())
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def record_request(self, request: dict[str, Any]) -> None:
        """Record a request made by this bot.

        Args:
            request: Dict with keys: path, method, headers, timestamp
        """
        with self._lock:
            self.request_history.append(request)
            self.last_updated = datetime.datetime.utcnow()
            # Analyze request for behavior detection
            self._analyze_request(request)

    def _analyze_request(self, request: dict[str, Any]) -> None:
        """Analyze a request to detect attack patterns.

        Args:
            request: Request dict to analyze
        """
        path = request.get("path", "").lower()
        method = request.get("method", "GET").upper()
        headers = request.get("headers", {})
        raw = request.get("raw", "").lower()

        # Detect SQL injection patterns
        sqli_patterns = ["union", "select", "drop", "insert", "delete", "update",
                         "or 1=1", "and 1=1", "' or '", "sleep(", "benchmark(",
                         "or+1=1", "and+1=1", "or%201=1", "and%201=1",
                         "admin'--", "1=1--", "' or '1'='1"]
        for pattern in sqli_patterns:
            if pattern in path or pattern in raw:
                self.detected_behaviors.add("sql_injection")
                break

        # Detect LFI/RFI patterns
        lfi_patterns = ["../", "..\\", "/etc/passwd", "/etc/shadow",
                        "php://", "expect://", "data://"]
        for pattern in lfi_patterns:
            if pattern in path or pattern in raw:
                self.detected_behaviors.add("lfi_rfi")
                break

        # Detect RCE patterns
        rce_patterns = ["; ls", "| cat", "&& wget", "$(curl",
                        "`nc`", "eval(", "exec(",
                        "| cat ", "; cat ", "&& cat ",
                        "cat /etc", "wget http", "curl http"]
        for pattern in rce_patterns:
            if pattern in raw:
                self.detected_behaviors.add("rce")
                break

        # Detect directory traversal
        if path.count("..") >= 2:
            self.detected_behaviors.add("directory_traversal")

        # Detect credential stuffing
        if method == "POST" and any(kw in path for kw in ["login", "admin", "auth"]):
            self.detected_behaviors.add("credential_stuffing")

        # Detect enumeration
        enum_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/server-status",
                      "/.git", "/.env", "/config", "/backup"]
        if any(path.startswith(p) for p in enum_paths):
            self.detected_behaviors.add("enumeration")

        # Update escalation level based on detected behaviors
        self._update_escalation()

    def _update_escalation(self) -> None:
        """Update escalation level based on detected behaviors."""
        if "rce" in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, EscalationLevel.DEEP_EXPLOIT)
        elif "sql_injection" in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, EscalationLevel.EXPLOIT_ATTEMPT)
        elif "lfi_rfi" in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, EscalationLevel.EXPLOIT_ATTEMPT)
        elif "credential_stuffing" in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, EscalationLevel.EXPLOIT_ATTEMPT)
        elif "directory_traversal" in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, EscalationLevel.PROBE)
        elif "enumeration" in self.detected_behaviors:
            self.escalation_level = max(self.escalation_level, EscalationLevel.SCANNING)

    def record_response(self, response: dict[str, Any]) -> None:
        """Record a response sent to this bot.

        Args:
            response: Dict with keys: status_code, body, content_type, timestamp
        """
        with self._lock:
            self.response_history.append(response)
            self.last_updated = datetime.datetime.utcnow()

    def get_personalization_context(self) -> dict[str, Any]:
        """Get context for personalized response generation.

        Returns:
            Dict containing bot-specific context for the AI prompt
        """
        with self._lock:
            return {
                "bot_ip": self.bot_ip,
                "session_id": self.session_id,
                "escalation_level": self.escalation_level,
                "escalation_label": self._escalation_label(),
                "detected_behaviors": list(self.detected_behaviors),
                "request_count": len(self.request_history),
                "last_request": self.request_history[-1] if self.request_history else None,
                "known_services": self.personalized_knowledge.get("known_services", []),
                "explored_paths": [r.get("path", "") for r in self.request_history],
                "bot_personality": self._derive_bot_personality(),
                "response_count": len(self.response_history),
            }

    def _escalation_label(self) -> str:
        """Get human-readable escalation label."""
        labels = {
            EscalationLevel.IDLE: "idle",
            EscalationLevel.SCANNING: "scanning",
            EscalationLevel.PROBE: "probing",
            EscalationLevel.EXPLOIT_ATTEMPT: "exploiting",
            EscalationLevel.COMPROMISE: "compromised",
            EscalationLevel.DEEP_EXPLOIT: "deep_exploiting",
        }
        return labels.get(self.escalation_level, "unknown")

    def _derive_bot_personality(self) -> str:
        """Derive a personality description based on detected behaviors."""
        if not self.detected_behaviors:
            return "generic scanner"

        personality_parts = []
        if "sql_injection" in self.detected_behaviors:
            personality_parts.append("SQLi expert")
        if "rce" in self.detected_behaviors:
            personality_parts.append("RCE specialist")
        if "lfi_rfi" in self.detected_behaviors:
            personality_parts.append("file inclusion specialist")
        if "credential_stuffing" in self.detected_behaviors:
            personality_parts.append("credential harvester")
        if "directory_traversal" in self.detected_behaviors:
            personality_parts.append("directory traversal expert")
        if "enumeration" in self.detected_behaviors:
            personality_parts.append("service enumerater")

        if personality_parts:
            return f"advanced {', '.join(personality_parts)} bot"
        return "automated scanner"

    def update_knowledge(self, new_info: dict[str, Any]) -> None:
        """Update bot's knowledge based on previous interactions.

        Args:
            new_info: Dict of knowledge to add/update
        """
        with self._lock:
            for key, value in new_info.items():
                if key in self.personalized_knowledge:
                    if isinstance(self.personalized_knowledge[key], list):
                        if isinstance(value, list):
                            # Extend list with new values
                            for v in value:
                                if v not in self.personalized_knowledge[key]:
                                    self.personalized_knowledge[key].append(v)
                        elif value not in self.personalized_knowledge[key]:
                            self.personalized_knowledge[key].append(value)
                    else:
                        self.personalized_knowledge[key] = value
                else:
                    self.personalized_knowledge[key] = value

    def to_dict(self) -> dict[str, Any]:
        """Serialize profile to dict (for logging/debugging)."""
        with self._lock:
            return {
                "bot_ip": self.bot_ip,
                "session_id": self.session_id,
                "escalation_level": self.escalation_level,
                "detected_behaviors": list(self.detected_behaviors),
                "request_count": len(self.request_history),
                "response_count": len(self.response_history),
                "known_services": self.personalized_knowledge.get("known_services", []),
                "created_at": str(self.created_at),
                "last_updated": str(self.last_updated),
            }

    def __repr__(self) -> str:
        return (
            f"BotProfile(bot_ip={self.bot_ip!r}, session={self.session_id!r}, "
            f"level={self.escalation_label}, behaviors={len(self.detected_behaviors)})"
        )


def _generate_session_id() -> str:
    """Generate a unique session ID."""
    import hashlib
    import secrets
    return hashlib.sha256(secrets.token_bytes(16)).hexdigest()[:16]
