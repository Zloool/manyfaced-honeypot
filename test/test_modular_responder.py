"""
Comprehensive tests for the modular responder system.

Tests cover:
- BotProfile: per-bot state tracking and personalization
- ResponderBase: abstract base class behavior
- PhpMyAdminResponder: domain-specific responder
- WordPressResponder: domain-specific responder
- WebDAVResponder: domain-specific responder
- ResponderRegistry: routing and management
- Integration: full pipeline with AI responder
"""

import os
import sys
from unittest.mock import MagicMock


# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip before any handler module is imported
_geoip_mock = MagicMock()
_geoip_mock.geolite2.geolite2 = _geoip_mock.geolite2
sys.modules["geoip"] = _geoip_mock
sys.modules["geoip.geolite2"] = _geoip_mock.geolite2
sys.modules["GeoIP"] = MagicMock()


# ---------------------------------------------------------------------------
# BotProfile Tests
# ---------------------------------------------------------------------------


class TestBotProfileCreation:
    """Tests for BotProfile creation and initialization."""

    def test_create_profile(self):
        """BotProfile should be created with correct attributes."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        assert profile.bot_ip == "1.2.3.4"
        assert profile.session_id is not None
        assert profile.escalation_level == 0
        assert profile.request_history == []
        assert profile.response_history == []
        assert profile.detected_behaviors == set()

    def test_profile_has_unique_session_id(self):
        """Each profile should have a unique session ID."""
        from manyfaced.common.responder import BotProfile

        profile1 = BotProfile(bot_ip="1.2.3.4")
        profile2 = BotProfile(bot_ip="1.2.3.4")
        assert profile1.session_id != profile2.session_id


class TestBotProfileRequestRecording:
    """Tests for request recording and analysis."""

    def test_record_request(self):
        """record_request() should add request to history."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/admin.php",
            "method": "GET",
            "headers": {"Host": "example.com"},
            "raw": "GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert len(profile.request_history) == 1
        assert profile.request_history[0]["path"] == "/admin.php"
        assert profile.last_updated is not None

    def test_detect_sql_injection(self):
        """Should detect SQL injection patterns."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/search?q=1'+OR+1=1--",
            "method": "GET",
            "headers": {},
            "raw": "GET /search?q=1'+OR+1=1-- HTTP/1.1\r\n\r\n",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert "sql_injection" in profile.detected_behaviors

    def test_detect_lfi(self):
        """Should detect LFI patterns."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/page?file=../../../../etc/passwd",
            "method": "GET",
            "headers": {},
            "raw": "GET /page?file=../../../../etc/passwd HTTP/1.1\r\n\r\n",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert "lfi_rfi" in profile.detected_behaviors

    def test_detect_rce(self):
        """Should detect RCE patterns."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/cmd",
            "method": "POST",
            "headers": {},
            "raw": "POST /cmd HTTP/1.1\r\n\r\ncat /etc/passwd",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert "rce" in profile.detected_behaviors

    def test_detect_directory_traversal(self):
        """Should detect directory traversal patterns."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/../../../../../../etc/shadow",
            "method": "GET",
            "headers": {},
            "raw": "GET /../../../../../../etc/shadow HTTP/1.1\r\n\r\n",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert "directory_traversal" in profile.detected_behaviors

    def test_detect_enum(self):
        """Should detect enumeration patterns."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/admin/",
            "method": "GET",
            "headers": {},
            "raw": "GET /admin/ HTTP/1.1\r\n\r\n",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert "enumeration" in profile.detected_behaviors


class TestBotProfileEscalation:
    """Tests for escalation level updates."""

    def test_escalation_on_rce(self):
        """Escalation should increase on RCE detection."""
        from manyfaced.common.responder import BotProfile, EscalationLevel

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/cmd",
            "method": "POST",
            "headers": {},
            "raw": "POST /cmd HTTP/1.1\r\n\r\ncat /etc/passwd",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert profile.escalation_level >= EscalationLevel.DEEP_EXPLOIT

    def test_escalation_on_sqli(self):
        """Escalation should increase on SQLi detection."""
        from manyfaced.common.responder import BotProfile, EscalationLevel

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/login?user=admin'--",
            "method": "POST",
            "headers": {},
            "raw": "POST /login HTTP/1.1\r\n\r\nuser=admin'--",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert profile.escalation_level >= EscalationLevel.EXPLOIT_ATTEMPT

    def test_escalation_on_enum(self):
        """Escalation should increase on enumeration detection."""
        from manyfaced.common.responder import BotProfile, EscalationLevel

        profile = BotProfile(bot_ip="1.2.3.4")
        request = {
            "path": "/admin/",
            "method": "GET",
            "headers": {},
            "raw": "GET /admin/ HTTP/1.1\r\n\r\n",
            "timestamp": "2026-04-21T10:00:00",
        }
        profile.record_request(request)

        assert profile.escalation_level >= EscalationLevel.SCANNING


class TestBotProfilePersonalization:
    """Tests for personalization context generation."""

    def test_get_personalization_context(self):
        """get_personalization_context() should return context dict."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        profile.record_request(
            {
                "path": "/admin/",
                "method": "GET",
                "headers": {},
                "raw": "GET /admin/ HTTP/1.1\r\n\r\n",
                "timestamp": "2026-04-21T10:00:00",
            }
        )
        profile.record_response(
            {
                "status_code": 200,
                "body": "<html>",
                "content_type": "text/html",
                "timestamp": "2026-04-21T10:00:01",
            }
        )

        context = profile.get_personalization_context()

        assert context["bot_ip"] == "1.2.3.4"
        assert context["session_id"] == profile.session_id
        assert context["escalation_level"] >= 1
        assert context["escalation_label"] in ["scanning", "probing", "exploiting"]
        assert context["request_count"] == 1
        assert context["response_count"] == 1
        assert "enumeration" in context["detected_behaviors"]


class TestBotProfileUpdateKnowledge:
    """Tests for knowledge updates."""

    def test_update_knowledge(self):
        """update_knowledge() should merge new info."""
        from manyfaced.common.responder import BotProfile

        profile = BotProfile(bot_ip="1.2.3.4")
        profile.update_knowledge({"known_services": ["phpmyadmin"]})
        assert profile.personalized_knowledge["known_services"] == ["phpmyadmin"]

        profile.update_knowledge({"known_services": ["wordpress"]})
        assert profile.personalized_knowledge["known_services"] == [
            "phpmyadmin",
            "wordpress",
        ]


# ---------------------------------------------------------------------------
# PhpMyAdminResponder Tests
# ---------------------------------------------------------------------------


class TestPhpMyAdminResponder:
    """Tests for PhpMyAdminResponder."""

    def test_matches_phpmyadmin_paths(self):
        """Should match phpMyAdmin paths."""
        from manyfaced.common.responder import PhpMyAdminResponder

        responder = PhpMyAdminResponder()
        assert responder.matches_path("/phpmyadmin/")
        assert responder.matches_path("/pma/")
        assert responder.matches_path("/mysql/")
        assert responder.matches_path("/db/")

    def test_does_not_match_other_paths(self):
        """Should not match non-phpMyAdmin paths."""
        from manyfaced.common.responder import PhpMyAdminResponder

        responder = PhpMyAdminResponder()
        assert not responder.matches_path("/wp-login.php")
        assert not responder.matches_path("/admin.php")
        assert not responder.matches_path("/")

    def test_generate_response(self):
        """generate_response() should return bytes and detected flag."""
        from manyfaced.common.responder import PhpMyAdminResponder

        responder = PhpMyAdminResponder()
        response_bytes, detected = responder.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert isinstance(response_bytes, bytes)
        assert detected == 1
        assert b"HTTP/1.1" in response_bytes
        assert b"phpMyAdmin" in response_bytes

    def test_generate_response_records_profile(self):
        """generate_response() should record request in profile."""
        from manyfaced.common.responder import PhpMyAdminResponder

        responder = PhpMyAdminResponder()
        responder.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        profile = responder.get_profile("1.2.3.4")
        assert profile is not None
        assert len(profile.request_history) == 1
        assert len(profile.response_history) == 1

    def test_disabled_responder(self):
        """Disabled responder should return static response."""
        from manyfaced.common.responder import PhpMyAdminResponder

        responder = PhpMyAdminResponder(enabled=False)
        response_bytes, detected = responder.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert isinstance(response_bytes, bytes)
        assert detected == 1

    def test_get_stats(self):
        """get_stats() should return stats dict."""
        from manyfaced.common.responder import PhpMyAdminResponder

        responder = PhpMyAdminResponder()
        responder.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        stats = responder.get_stats()
        assert stats["domain"] == "phpmyadmin"
        assert stats["enabled"] is True
        assert stats["active_profiles"] == 1
        assert stats["total_responses"] == 1


# ---------------------------------------------------------------------------
# WordPressResponder Tests
# ---------------------------------------------------------------------------


class TestWordPressResponder:
    """Tests for WordPressResponder."""

    def test_matches_wordpress_paths(self):
        """Should match WordPress paths."""
        from manyfaced.common.responder import WordPressResponder

        responder = WordPressResponder()
        assert responder.matches_path("/wp-login.php")
        assert responder.matches_path("/wp-admin/")
        assert responder.matches_path("/wp-content/")
        assert responder.matches_path("/xmlrpc.php")

    def test_does_not_match_other_paths(self):
        """Should not match non-WordPress paths."""
        from manyfaced.common.responder import WordPressResponder

        responder = WordPressResponder()
        assert not responder.matches_path("/phpmyadmin/")
        assert not responder.matches_path("/admin.php")
        assert not responder.matches_path("/")

    def test_generate_response(self):
        """generate_response() should return bytes and detected flag."""
        from manyfaced.common.responder import WordPressResponder

        responder = WordPressResponder()
        response_bytes, detected = responder.generate_response(
            path="/wp-login.php",
            raw_request="GET /wp-login.php HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert isinstance(response_bytes, bytes)
        assert detected == 1
        assert b"HTTP/1.1" in response_bytes
        assert b"WordPress" in response_bytes

    def test_generate_xmlrpc_response(self):
        """Should generate XML-RPC response for xmlrpc.php."""
        from manyfaced.common.responder import WordPressResponder

        responder = WordPressResponder()
        response_bytes, detected = responder.generate_response(
            path="/xmlrpc.php",
            raw_request="POST /xmlrpc.php HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert isinstance(response_bytes, bytes)
        assert b"xmlrpc" in response_bytes.lower()


# ---------------------------------------------------------------------------
# WebDAVResponder Tests
# ---------------------------------------------------------------------------


class TestWebDAVResponder:
    """Tests for WebDAVResponder."""

    def test_matches_webdav_paths(self):
        """Should match WebDAV paths."""
        from manyfaced.common.responder import WebDAVResponder

        responder = WebDAVResponder()
        assert responder.matches_path("/webdav/")
        assert responder.matches_path("/dav/")
        assert responder.matches_path("/files/")

    def test_does_not_match_other_paths(self):
        """Should not match non-WebDAV paths."""
        from manyfaced.common.responder import WebDAVResponder

        responder = WebDAVResponder()
        assert not responder.matches_path("/wp-login.php")
        assert not responder.matches_path("/phpmyadmin/")
        assert not responder.matches_path("/")

    def test_generate_propfind_response(self):
        """Should generate PROPFIND response."""
        from manyfaced.common.responder import WebDAVResponder

        responder = WebDAVResponder()
        response_bytes, detected = responder.generate_response(
            path="/webdav/",
            raw_request="PROPFIND /webdav/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert isinstance(response_bytes, bytes)
        assert detected == 1
        assert b"HTTP/1.1" in response_bytes
        assert b"multistatus" in response_bytes.lower()
        assert b"DAV:" in response_bytes

    def test_generate_options_response(self):
        """Should generate OPTIONS response."""
        from manyfaced.common.responder import WebDAVResponder

        responder = WebDAVResponder()
        response_bytes, detected = responder.generate_response(
            path="/webdav/",
            raw_request="OPTIONS /webdav/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert isinstance(response_bytes, bytes)
        assert detected == 1
        assert b"HTTP/1.1 200 OK" in response_bytes


# ---------------------------------------------------------------------------
# ResponderRegistry Tests
# ---------------------------------------------------------------------------


class TestResponderRegistry:
    """Tests for ResponderRegistry."""

    def test_register_and_get_responder(self):
        """Should register and retrieve responders."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
            WordPressResponder,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())
        registry.register(WordPressResponder())

        pma_responder = registry.get_responder("/phpmyadmin/")
        wp_responder = registry.get_responder("/wp-login.php")

        assert pma_responder is not None
        assert isinstance(pma_responder, PhpMyAdminResponder)
        assert wp_responder is not None
        assert isinstance(wp_responder, WordPressResponder)

    def test_get_responder_returns_none_for_unmatched_path(self):
        """Should return None for unmatched paths."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        result = registry.get_responder("/admin.php")
        assert result is None

    def test_generate_response_delegates_to_responder(self):
        """generate_response() should delegate to matching responder."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        response_bytes, detected = registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert response_bytes is not None
        assert detected == 1

    def test_generate_response_returns_none_for_unmatched_path(self):
        """generate_response() should return None for unmatched paths."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        result = registry.generate_response(
            path="/admin.php",
            raw_request="GET /admin.php HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert result is None

    def test_unregister_responder(self):
        """Should unregister responders."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())
        assert registry.get_responder("/phpmyadmin/") is not None

        registry.unregister("phpmyadmin")
        assert registry.get_responder("/phpmyadmin/") is None

    def test_get_bot_profiles(self):
        """get_bot_profiles() should return profiles across all responders."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
            WordPressResponder,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())
        registry.register(WordPressResponder())

        # Generate responses to create profiles
        registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        registry.generate_response(
            path="/wp-login.php",
            raw_request="GET /wp-login.php HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        profiles = registry.get_bot_profiles("1.2.3.4")
        assert len(profiles) == 2

    def test_clear_bot_profiles(self):
        """clear_bot_profiles() should clear profiles across all responders."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        # Generate response to create profile
        registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert len(registry.get_bot_profiles("1.2.3.4")) == 1

        # Clear profile
        registry.clear_bot_profiles("1.2.3.4")
        assert len(registry.get_bot_profiles("1.2.3.4")) == 0

    def test_get_stats(self):
        """get_stats() should return registry stats."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        stats = registry.get_stats()
        assert stats["total_responders"] == 1
        assert "phpmyadmin" in stats["responders"]


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestModularResponderIntegration:
    """Tests for full integration of modular responder system."""

    def test_full_pipeline_with_registry(self):
        """Full pipeline: request -> registry -> responder -> response."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        # First request
        response1, detected1 = registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert detected1 == 1

        # Second request (same bot, different path)
        response2, detected2 = registry.generate_response(
            path="/phpmyadmin/index.php",
            raw_request="GET /phpmyadmin/index.php HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )
        assert detected2 == 1

        # Profile should have 2 requests and 2 responses
        profile = registry.get_bot_profiles("1.2.3.4")[0]
        assert profile["request_count"] == 2
        assert profile["response_count"] == 2

    def test_multiple_bots_are_isolated(self):
        """Profiles should be isolated per bot IP."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        # Bot 1
        registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        # Bot 2
        registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="5.6.7.8",
        )

        profiles_1 = registry.get_bot_profiles("1.2.3.4")
        profiles_2 = registry.get_bot_profiles("5.6.7.8")

        assert len(profiles_1) == 1
        assert len(profiles_2) == 1
        assert profiles_1[0]["bot_ip"] == "1.2.3.4"
        assert profiles_2[0]["bot_ip"] == "5.6.7.8"

    def test_escalation_accumulates_across_requests(self):
        """Escalation level should accumulate across requests."""
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        # Simple scan
        registry.generate_response(
            path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        profile = registry.get_bot_profiles("1.2.3.4")[0]
        initial_level = profile["escalation_level"]

        # SQL injection attempt
        registry.generate_response(
            path="/phpmyadmin/sql.php?query=1'+OR+1=1--",
            raw_request="GET /phpmyadmin/sql.php?query=1'+OR+1=1-- HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        profile = registry.get_bot_profiles("1.2.3.4")[0]
        assert profile["escalation_level"] >= initial_level
        assert "sql_injection" in profile["detected_behaviors"]

    def test_registry_with_ai_responder(self):
        """AIResponder should delegate to ResponderRegistry."""
        from manyfaced.common.ai_responder import AIResponder
        from manyfaced.common.responder import (
            PhpMyAdminResponder,
            ResponderRegistry,
        )

        registry = ResponderRegistry()
        registry.register(PhpMyAdminResponder())

        # Create AIResponder with registry (but without LLM)
        ai = AIResponder(registry=registry)
        ai._initialized = True
        ai._available = True

        # Should delegate to registry
        response_bytes, detected = ai.generate_response(
            request_path="/phpmyadmin/",
            raw_request="GET /phpmyadmin/ HTTP/1.1\r\n\r\n",
            bot_ip="1.2.3.4",
        )

        assert response_bytes is not None
        assert detected == 1
        assert b"phpMyAdmin" in response_bytes
