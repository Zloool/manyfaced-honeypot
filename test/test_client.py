"""Tests for the client-side HTTP handler system.

Tests the new handler registry architecture:
- WordPressHandler, PhpMyAdminHandler, JenkinsHandler, etc.
- GenericHandler (monster page for unknown paths)
- BotProfile tracking
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.common.httphandler import HTTPRequest
from manyfaced.handlers import (
    WordPressHandler,
    PhpMyAdminHandler,
    JenkinsHandler,
    TomcatHandler,
    DrupalHandler,
    CPanelHandler,
    GenericHandler,
    HandlerRegistry,
    BotProfile,
)


class TestBotProfile(unittest.TestCase):
    """Test BotProfile state tracking."""

    def test_create_profile(self):
        profile = BotProfile("1.2.3.4")
        self.assertEqual(profile.bot_ip, "1.2.3.4")
        self.assertIsNotNone(profile.session_id)
        self.assertEqual(profile.escalation_level, BotProfile.IDLE)
        self.assertEqual(len(profile.request_history), 0)

    def test_record_request(self):
        profile = BotProfile("1.2.3.4")
        profile.record_request({"path": "/wp-login.php", "method": "GET"})
        self.assertEqual(len(profile.request_history), 1)

    def test_credential_capture(self):
        profile = BotProfile("1.2.3.4")
        profile.capture_credentials({"username": "admin", "password": "secret"})
        self.assertEqual(len(profile.captured_credentials), 1)
        self.assertEqual(profile.captured_credentials[0]["username"], "admin")
        self.assertIn("credential_stuffing", profile.detected_behaviors)

    def test_escalation_on_exploit(self):
        profile = BotProfile("1.2.3.4")
        profile.record_request({
            "path": "/admin?or+1=1",
            "method": "GET",
            "raw": "GET /admin?or+1=1 HTTP/1.1",
        })
        self.assertIn("sql_injection", profile.detected_behaviors)
        self.assertGreater(profile.escalation_level, BotProfile.IDLE)

    def test_get_stats(self):
        profile = BotProfile("1.2.3.4")
        profile.record_request({"path": "/test", "method": "GET"})
        stats = profile.get_stats()
        self.assertEqual(stats["bot_ip"], "1.2.3.4")
        self.assertEqual(stats["request_count"], 1)
        self.assertIn("session_id", stats)


class TestWordPressHandler(unittest.TestCase):
    """Test WordPressHandler responses."""

    def setUp(self):
        self.handler = WordPressHandler()

    def test_matches_path(self):
        self.assertTrue(self.handler.matches_path("/wp-login.php"))
        self.assertTrue(self.handler.matches_path("/wp-admin/"))
        self.assertTrue(self.handler.matches_path("/wp-content/"))
        self.assertFalse(self.handler.matches_path("/phpmyadmin/"))

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, detected = self.handler.generate_response(
            "/wp-login.php",
            "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"WordPress", response)
        self.assertIn(b"wp-login.php", response)
        self.assertIn(b"Log In", response)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, detected = self.handler.generate_response(
            "/wp-login.php",
            "POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nlog=admin&pwd=secret123",
            "1.2.3.4",
        )
        # Should return login failed response (encourages brute force)
        self.assertIn(b"ERROR", response)
        self.assertIn(b"Invalid username", response)

    def test_admin_redirect(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/wp-admin/",
            "GET /wp-admin/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"wp-login.php", response)

    def test_xmlrpc_response(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/xmlrpc.php",
            "POST /xmlrpc.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"XML-RPC", response)


class TestPhpMyAdminHandler(unittest.TestCase):
    """Test PhpMyAdminHandler responses."""

    def setUp(self):
        self.handler = PhpMyAdminHandler()

    def test_matches_path(self):
        self.assertTrue(self.handler.matches_path("/phpmyadmin/"))
        self.assertTrue(self.handler.matches_path("/pma/"))
        self.assertFalse(self.handler.matches_path("/wp-login.php"))

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/phpmyadmin/",
            "GET /phpmyadmin/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"phpMyAdmin", response)
        self.assertIn(b"pma_username", response)
        self.assertIn(b"pma_password", response)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/phpmyadmin/index.php",
            "POST /phpmyadmin/index.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nserver=0&pma_username=root&pma_password=admin",
            "1.2.3.4",
        )
        self.assertIn(b"Access denied", response)


class TestJenkinsHandler(unittest.TestCase):
    """Test JenkinsHandler responses."""

    def setUp(self):
        self.handler = JenkinsHandler()

    def test_matches_path(self):
        self.assertTrue(self.handler.matches_path("/jenkins/"))
        self.assertTrue(self.handler.matches_path("/jenkins/login"))
        self.assertFalse(self.handler.matches_path("/wp-login.php"))

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/jenkins/login",
            "GET /jenkins/login HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"Jenkins", response)
        self.assertIn(b"j_username", response)
        self.assertIn(b"j_password", response)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/jenkins/",
            "GET /jenkins/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"Jenkins", response)
        self.assertIn(b"build-app", response)


class TestTomcatHandler(unittest.TestCase):
    """Test TomcatHandler responses."""

    def setUp(self):
        self.handler = TomcatHandler()

    def test_matches_path(self):
        self.assertTrue(self.handler.matches_path("/manager/html"))
        self.assertTrue(self.handler.matches_path("/host-manager/"))
        self.assertFalse(self.handler.matches_path("/wp-login.php"))

    def test_manager_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/manager/html",
            "GET /manager/html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"Tomcat", response)
        self.assertIn(b"Manager", response)


class TestDrupalHandler(unittest.TestCase):
    """Test DrupalHandler responses."""

    def setUp(self):
        self.handler = DrupalHandler()

    def test_matches_path(self):
        self.assertTrue(self.handler.matches_path("/user/login"))
        self.assertTrue(self.handler.matches_path("/admin"))
        self.assertFalse(self.handler.matches_path("/wp-login.php"))

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/user/login",
            "GET /user/login HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"Drupal", response)
        self.assertIn(b"edit-name", response)
        self.assertIn(b"edit-pass", response)


class TestCPanelHandler(unittest.TestCase):
    """Test CPanelHandler responses."""

    def setUp(self):
        self.handler = CPanelHandler()

    def test_matches_path(self):
        self.assertTrue(self.handler.matches_path("/cpanel/"))
        self.assertTrue(self.handler.matches_path("/whm/"))
        self.assertTrue(self.handler.matches_path("/webmail/"))
        self.assertFalse(self.handler.matches_path("/wp-login.php"))

    def test_cpanel_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/cpanel/",
            "GET /cpanel/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"cPanel", response)
        self.assertIn(b"Login", response)


class TestGenericHandler(unittest.TestCase):
    """Test GenericHandler (monster page) responses."""

    def setUp(self):
        self.handler = GenericHandler()

    def test_matches_all_paths(self):
        self.assertTrue(self.handler.matches_path("/anything"))
        self.assertTrue(self.handler.matches_path("/wp-login.php"))
        self.assertTrue(self.handler.matches_path("/"))

    def test_monster_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/random-path",
            "GET /random-path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"Server Administration Panel", response)
        self.assertIn(b"WordPress", response)
        self.assertIn(b"phpMyAdmin", response)
        self.assertIn(b"Jenkins", response)

    def test_traversal_error(self):
        profile = MagicMock()
        self.handler.bot_profiles = {"1.2.3.4": profile}
        response, _ = self.handler.generate_response(
            "/../../etc/passwd",
            "GET /../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIn(b"403", response)
        self.assertIn(b"Forbidden", response)


class TestHandlerRegistry(unittest.TestCase):
    """Test HandlerRegistry routing."""

    def setUp(self):
        self.registry = HandlerRegistry()
        self.registry.register(WordPressHandler())
        self.registry.register(PhpMyAdminHandler())
        self.registry.register(JenkinsHandler())
        self.registry.register(TomcatHandler())
        self.registry.register(DrupalHandler())
        self.registry.register(CPanelHandler())
        self.registry.register(GenericHandler())

    def test_get_handler_wordpress(self):
        handler = self.registry.get_handler("/wp-login.php")
        self.assertIsInstance(handler, WordPressHandler)

    def test_get_handler_phpmyadmin(self):
        handler = self.registry.get_handler("/phpmyadmin/")
        self.assertIsInstance(handler, PhpMyAdminHandler)

    def test_get_handler_jenkins(self):
        handler = self.registry.get_handler("/jenkins/")
        self.assertIsInstance(handler, JenkinsHandler)

    def test_get_handler_tomcat(self):
        handler = self.registry.get_handler("/manager/html")
        self.assertIsInstance(handler, TomcatHandler)

    def test_get_handler_drupal(self):
        handler = self.registry.get_handler("/user/login")
        self.assertIsInstance(handler, DrupalHandler)

    def test_get_handler_cpanel(self):
        handler = self.registry.get_handler("/cpanel/")
        self.assertIsInstance(handler, CPanelHandler)

    def test_get_handler_generic_fallback(self):
        handler = self.registry.get_handler("/random-path")
        self.assertIsInstance(handler, GenericHandler)

    def test_generate_response(self):
        result = self.registry.generate_response(
            "/wp-login.php",
            "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIsNotNone(result)
        response_bytes, detected = result
        self.assertIn(b"WordPress", response_bytes)

    def test_get_all_handlers(self):
        handlers = self.registry.get_all_handlers()
        self.assertEqual(len(handlers), 7)

    def test_stats(self):
        stats = self.registry.get_stats()
        self.assertEqual(stats["total_handlers"], 7)
        self.assertIn("handlers", stats)

    def test_get_all_matching_handlers(self):
        """Test that get_all_matching_handlers returns all matching handlers."""
        # /xmlrpc.php matches both WordPress and Drupal
        matching = self.registry.get_all_matching_handlers("/xmlrpc.php")
        matching_domains = [h.domain for h in matching]
        self.assertIn("wordpress", matching_domains)
        self.assertIn("drupal", matching_domains)

    def test_multi_handler_mashup(self):
        """Test that multiple handlers mash responses together."""
        result = self.registry.generate_response(
            "/admin",
            "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "1.2.3.4",
        )
        self.assertIsNotNone(result)
        response_bytes, detected = result
        # Should contain content from at least one handler
        self.assertTrue(len(response_bytes) > 0)
        # Should have detected content
        self.assertGreater(detected, 0)

    def test_mash_responses_static(self):
        """Test the static _mash_responses method."""
        resp1 = b"HTTP/1.1 200 OK\r\n\r\n<body>WordPress</body>"
        resp2 = b"HTTP/1.1 200 OK\r\n\r\n<body>Drupal</body>"
        results = [(resp1, 1), (resp2, 1)]
        mashed, detected = HandlerRegistry._mash_responses(results)
        self.assertIn(b"WordPress", mashed)
        self.assertIn(b"Drupal", mashed)
        self.assertEqual(detected, 1)

    def test_mash_responses_empty(self):
        """Test _mash_responses with empty input."""
        mashed, detected = HandlerRegistry._mash_responses([])
        self.assertEqual(mashed, b"")
        self.assertEqual(detected, 0)

    def test_mash_responses_single(self):
        """Test _mash_responses with single response."""
        resp = b"HTTP/1.1 200 OK\r\n\r\n<body>WordPress</body>"
        mashed, detected = HandlerRegistry._mash_responses([(resp, 1)])
        self.assertIn(b"WordPress", mashed)
        self.assertEqual(detected, 1)


class TestBotProfileDialogue(unittest.TestCase):
    """Test BotProfile dialogue tracking functionality."""

    def test_dialogue_recording(self):
        """Test that interactions are recorded in dialogue."""
        profile = BotProfile("1.2.3.4")
        request = {
            "path": "/wp-login.php",
            "method": "GET",
            "raw": "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "headers": {"Host": "example.com"},
        }
        response = b"HTTP/1.1 200 OK\r\n\r\n<html>WordPress</html>"
        profile.record_interaction(request, response, 1)
        
        dialogue = profile.get_dialogue()
        self.assertEqual(len(dialogue), 1)
        self.assertEqual(dialogue[0]["sequence"], 1)
        self.assertEqual(dialogue[0]["request"]["path"], "/wp-login.php")
        self.assertIn(b"WordPress", dialogue[0]["response"]["raw"].encode())

    def test_metadata_extraction(self):
        """Test that metadata is extracted from the first request."""
        profile = BotProfile("1.2.3.4")
        request = {
            "path": "/wp-login.php",
            "method": "GET",
            "raw": "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: WPScan v3.8.22\r\nAccept: */*\r\n\r\n",
            "headers": {},
        }
        profile.record_request(request)
        
        self.assertIn("user_agent", profile.metadata)
        self.assertEqual(profile.metadata["user_agent"], "WPScan v3.8.22")
        self.assertEqual(profile.metadata["host"], "example.com")
        self.assertEqual(profile.metadata["method"], "GET")

    def test_scanner_detection(self):
        """Test that known scanners are detected from User-Agent."""
        profile = BotProfile("1.2.3.4")
        request = {
            "path": "/",
            "method": "GET",
            "raw": "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
            "headers": {},
        }
        profile.record_request(request)
        
        self.assertIn("scanner_detected", profile.metadata)
        self.assertTrue(profile.metadata["scanner_detected"])
        self.assertEqual(profile.metadata["scanner_name"].lower(), "nikto/2.1.6")

    def test_full_report(self):
        """Test that get_full_report returns complete data."""
        profile = BotProfile("1.2.3.4")
        request = {
            "path": "/wp-login.php",
            "method": "POST",
            "raw": "POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\nlog=admin&pwd=test",
            "headers": {},
        }
        response = b"HTTP/1.1 200 OK\r\n\r\n<html>ERROR</html>"
        profile.record_request(request)
        profile.record_interaction(request, response, 1)
        profile.capture_credentials({"username": "admin", "password": "test"})
        
        report = profile.get_full_report()
        self.assertEqual(report["bot_ip"], "1.2.3.4")
        self.assertEqual(report["dialogue_count"], 1)
        self.assertEqual(report["credential_attempts"], 1)
        self.assertEqual(len(report["dialogue"]), 1)
        self.assertIn("metadata", report)

    def test_dialogue_truncation(self):
        """Test that large requests/responses are truncated."""
        profile = BotProfile("1.2.3.4")
        large_raw = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" + "X" * 10000
        request = {
            "path": "/test",
            "method": "GET",
            "raw": large_raw,
            "headers": {},
        }
        large_response = b"HTTP/1.1 200 OK\r\n\r\n" + b"Y" * 10000
        profile.record_interaction(request, large_response, 1)
        
        dialogue = profile.get_dialogue()
        self.assertEqual(len(dialogue), 1)
        # Check that truncation marker is present
        self.assertIn("truncated", dialogue[0]["request"]["raw"])
        self.assertIn("truncated", dialogue[0]["response"]["raw"])


class TestHTTPRequest(unittest.TestCase):
    """Test HTTPRequest parsing."""

    def test_parse_get(self):
        req = HTTPRequest("GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(req.command, "GET")
        self.assertEqual(req.path, "/wp-login.php")
        self.assertEqual(req.request_version, "HTTP/1.1")

    def test_parse_post(self):
        req = HTTPRequest("POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\nlog=admin&pwd=test")
        self.assertEqual(req.command, "POST")
        self.assertEqual(req.path, "/wp-login.php")

    def test_parse_with_query_string(self):
        req = HTTPRequest("GET /search?q=test&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(req.path, "/search?q=test&lang=en")


if __name__ == "__main__":
    unittest.main()
