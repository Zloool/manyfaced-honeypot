"""Tests for BotProfile state tracking and dialogue functionality."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers import BotProfile


class TestBotProfile(unittest.TestCase):
    """Test BotProfile state tracking."""

    def test_create_profile(self):
        profile = BotProfile('1.2.3.4')
        self.assertEqual(profile.bot_ip, '1.2.3.4')
        self.assertIsNotNone(profile.session_id)
        self.assertEqual(profile.escalation_level, BotProfile.IDLE)
        self.assertEqual(len(profile.request_history), 0)

    def test_record_request(self):
        profile = BotProfile('1.2.3.4')
        profile.record_request({'path': '/wp-login.php', 'method': 'GET'})
        self.assertEqual(len(profile.request_history), 1)

    def test_credential_capture(self):
        profile = BotProfile('1.2.3.4')
        profile.capture_credentials({'username': 'admin', 'password': 'secret'})
        self.assertEqual(len(profile.captured_credentials), 1)
        self.assertEqual(profile.captured_credentials[0]['username'], 'admin')
        self.assertIn('credential_stuffing', profile.detected_behaviors)

    def test_escalation_on_exploit(self):
        profile = BotProfile('1.2.3.4')
        profile.record_request(
            {
                'path': '/admin?or+1=1',
                'method': 'GET',
                'raw': 'GET /admin?or+1=1 HTTP/1.1',
            }
        )
        self.assertIn('sql_injection', profile.detected_behaviors)
        self.assertGreater(profile.escalation_level, BotProfile.IDLE)

    def test_get_stats(self):
        profile = BotProfile('1.2.3.4')
        profile.record_request({'path': '/test', 'method': 'GET'})
        stats = profile.get_stats()
        self.assertEqual(stats['bot_ip'], '1.2.3.4')
        self.assertEqual(stats['request_count'], 1)
        self.assertIn('session_id', stats)


class TestBotProfileDialogue(unittest.TestCase):
    """Test BotProfile dialogue tracking functionality."""

    def test_dialogue_recording(self):
        """Test that interactions are recorded in dialogue."""
        profile = BotProfile('1.2.3.4')
        request = {
            'path': '/wp-login.php',
            'method': 'GET',
            'raw': 'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            'headers': {'Host': 'example.com'},
        }
        response = b'HTTP/1.1 200 OK\r\n\r\n<html>WordPress</html>'
        profile.record_interaction(request, response, 1)

        dialogue = profile.get_dialogue()
        self.assertEqual(len(dialogue), 1)
        self.assertEqual(dialogue[0]['sequence'], 1)
        self.assertEqual(dialogue[0]['request']['path'], '/wp-login.php')
        self.assertIn(b'WordPress', dialogue[0]['response']['raw'].encode())

    def test_metadata_extraction(self):
        """Test that metadata is extracted from the first request."""
        profile = BotProfile('1.2.3.4')
        request = {
            'path': '/wp-login.php',
            'method': 'GET',
            'raw': 'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: WPScan v3.8.22\r\nAccept: */*\r\n\r\n',
            'headers': {},
        }
        profile.record_request(request)

        self.assertIn('user_agent', profile.metadata)
        self.assertEqual(profile.metadata['user_agent'], 'WPScan v3.8.22')
        self.assertEqual(profile.metadata['host'], 'example.com')
        self.assertEqual(profile.metadata['method'], 'GET')

    def test_scanner_detection(self):
        """Test that known scanners are detected from User-Agent."""
        profile = BotProfile('1.2.3.4')
        request = {
            'path': '/',
            'method': 'GET',
            'raw': 'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Nikto/2.1.6\r\n\r\n',
            'headers': {},
        }
        profile.record_request(request)

        self.assertIn('scanner_detected', profile.metadata)
        self.assertTrue(profile.metadata['scanner_detected'])
        self.assertEqual(profile.metadata['scanner_name'].lower(), 'nikto/2.1.6')

    def test_full_report(self):
        """Test that get_full_report returns complete data."""
        profile = BotProfile('1.2.3.4')
        request = {
            'path': '/wp-login.php',
            'method': 'POST',
            'raw': 'POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\nlog=admin&pwd=test',
            'headers': {},
        }
        response = b'HTTP/1.1 200 OK\r\n\r\n<html>ERROR</html>'
        profile.record_request(request)
        profile.record_interaction(request, response, 1)
        profile.capture_credentials({'username': 'admin', 'password': 'test'})

        report = profile.get_full_report()
        self.assertEqual(report['bot_ip'], '1.2.3.4')
        self.assertEqual(report['dialogue_count'], 1)
        self.assertEqual(report['credential_attempts'], 1)
        self.assertEqual(len(report['dialogue']), 1)
        self.assertIn('metadata', report)

    def test_dialogue_truncation(self):
        """Test that large requests/responses are truncated."""
        profile = BotProfile('1.2.3.4')
        large_raw = 'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n' + 'X' * 10000
        request = {
            'path': '/test',
            'method': 'GET',
            'raw': large_raw,
            'headers': {},
        }
        large_response = b'HTTP/1.1 200 OK\r\n\r\n' + b'Y' * 10000
        profile.record_interaction(request, large_response, 1)

        dialogue = profile.get_dialogue()
        self.assertEqual(len(dialogue), 1)
        # Check that truncation marker is present
        self.assertIn('truncated', dialogue[0]['request']['raw'])
        self.assertIn('truncated', dialogue[0]['response']['raw'])


if __name__ == '__main__':
    unittest.main()
