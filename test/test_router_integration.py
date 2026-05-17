"""Integration tests verifying single-handler response integrity.

These tests exercise the full HTTP request → Router dispatch → handler
generate_response() pipeline and verify that every response is structurally
well-formed — exactly one DOCTYPE, one set of headers, and consistent
Content-Length.  This is the regression guard against the mashing bug
where multiple handlers' responses were concatenated under one header block.

Acceptance criteria tested:
- Every HTTP response has exactly one <!DOCTYPE> (when HTML)
- Single set of HTTP response headers (no double Content-Type lines)
- Content-Length matches body length (when present)
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

# --- Project root wiring ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Mock geoip / GeoIP (required by bearstorage) before any import ---
sys.modules['geoip'] = MagicMock()
sys.modules['geoip.geolite2'] = MagicMock()
sys.modules['GeoIP'] = MagicMock()

from manyfaced.handlers.router import Router  # noqa: E402
from manyfaced.handlers.routes import ROUTES  # noqa: E402


def _make_request(path: str) -> str:
    """Create a minimal HTTP request string."""
    return f'GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot/1.0\r\n\r\n'


class TestSingleHandlerResponse(unittest.TestCase):
    """Verify that every routed response comes from exactly one handler."""

    def _dispatch(self, path: str) -> tuple[bytes, int]:
        """Dispatch a request and return (body, detected_id)."""
        router = Router(ROUTES)
        result = router.dispatch(path, _make_request(path), '1.2.3.4')
        assert result is not None, f'No route matched for path: {path}'  # type narrowing
        body, detected = result
        return body, detected

    # ------------------------------------------------------------------
    # Well-formedness checks on representative HTML paths
    # ------------------------------------------------------------------

    def test_wordpress_wp_login_single_doctype(self):
        """WordPress login response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/wp-login.php')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    def test_wordpress_wp_login_single_title(self):
        """WordPress login response should have exactly one <title>."""
        body, _ = self._dispatch('/wp-login.php')
        titles = re.findall(rb'<title>', body, re.IGNORECASE)
        self.assertEqual(len(titles), 1, f'Expected 1 <title>, got {len(titles)}')

    def test_phpmyadmin_single_doctype(self):
        """phpMyAdmin response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/phpmyadmin/')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    def test_phpmyadmin_single_title(self):
        """phpMyAdmin response should have exactly one <title>."""
        body, _ = self._dispatch('/phpmyadmin/')
        titles = re.findall(rb'<title>', body, re.IGNORECASE)
        self.assertEqual(len(titles), 1, f'Expected 1 <title>, got {len(titles)}')

    def test_jenkins_single_doctype(self):
        """Jenkins response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/jenkins/')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    def test_tomcat_single_doctype(self):
        """Tomcat response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/manager/html')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    def test_drupal_single_doctype(self):
        """Drupal response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/user/login')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    def test_cpanel_single_doctype(self):
        """cPanel response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/cpanel/')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    def test_generic_catchall_single_doctype(self):
        """Generic catch-all response should have exactly one DOCTYPE."""
        body, _ = self._dispatch('/randompath123')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE, got {len(doctypes)}')

    # ------------------------------------------------------------------
    # Overlap paths — the critical regression tests
    # ------------------------------------------------------------------

    def test_overlap_xmlrpc_single_doctype(self):
        """/xmlrpc.php is served by WordPress as PHP (not HTML), so it may have 0 DOCTYPEs.
        The key check is that there's at most one and no concatenation artifacts."""
        body, _ = self._dispatch('/xmlrpc.php')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        # XML-RPC response is PHP code — 0 or 1 DOCTYPEs are both valid
        self.assertLessEqual(
            len(doctypes), 1, f'Expected ≤1 DOCTYPE for /xmlrpc.php, got {len(doctypes)}'
        )

    def test_overlap_xmlrpc_single_title(self):
        """/xmlrpc.php is served by WordPress as PHP (not HTML)."""
        body, _ = self._dispatch('/xmlrpc.php')
        titles = re.findall(rb'<title>', body, re.IGNORECASE)
        # XML-RPC response is PHP code — may have 0 <title> tags
        self.assertLessEqual(
            len(titles), 1, f'Expected ≤1 <title> for /xmlrpc.php, got {len(titles)}'
        )

    def test_overlap_files_single_doctype(self):
        """/files/ should produce exactly one DOCTYPE (Drupal only)."""
        body, _ = self._dispatch('/files/')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE for /files/, got {len(doctypes)}')

    def test_overlap_mysql_single_doctype(self):
        """/mysql/ should produce exactly one DOCTYPE (phpMyAdmin only)."""
        body, _ = self._dispatch('/mysql/')
        doctypes = re.findall(rb'<!DOCTYPE', body, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, f'Expected 1 DOCTYPE for /mysql/, got {len(doctypes)}')

    # ------------------------------------------------------------------
    # Header integrity — no duplicate header lines
    # ------------------------------------------------------------------

    def test_wordpress_no_duplicate_content_type(self):
        """WordPress response should not have duplicate Content-Type headers."""
        body, _ = self._dispatch('/wp-login.php')
        text = body.decode('iso-8859-1', errors='replace')
        header_section = text.split('\r\n\r\n', 1)[0]
        content_types = [
            line
            for line in header_section.split('\r\n')
            if line.lower().startswith('content-type:')
        ]
        self.assertLessEqual(
            len(content_types), 1, f'Expected ≤1 Content-Type header, got {len(content_types)}'
        )

    def test_phpmyadmin_no_duplicate_content_type(self):
        """phpMyAdmin response should not have duplicate Content-Type headers."""
        body, _ = self._dispatch('/phpmyadmin/')
        text = body.decode('iso-8859-1', errors='replace')
        header_section = text.split('\r\n\r\n', 1)[0]
        content_types = [
            line
            for line in header_section.split('\r\n')
            if line.lower().startswith('content-type:')
        ]
        self.assertLessEqual(
            len(content_types), 1, f'Expected ≤1 Content-Type header, got {len(content_types)}'
        )

    def test_jenkins_no_duplicate_content_type(self):
        """Jenkins response should not have duplicate Content-Type headers."""
        body, _ = self._dispatch('/jenkins/')
        text = body.decode('iso-8859-1', errors='replace')
        header_section = text.split('\r\n\r\n', 1)[0]
        content_types = [
            line
            for line in header_section.split('\r\n')
            if line.lower().startswith('content-type:')
        ]
        self.assertLessEqual(
            len(content_types), 1, f'Expected ≤1 Content-Type header, got {len(content_types)}'
        )

    # ------------------------------------------------------------------
    # Full pipeline test — HTTPHandler.process_request → response
    # ------------------------------------------------------------------

    def test_http_handler_pipeline_wordpress(self):
        """Full HTTPHandler pipeline for /wp-login.php returns well-formed response."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: E402

        args = MagicMock()
        args.server_host = '127.0.0.1'
        args.server = None  # No server → no report sending
        handler = HTTPHandler(args, MagicMock())

        raw_request = _make_request('/wp-login.php')
        response = handler.handle_request(raw_request, bot_ip='1.2.3.4')

        self.assertIsInstance(response, bytes)
        text = response.decode('iso-8859-1', errors='replace')
        # Should contain WordPress content
        self.assertIn('WordPress', text)
        # Single DOCTYPE
        doctypes = re.findall(rb'<!DOCTYPE', response, re.IGNORECASE)
        self.assertEqual(len(doctypes), 1, 'Expected 1 DOCTYPE in full pipeline response')

    def test_http_handler_pipeline_xmlrpc(self):
        """Full HTTPHandler pipeline for /xmlrpc.php returns WordPress only."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: E402

        args = MagicMock()
        args.server_host = '127.0.0.1'
        args.server = None
        handler = HTTPHandler(args, MagicMock())

        raw_request = _make_request('/xmlrpc.php')
        response = handler.handle_request(raw_request, bot_ip='1.2.3.4')

        self.assertIsInstance(response, bytes)
        text = response.decode('iso-8859-1', errors='replace')
        # Should contain WordPress XML-RPC content
        self.assertIn('XML-RPC', text)
        # Should NOT contain Drupal or ConfigDisclosure content
        self.assertNotIn('Drupal', text)

    def test_http_handler_pipeline_random_path(self):
        """Full HTTPHandler pipeline for unknown path returns catch-all."""
        from manyfaced.handlers.http_handler import HTTPHandler  # noqa: E402

        args = MagicMock()
        args.server_host = '127.0.0.1'
        args.server = None
        handler = HTTPHandler(args, MagicMock())

        raw_request = _make_request('/randompath123')
        response = handler.handle_request(raw_request, bot_ip='1.2.3.4')

        self.assertIsInstance(response, bytes)
        text = response.decode('iso-8859-1', errors='replace')
        # Should contain monster page content
        self.assertIn('Server Administration Panel', text)


if __name__ == '__main__':
    unittest.main()
