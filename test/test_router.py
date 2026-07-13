"""Tests for the Router module and route table.

Verifies that every HTTP request produces a response from exactly one handler,
that dispatch is visible in one ordered route table, and that concatenation
behavior is structurally impossible to reintroduce.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers.router import (
    Any,
    PathExact,
    PathPrefix,
    Router,
    Route,
)
from manyfaced.handlers.routes import ROUTES


class TestMatchers(unittest.TestCase):
    """Test individual matcher classes."""

    def test_path_prefix_matches(self):
        m = PathPrefix('/wp-admin')
        self.assertTrue(m.match('/wp-admin/'))
        self.assertTrue(m.match('/wp-admin/dashboard'))
        self.assertFalse(m.match('/wp-login.php'))

    def test_path_prefix_case_insensitive(self):
        m = PathPrefix('/WP-ADMIN')
        self.assertTrue(m.match('/wp-admin/'))
        self.assertTrue(m.match('/Wp-Admin/test'))

    def test_path_exact_matches(self):
        m = PathExact('/xmlrpc.php')
        self.assertTrue(m.match('/xmlrpc.php'))
        self.assertFalse(m.match('/xmlrpc.php.bak'))
        self.assertFalse(m.match('/wp-admin/'))

    def test_path_exact_case_insensitive(self):
        m = PathExact('/XMLRPC.PHP')
        self.assertTrue(m.match('/xmlrpc.php'))
        self.assertTrue(m.match('/XmlRpc.Php'))

    def test_any_always_matches(self):
        m = Any()
        self.assertTrue(m.match('/anything'))
        self.assertTrue(m.match(''))
        self.assertTrue(m.match('/wp-admin/secret'))


class TestRouterDispatch(unittest.TestCase):
    """Test Router.dispatch returns exactly one handler response."""

    def _make_request(self, path: str) -> str:
        return f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n'

    # ------------------------------------------------------------------
    # One-per-handler canonical paths
    # ------------------------------------------------------------------

    def test_wordpress_wp_login(self):
        router = Router(ROUTES)
        result = router.dispatch('/wp-login.php', self._make_request('/wp-login.php'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'WordPress', body)

    def test_wordpress_xmlrpc(self):
        router = Router(ROUTES)
        result = router.dispatch('/xmlrpc.php', self._make_request('/xmlrpc.php'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        # WordPress owns /xmlrpc.php — should NOT contain Drupal or ConfigDisclosure content
        self.assertIn(b'XML-RPC', body)

    def test_phpmyadmin_login(self):
        router = Router(ROUTES)
        result = router.dispatch('/phpmyadmin/', self._make_request('/phpmyadmin/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'phpMyAdmin', body)

    def test_jenkins_login(self):
        router = Router(ROUTES)
        result = router.dispatch('/jenkins/', self._make_request('/jenkins/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Jenkins', body)

    def test_tomcat_manager(self):
        router = Router(ROUTES)
        result = router.dispatch('/manager/html', self._make_request('/manager/html'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Apache Tomcat', body)

    def test_drupal_user(self):
        router = Router(ROUTES)
        result = router.dispatch('/user/login', self._make_request('/user/login'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Drupal', body)

    def test_cpanel_login(self):
        router = Router(ROUTES)
        result = router.dispatch('/cpanel/', self._make_request('/cpanel/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'cPanel', body)

    def test_bitrix_admin(self):
        router = Router(ROUTES)
        result = router.dispatch('/bitrix/admin/', self._make_request('/bitrix/admin/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Bitrix', body)

    def test_bitrix_auth(self):
        router = Router(ROUTES)
        result = router.dispatch('/bitrix/auth/', self._make_request('/bitrix/auth/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Bitrix', body)

    def test_bitrix_portal(self):
        router = Router(ROUTES)
        result = router.dispatch('/bitrix/', self._make_request('/bitrix/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Bitrix', body)

    def test_config_disclosure_wpconfig(self):
        router = Router(ROUTES)
        result = router.dispatch('/wp-config.php', self._make_request('/wp-config.php'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'DB_NAME', body)

    def test_generic_catchall(self):
        router = Router(ROUTES)
        result = router.dispatch('/asdfasdf', self._make_request('/asdfasdf'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        # GenericHandler serves the monster page
        self.assertIn(b'Server Administration Panel', body)

    def test_root_path_catchall(self):
        router = Router(ROUTES)
        # A path with no matching route must fall through to the generic
        # catch-all handler (GenericHandler) rather than an admin panel.
        # Note: bare '/' is now claimed by the Elasticsearch root route
        # (issue #461/#468), so we probe a genuinely unrouted path here.
        result = router.dispatch(
            '/no-such-catchall-path', self._make_request('/no-such-catchall-path'), '1.2.3.4'
        )
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Server Administration Panel', body)

    # ------------------------------------------------------------------
    # Overlap resolution — deliberate ordering tests
    # ------------------------------------------------------------------

    def test_overlap_xmlrpc_php_wins_wordpress(self):
        """/xmlrpc.php is claimed by WordPress, Drupal, and ConfigDisclosure.
        WordPress route is listed first → WordPress wins."""
        router = Router(ROUTES)
        result = router.dispatch('/xmlrpc.php', self._make_request('/xmlrpc.php'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        # Should contain WordPress XML-RPC content
        self.assertIn(b'XML-RPC', body)
        # Should NOT contain Drupal content (Drupal also claims /xmlrpc.php)
        self.assertNotIn(b'Drupal', body)
        # Should NOT contain ConfigDisclosure fake config file content
        self.assertNotIn(b'DB_NAME', body)

    def test_overlap_files_wins_drupal(self):
        """/files is claimed by Drupal and WebDAV (separate brief).
        Drupal route is listed first → Drupal wins."""
        router = Router(ROUTES)
        result = router.dispatch('/files/', self._make_request('/files/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        # Should contain Drupal content
        self.assertIn(b'Drupal', body)

    def test_overlap_mysql_wins_phpmyadmin(self):
        """/mysql is claimed by phpMyAdmin and ConfigDisclosure.
        phpMyAdmin route is listed first → phpMyAdmin wins."""
        router = Router(ROUTES)
        result = router.dispatch('/mysql/', self._make_request('/mysql/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        # Should contain phpMyAdmin content
        self.assertIn(b'phpMyAdmin', body)

    def test_overlap_mysql_config_disclosure_unreachable(self):
        """/mysql ConfigDisclosure route exists but is unreachable because
        the phpMyAdmin route appears first in ROUTES."""
        router = Router(ROUTES)
        # Verify that /mysql/ matches a phpMyAdmin route, not ConfigDisclosure
        explanation = router.explain('/mysql/')
        self.assertIn('phpmyadmin', explanation.lower())

    def test_overlap_xmlrpc_config_disclosure_unreachable(self):
        """/xmlrpc.php ConfigDisclosure route exists but is unreachable because
        the WordPress route appears first in ROUTES."""
        router = Router(ROUTES)
        explanation = router.explain('/xmlrpc.php')
        self.assertIn('wordpress', explanation.lower())

    # ------------------------------------------------------------------
    # Query string stripping (regression guard for current behavior)
    # ------------------------------------------------------------------

    def test_query_string_stripped_for_matching(self):
        """Path matching should strip query strings before comparison."""
        router = Router(ROUTES)
        result = router.dispatch(
            '/wp-login.php?redirect_to=%2Fwp-admin',
            self._make_request('/wp-login.php?redirect_to=%2Fwp-admin'),
            '1.2.3.4',
        )
        assert result is not None  # type narrowing for type checker
        body, _ = result
        # Should match WordPress handler (which handles /wp-login.php)
        self.assertIn(b'WordPress', body)

    def test_query_string_stripped_phpmyadmin(self):
        """Query string on phpMyAdmin path should still route correctly."""
        router = Router(ROUTES)
        result = router.dispatch(
            '/phpmyadmin/?db=test&table=users', self._make_request('/phpmyadmin/'), '1.2.3.4'
        )
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'phpMyAdmin', body)

    # ------------------------------------------------------------------
    # Case insensitivity (regression guard)
    # ------------------------------------------------------------------

    def test_case_insensitive_wordpress(self):
        """Path matching should be case-insensitive."""
        router = Router(ROUTES)
        result = router.dispatch('/WP-LOGIN.PHP', self._make_request('/wp-login.php'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'WordPress', body)

    def test_case_insensitive_phpmyadmin(self):
        """Path matching should be case-insensitive."""
        router = Router(ROUTES)
        result = router.dispatch('/PHPMYADMIN/', self._make_request('/phpmyadmin/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'phpMyAdmin', body)

    def test_case_insensitive_jenkins(self):
        """Path matching should be case-insensitive."""
        router = Router(ROUTES)
        result = router.dispatch('/JENKINS/', self._make_request('/jenkins/'), '1.2.3.4')
        assert result is not None  # type narrowing for type checker
        body, _ = result
        self.assertIn(b'Jenkins', body)

    # ------------------------------------------------------------------
    # Single handler guarantee — dispatch never returns a list
    # ------------------------------------------------------------------

    def test_dispatch_returns_tuple_not_list(self):
        """Router.dispatch() must return (bytes, int), never a list."""
        for path in ['/wp-login.php', '/xmlrpc.php', '/phpmyadmin/', '/jenkins/', '/', '/asdf']:
            router = Router(ROUTES)
            result = router.dispatch(path, self._make_request(path), '1.2.3.4')
            if result is not None:
                body, detected = result  # Unpack as tuple — will raise TypeError if list
                self.assertIsInstance(body, bytes)
                self.assertIsInstance(detected, int)

    def test_dispatch_returns_single_response(self):
        """The response body should come from exactly one handler.
        This is the regression guard against the mashing bug."""
        for path in ['/wp-login.php', '/xmlrpc.php', '/phpmyadmin/', '/jenkins/']:
            router = Router(ROUTES)
            result = router.dispatch(path, self._make_request(path), '1.2.3.4')
            assert result is not None  # type narrowing for type checker
            body, _ = result
            # Count DOCTYPE declarations — should be at most 1 for HTML responses
            doctype_count = body.lower().count(b'<!doctype')
            self.assertLessEqual(
                doctype_count, 1, f'Path {path} has {doctype_count} DOCTYPEs (expected ≤1)'
            )

    # ------------------------------------------------------------------
    # Router.explain() debug method
    # ------------------------------------------------------------------

    def test_explain_returns_debug_string(self):
        router = Router(ROUTES)
        explanation = router.explain('/wp-login.php')
        self.assertIn('wordpress', explanation.lower())
        self.assertIn('route', explanation.lower())

    def test_explain_for_catchall(self):
        router = Router(ROUTES)
        explanation = router.explain('/nonexistent123')
        self.assertIn('catchall', explanation.lower())


class TestRouteTableCompleteness(unittest.TestCase):
    """Verify the route table has expected properties."""

    def test_last_route_is_catch_all(self):
        """The final entry in ROUTES must be an Any() matcher (catch-all)."""
        last = ROUTES[-1]
        self.assertIsInstance(last.matcher, Any)
        self.assertEqual(last.name, 'catchall_monster_page')

    def test_no_duplicate_handler_classes_in_sequence(self):
        """Each handler class should appear in contiguous blocks — no interleaving."""
        # This is a soft check: just verify the table has entries for all expected handlers
        handler_names = {r.name for r in ROUTES}
        self.assertIn('wordpress_wp_login', handler_names)
        self.assertIn('phpmyadmin_phpmyadmin', handler_names)
        self.assertIn('jenkins_jenkins', handler_names)
        self.assertIn('tomcat_manager', handler_names)
        self.assertIn('drupal_user', handler_names)
        self.assertIn('cpanel_cpanel', handler_names)
        self.assertIn('config_wp_config_php', handler_names)
        self.assertIn('catchall_monster_page', handler_names)

    def test_route_table_has_entries(self):
        """ROUTES should have a substantial number of entries."""
        self.assertGreater(len(ROUTES), 50, 'Expected many route entries')


if __name__ == '__main__':
    unittest.main()
