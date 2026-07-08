"""GitLab handler tests (issue #283)."""

import unittest
from unittest.mock import MagicMock

from manyfaced.common.status import GITLAB_HTTP
from manyfaced.handlers import GitLabHandler


class TestGitLabHandler(unittest.TestCase):
    """Test GitLab responses."""

    def setUp(self):
        self.handler = GitLabHandler()

    def test_detected_id(self):
        self.assertEqual(self.handler.DETECTED_ID, GITLAB_HTTP)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/users/sign_in',
            'GET /users/sign_in HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'GitLab', response)
        self.assertEqual(detected, GITLAB_HTTP)

    def test_login_post(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/users/sign_in',
            'POST /users/sign_in HTTP/1.1\r\nHost: x\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
            'user=admin&password=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
