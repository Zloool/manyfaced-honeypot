"""Tests for the Docker Registry / daemon API HTTP handler (issue #275)."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers.docker_handler import DockerHandler
from manyfaced.common.status import DOCKER_HTTP


class TestDockerHandler(unittest.TestCase):
    """Test DockerHandler responses."""

    def setUp(self):
        self.handler = DockerHandler()

    def _profile(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        return profile

    def test_detected_id(self):
        """Handler reports the correct detected ID constant."""
        self.assertEqual(self.handler.DETECTED_ID, DOCKER_HTTP)
        self.assertEqual(DOCKER_HTTP, 1032)

    def test_main_page(self):
        """GET /v2/ returns the registry v2 ping (contains 'docker')."""
        self._profile()
        response, detected = self.handler.generate_response(
            '/v2/',
            'GET /v2/ HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'docker', response.lower())
        self.assertEqual(detected, DOCKER_HTTP)

    def test_v2_ping_json(self):
        self._profile()
        response, _ = self.handler.generate_response(
            '/v2/',
            'GET /v2/ HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'docker_distribution', response.lower())
        self.assertIn(b'registry', response.lower())

    def test_v2_catalog(self):
        self._profile()
        response, _ = self.handler.generate_response(
            '/v2/_catalog',
            'GET /v2/_catalog HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'repositories', response.lower())

    def test_v2_tags_list(self):
        self._profile()
        response, _ = self.handler.generate_response(
            '/v2/library/nginx/tags/list',
            'GET /v2/library/nginx/tags/list HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'tags', response.lower())
        self.assertIn(b'library/nginx', response.lower())

    def test_daemon_version(self):
        self._profile()
        response, _ = self.handler.generate_response(
            '/version',
            'GET /version HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'ApiVersion', response)
        self.assertIn(b'26.0.0', response)

    def test_daemon_info(self):
        self._profile()
        response, _ = self.handler.generate_response(
            '/info',
            'GET /info HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Containers', response)
        self.assertIn(b'ServerVersion', response)

    def test_daemon_containers(self):
        self._profile()
        response, _ = self.handler.generate_response(
            '/containers/json',
            'GET /containers/json HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        # Empty container list -> JSON array.
        self.assertIn(b'[]', response)

    def test_docker_env_traversal(self):
        """Path-traversal probe /docker/.env discloses a fake .env file."""
        self._profile()
        response, _ = self.handler.generate_response(
            '/docker/.env',
            'GET /docker/.env HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'DB_PASSWORD', response)
        self.assertIn(b'AWS_ACCESS_KEY_ID', response)

    def test_docker_env_url_encoded(self):
        """URL-encoded probe /docker/%2eenv is decoded and recognised."""
        self._profile()
        response, _ = self.handler.generate_response(
            '/docker/%2eenv',
            'GET /docker/%2eenv HTTP/1.1\r\nHost: x\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'DB_PASSWORD', response)

    def test_login_post(self):
        """Credential-bearing POST returns 'Error' (login failed)."""
        self._profile()
        response, _ = self.handler.generate_response(
            '/v2/auth',
            'POST /v2/auth HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret123',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)


if __name__ == '__main__':
    unittest.main()
