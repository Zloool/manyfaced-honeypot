"""Regression tests for P3 service/app protocol fidelity (backlog #528).

Covers: Elasticsearch served as HTTP (#461/#468), MCP SSE + JSON-RPC (#427/#434),
Docker probe gating (#522), Kubernetes status codes (#489), FTP/POP3/IMAP
non-HTTP greetings (#491), and config-disclosure hygiene (#479/#494).
Credentials are out of scope — these tests only assert protocol shape.

Note: the fidelity handlers return ``(body_bytes, detected_id)`` where
``detected_id`` is the protocol's numeric face id (>= 1000); the real HTTP
status line lives inside ``body_bytes``.
"""

import unittest
from datetime import datetime, timezone

from manyfaced.handlers.mcp_handler import MCPHandler
from manyfaced.handlers.docker_handler import DockerHandler
from manyfaced.handlers.kubernetes_handler import KubernetesHandler
from manyfaced.handlers.http_handler import HTTPHandler
from manyfaced.handlers.config_responses.security_configs import fake_security_txt
from manyfaced.common.faces import is_http_port


CRLF = bytes([13, 10])


def _body_str(body) -> str:
    return body.decode('utf-8', errors='replace')


class TestElasticsearchHTTP(unittest.TestCase):
    def test_9200_is_http_port(self):
        self.assertTrue(is_http_port(9200))
        self.assertTrue(is_http_port(15672))

    def test_elasticsearch_root_returns_cluster_info(self):
        from manyfaced.handlers.elastic_handler import ElasticHandler

        body, status = ElasticHandler().generate_response('/', 'GET', '1.2.3.4')
        self.assertIsInstance(status, int)
        self.assertIn('cluster_name', _body_str(body))
        self.assertIn('version', _body_str(body))


class TestMCPProtocol(unittest.TestCase):
    def test_sse_stream_is_event_stream(self):
        h = MCPHandler()
        body, status = h.generate_response('/sse', 'GET', '1.2.3.4')
        self.assertIn('text/event-stream', _body_str(body))

    def test_jsonrpc_initialize_returns_result(self):
        h = MCPHandler()
        req = (
            'POST /mcp HTTP/1.1\r\n'
            'Content-Type: application/json\r\n\r\n'
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
        )
        body, status = h.generate_response('/mcp', req, '1.2.3.4')
        self.assertIn('"result"', _body_str(body))
        self.assertIn('protocolVersion', _body_str(body))


class TestDockerGating(unittest.TestCase):
    def test_docker_ua_gets_daemon_response(self):
        h = DockerHandler()
        body, status = h.generate_response(
            '/version', 'GET', '1.2.3.4', headers={'User-Agent': 'Docker/24.0'}
        )
        self.assertIsInstance(status, int)
        # Docker-shaped probe receives a real daemon fingerprint (200).
        self.assertIn('200', _body_str(body))

    def test_non_docker_probe_gets_404(self):
        h = DockerHandler()
        body, status = h.generate_response(
            '/version', 'GET', '1.2.3.4', headers={'User-Agent': 'curl/8.0'}
        )
        # Non-Docker scanner must NOT get a 200 Docker daemon fingerprint.
        self.assertIn('404', _body_str(body))
        self.assertNotIn('200', _body_str(body).split('\r\n', 1)[0])


class TestKubernetesStatusCodes(unittest.TestCase):
    def test_protected_api_v1_requires_auth(self):
        h = KubernetesHandler()
        body, status = h.generate_response(
            '/api/v1/pods', 'GET', '1.2.3.4', headers={'User-Agent': 'kube-probe'}
        )
        self.assertIn('kind', _body_str(body))
        self.assertIn('Status', _body_str(body))
        self.assertIn('403', _body_str(body))

    def test_unknown_path_is_404_status(self):
        h = KubernetesHandler()
        body, status = h.generate_response('/nonexistent', 'GET', '1.2.3.4')
        self.assertIn('kind', _body_str(body))
        self.assertIn('Status', _body_str(body))
        self.assertIn('404', _body_str(body))

    def test_public_discovery_is_200(self):
        h = KubernetesHandler()
        body, status = h.generate_response('/healthz', 'GET', '1.2.3.4')
        self.assertIn('200', _body_str(body))


class TestNonHttpGreetings(unittest.TestCase):
    def test_ftp_pop3_imap_get_protocol_banner(self):
        h = HTTPHandler.__new__(HTTPHandler)
        self.assertTrue(h._non_http_greeting('ftp').startswith(b'220 '))
        self.assertTrue(h._non_http_greeting('pop3').startswith(b'+OK'))
        self.assertTrue(h._non_http_greeting('imap').startswith(b'* OK'))
        for proto in ('ftp', 'pop3', 'imap'):
            self.assertTrue(h._non_http_greeting(proto).endswith(CRLF))


class TestConfigDisclosure(unittest.TestCase):
    def test_security_txt_expires_is_future(self):
        now = datetime.now(timezone.utc)
        txt = fake_security_txt()
        expires_line = [line for line in txt.split('\n') if line.startswith('Expires:')][0]
        expires = datetime.strptime(
            expires_line.split(':', 1)[1].strip(), '%Y-%m-%dT%H:%M:%S.000Z'
        ).replace(tzinfo=timezone.utc)
        self.assertGreater(expires, now)


if __name__ == '__main__':
    unittest.main()
