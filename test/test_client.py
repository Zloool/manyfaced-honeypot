import os
import sys
import unittest
from manyfaced.client import get_honey_http, faces, compile_banner, honey_generic

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.client.faces import faces as faces_dict
from manyfaced.common.httphandler import HTTPRequest
from manyfaced.common.status import UNKNOWN_HTTP


class TestClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_dir = os.path.dirname(os.path.abspath(__file__))
        cls.responses_dir = os.path.join(cls.root_dir, 'manyfaced', 'client', 'responses')

    def test_get_honey_http_known_face(self):
        request = HTTPRequest("GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        faces_config = {
            '/3001': 'webdav.xml',
            '/../../../../etc/passwd': 'webdav.xml',
            '/?author=1': 'webdav.xml',
            '/index.php/admin/': 'webdav.xml',
            '/admin.php': 'webdav.xml',
            '/admin/': 'webdav.xml',
        }
        import manyfaced.client.client as client_mod
        orig_faces = client_mod.faces
        client_mod.faces = faces_config

        try:
            output_data, detected = get_honey_http(request, bot_ip, verbose=False)

            # Verify detection
            self.assertTrue(detected)
            # Verify response contains expected content
            self.assertIn('webdav.xml', str(output_data))
        finally:
            client_mod.faces = orig_faces

    def test_get_robots_txt(self):
        request = HTTPRequest("GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        faces_config = {'/robots.txt': 'robots'}
        import manyfaced.client.client as client_mod
        orig_faces = client_mod.faces
        client_mod.faces = faces_config

        try:
            output_data, detected = get_honey_http(request, bot_ip, verbose=False)

            # Verify detection
            self.assertTrue(detected)
            # Verify robots.txt content
            self.assertIn('Allow: /', str(output_data))
        finally:
            client_mod.faces = orig_faces

    def test_get_webdav_xml(self):
        request = HTTPRequest("GET /webdav.xml HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        faces_config = {'/webdav.xml': 'webdav.xml'}
        import manyfaced.client.client as client_mod
        orig_faces = client_mod.faces
        client_mod.faces = faces_config

        try:
            output_data, detected = get_honey_http(request, bot_ip, verbose=False)

            # Verify detection
            self.assertTrue(detected)
            # Verify XML response content
            self.assertIn('Multi-Status', str(output_data))
        finally:
            client_mod.faces = orig_faces

    def test_get_text_plain_response(self):
        # Test with a face that uses text/plain content-type
        request = HTTPRequest("GET /text.txt HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        # Use the response file directly
        output_data = honey_generic('zero')

        # Verify response starts with HTTP status line
        self.assertIn("HTTP/1.1", str(output_data))

    def test_get_xml_response(self):
        request = HTTPRequest("GET /data.xml HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"

        output_data = honey_generic('webdav.xml')

        # Verify content type or response structure
        self.assertIn('application/xml', str(output_data))

    def test_compile_banner(self):
        banner = compile_banner()

        # Verify banner contains server version
        self.assertIn('Apache/1.3.42 (Unix)  (Red Hat/Linux)  OpenSSL/1.0.1e PHP/5.5.9 ', banner)
        # Verify content type is set correctly for HTML
        self.assertIn('text/html; charset=UTF-8', banner)

    def test_honey_generic(self):
        face = "zero"
        output_data = honey_generic(face)

        # Verify response starts with proper HTTP status line
        self.assertIn("HTTP/1.1 200 OK", str(output_data))
        # Verify content type is correct for HTML
        self.assertIn('text/html; charset=UTF-8', str(output_data))

    def test_get_unknown_face(self):
        request = HTTPRequest("GET /unknown_path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip, verbose=False)

        # Verify response for unknown paths defaults to zero face
        self.assertIn("welcome", str(output_data).lower())

    def test_faces_dict_has_zero(self):
        # Verify zero face exists for unknown paths
        self.assertIn('zero', faces_dict)

    def test_response_sizes(self):
        output_data = honey_generic('webdav.xml')

        # Verify response is non-empty
        self.assertGreater(len(output_data), 0)


if __name__ == '__main__':
    unittest.main()
