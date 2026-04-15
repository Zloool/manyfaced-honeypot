import unittest
from manyfaced.client import get_honey_http, faces, compile_banner, honey_generic
from manyfaced.common.httphandler import HTTPRequest

class TestClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_dir = os.path.dirname(os.path.abspath(__file__))
        cls.responses_dir = os.path.join(cls.root_dir, 'responses')

    def test_get_honey_http_known_face(self):
        request = HTTPRequest("GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip)
        
        # Verify detection
        self.assertTrue(detected)
        # Verify response contains expected content
        self.assertIn('webdav.xml', str(output_data))
        
    def test_get_robots_txt(self):
        request = HTTPRequest("GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip)
        
        # Verify detection
        self.assertTrue(detected)
        # Verify robots.txt content
        self.assertIn('Allow: /', str(output_data))
        
    def test_get_webdav_xml(self):
        request = HTTPRequest("GET /webdav.xml HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip)
        
        # Verify detection
        self.assertTrue(detected)
        # Verify XML response content
        self.assertIn('Multi-Status', str(output_data))
        
    def test_get_text_plain_response(self):
        request = HTTPRequest("GET /text.txt HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip)
        
        # Verify detection
        self.assertTrue(detected)
        # Verify content type
        self.assertIn('text/plain', str(output_data))
        
    def test_get_xml_response(self):
        request = HTTPRequest("GET /data.xml HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip)
        
        # Verify detection
        self.assertTrue(detected)
        # Verify content type
        self.assertIn('application/xml', str(output_data))
        
    def test_compile_banner(self):
        banner = compile_banner()
        expected_server_version = "Apache/1.3.42 (Unix)  (Red Hat/Linux)  OpenSSL/1.0.1e PHP/5.5.9 "
        
        # Verify banner contains server version
        self.assertIn(expected_server_version, banner)
        # Verify content type is set correctly for HTML
        self.assertIn('text/html; charset=UTF-8', banner)
        
    def test_honey_generic(self):
        face = "test.html"
        output_data = honey_generic(face)
        
        # Verify response starts with proper HTTP status line
        self.assertIn("HTTP/1.1 200 OK", str(output_data))
        # Verify content type is correct for HTML
        self.assertIn('text/html; charset=UTF-8', str(output_data))
        
    def test_get_unknown_face(self):
        request = HTTPRequest("GET /unknown_path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip)
        
        # Verify detection is False
        self.assertFalse(detected)
        # Verify response indicates not found
        self.assertIn("404", str(output_data))
    
    def test_response_sizes(self):
        request = HTTPRequest("GET /webdav.xml HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, _ = get_honey_http(request, bot_ip)
        
        # Verify response size
        self.assertEqual(len(output_data), 1024)

if __name__ == '__main__':
    unittest.main()

if __name__ == '__main__':
    unittest.main()
