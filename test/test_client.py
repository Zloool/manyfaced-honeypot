import unittest
from manyfaced.client.client import get_honey_http, faces, compile_banner, honey_generic
from manyfaced.common.httphandler import HTTPRequest

class TestClient(unittest.TestCase):
    def test_get_honey_http_known_face(self):
        request = HTTPRequest("GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip, verbose=True)
        self.assertEqual(detected, 1)
        self.assertIn("webdav.xml", output_data)

    def test_get_honey_http_unknown_face(self):
        request = HTTPRequest("GET /unknown_path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        bot_ip = "192.168.1.1"
        output_data, detected = get_honey_http(request, bot_ip, verbose=True)
        self.assertEqual(detected, 0)  # Assuming UNKNOWN_HTTP is 0
        self.assertIn("zero", output_data)

    def test_compile_banner(self):
        banner = compile_banner(msg_size=123, code="HTTP/1.1 200 OK")
        expected = "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n"
        self.assertEqual(banner, expected)

    def test_honey_generic(self):
        face = "webdav.xml"
        output_data = honey_generic(face)
        self.assertIn("webdav.xml", output_data)

if __name__ == '__main__':
    unittest.main()
