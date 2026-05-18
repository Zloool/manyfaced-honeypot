from http.server import BaseHTTPRequestHandler
from io import BytesIO


class HTTPRequest(BaseHTTPRequestHandler):
    """
    This class is just an incapsulation of BaseHTTPRequestHandler, so it can be
    created from string.
    Code from:
    http://stackoverflow.com/questions/2115410/does-python-have-a-module-for-parsing-http-requests-and-responses

    print(request.command)          # "GET"
    print request.path             # "/who/ken/trust.html"
    print request.request_version  # "HTTP/1.1"
    print len(request.headers)     # 3
    print request.headers.keys()   # ['accept-charset', 'host', 'accept']
    print request.headers['host']  # "cm.bell-labs.com"
    """

    def __init__(self, request_text):
        # Normalize input: ensure we work with bytes throughout
        if isinstance(request_text, str):
            # Encode to latin-1 (iso-8859-1) which accepts any byte value
            # Replace characters outside range with replacement char
            try:
                request_text = request_text.encode('iso-8859-1')
            except UnicodeEncodeError:
                request_text = (
                    request_text.encode('utf-8', errors='replace')
                    .decode('latin-1')
                    .encode('iso-8859-1')
                )
        elif isinstance(request_text, bytes):
            # Already bytes — use as-is (handles the case where raw socket data is passed)
            request_text = request_text
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.data = request_text
        if self.error_code is not None:
            raise ValueError(self.error_message or f'HTTP parse error: {self.error_code}')

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Override to capture error info without sending an actual HTTP response.

        The parent class sends a full error page; we just store the values
        for later inspection by the honeypot handler.
        """
        self.error_code = code
        self.error_message = message or ''
