from http.server import BaseHTTPRequestHandler
from io import StringIO
from http import HTTPStatus
import http
import email.parser
import email.message

class HTTPRequest(BaseHTTPRequestHandler):
    """
    This class is just an incapsulation of BaseHTTPRequestHandler, so it can be
    created from string.
    Code from:
    http://stackoverflow.com/questions/2115410/does-python-have-a-module-for-parsing-http-requests-and-responses

    print request.command          # "GET"
    print request.path             # "/who/ken/trust.html"
    print request.request_version  # "HTTP/1.1"
    print len(request.headers)     # 3
    print request.headers.keys()   # ['accept-charset', 'host', 'accept']
    print request.headers['host']  # "cm.bell-labs.com"
    """

    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.data = request_text

    def send_error(self, code, message, idk):
        self.error_code = code
        self.error_message = message

    def parse_request(self):
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        #requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = self.raw_requestline
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            command, path, version = words
            try:
                if version[:5] != 'HTTP/':
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
        elif len(words) == 2:
            command, path = words
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % command)
                return False
        elif not words:
            return False
        else:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % requestline)
            return False
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive.
        try:
            self.headers = HTTPRequest.parse_headers(self.rfile,
                                                        _class=self.MessageClass)
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
                self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def parse_headers(fp, _class=http.client.HTTPMessage):
        headers = []
        _MAXLINE = 65536
        _MAXHEADERS = 100
        while True:
            line = fp.readline(_MAXLINE + 1).encode()
            if len(line) > _MAXLINE:
                raise http.client.LineTooLong("header line")
            headers.append(line)
            if len(headers) > _MAXHEADERS:
                raise http.client.HTTPException("got more than %d headers" % _MAXHEADERS)
            if line in (b'\r\n', b'\n', b''):
                break
        hstring = b''.join(headers).decode('iso-8859-1')
        return email.parser.Parser(_class=_class).parsestr(hstring)
