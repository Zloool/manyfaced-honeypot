"""Regression tests for issue #638: CVE-2025-29927 Next.js RCE probes arriving on
non-HTTP ports (e.g. the SMB-redirect port 10445) must be attributed to the
Next.js face (NEXTJS_HTTP) rather than the generic HTTP_ON_NONHTTP_PORT sentinel.
"""

from manyfaced.client.client import (
    _http_mismatch_detected_id,
    _is_nextjs_cve_2025_29927,
)
from manyfaced.common.status import HTTP_ON_NONHTTP_PORT, NEXTJS_HTTP


def _cve_body() -> bytes:
    return (
        b'POST / HTTP/1.1\r\n'
        b'Host: 68.183.114.1:10445\r\n'
        b'Content-Type: multipart/form-data; boundary=x\r\n'
        b'x-middleware-subrequest: /\r\n'
        b'\r\n'
        b'--x\r\n'
        b'Content-Disposition: form-data; name="1"\r\n\r\n'
        b'"$@0"\r\n'
        b'--x\r\n'
        b'Content-Disposition: form-data; name="0"\r\n\r\n'
        b'{"then":"$1:__proto__:then", "_response": {"$B": "NEXT_REDIRECT"}}\r\n'
        b'--x--\r\n'
    )


def _normal_http() -> bytes:
    return b'GET / HTTP/1.1\r\nHost: 68.183.114.1\r\n\r\n'


class TestNextjsCveCrossPort:
    def test_cve_body_detected(self):
        assert _is_nextjs_cve_2025_29927(_cve_body()) is True

    def test_normal_http_not_detected(self):
        assert _is_nextjs_cve_2025_29927(_normal_http()) is False

    def test_cve_mismatch_attributed_to_nextjs(self):
        # An HTTP frame carrying the CVE body on a NON-HTTP port must be
        # attributed to the Next.js face, not the generic HTTP_ON_NONHTTP_PORT.
        assert _http_mismatch_detected_id(_cve_body()) == NEXTJS_HTTP

    def test_plain_http_mismatch_stays_http_on_nonhttp(self):
        assert _http_mismatch_detected_id(_normal_http()) == HTTP_ON_NONHTTP_PORT

    def test_header_only_marker_detected(self):
        raw = b'GET / HTTP/1.1\r\nx-middleware-subrequest: /_next\r\n\r\n'
        assert _is_nextjs_cve_2025_29927(raw) is True
