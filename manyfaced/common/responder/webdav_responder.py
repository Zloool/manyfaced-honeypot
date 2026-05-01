"""
WebDAV responder module.

Generates realistic WebDAV responses that encourage deeper exploitation.
Adapts responses based on the bot's behavior and escalation level.

Usage:
    from manyfaced.common.responder.webdav_responder import WebDAVResponder

    responder = WebDAVResponder(ai_responder=ai_responder)
    response_bytes, detected = responder.generate_response(
        path="/webdav/",
        raw_request="PROPFIND /webdav/ HTTP/1.1...",
        bot_ip="1.2.3.4",
    )
"""

from __future__ import annotations

import datetime

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.responder.responder_base import ResponderBase

logger = get_logger(__name__)


class WebDAVResponder(ResponderBase):
    """WebDAV honeypot responder.

    Generates realistic WebDAV responses that:
    - Match the expected service type
    - Contain subtle vulnerability indicators
    - Encourage further probing
    - Adapt to the bot's behavior and escalation level
    """

    domain = "webdav"

    # Path patterns that this responder handles
    PATH_PATTERNS = [
        "/webdav", "/webdav/", "/webdav/index.php",
        "/dav", "/dav/", "/dav/index.php",
        "/files", "/files/", "/files/index.php",
    ]

    def __init__(self, ai_responder=None, enabled: bool = True):
        """Initialize the WebDAV responder.

        Args:
            ai_responder: Optional AIResponder instance
            enabled: Whether this responder is active
        """
        super().__init__(ai_responder=ai_responder, enabled=enabled)

    def matches_path(self, path: str) -> bool:
        """Check if this responder should handle the given path."""
        path_lower = path.lower().split("?")[0]
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict | None = None,
    ) -> tuple[bytes, int]:
        """Generate a WebDAV response for the given request.

        Args:
            path: The URL path
            raw_request: The raw HTTP request string
            bot_ip: The bot's IP address
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag)
        """
        if not self.enabled:
            return self._static_response(path, raw_request), 1

        # Get or create bot profile
        profile = self.get_or_create_profile(bot_ip)

        # Record the request
        request_data = {
            "path": path,
            "method": self._extract_method(raw_request),
            "headers": dict(headers) if headers else {},
            "raw": raw_request,
            "timestamp": str(datetime.datetime.now(datetime.timezone.utc)),
        }
        profile.record_request(request_data)

        # Try AI-powered response first
        ai_result = self._try_ai_response(path, raw_request, bot_ip, headers)
        if ai_result is not None:
            response_text, detected = ai_result
            response_bytes = self._build_http_response(response_text, path)
        else:
            response_bytes, detected = self._static_response(path, raw_request), 1

        # Record the response
        response_data = {
            "status_code": 200,
            "body": response_bytes.decode("iso-8859-1", errors="replace")[:500],
            "content_type": "text/html; charset=UTF-8",
            "timestamp": str(datetime.datetime.now(datetime.timezone.utc)),
        }
        profile.record_response(response_data)
        self._response_count += 1

        return response_bytes, detected

    def get_response_template(self) -> str:
        """Return the response template for AI generation."""
        return """\
You are a vulnerable WebDAV server running Apache with mod_dav enabled.
A bot from {bot_ip} has requested {path} using {method}.

Bot profile:
- Escalation level: {escalation_level} ({escalation_label})
- Detected behaviors: {detected_behaviors}
- Bot personality: {bot_personality}
- This is request #{request_count} from this bot
- This is response #{response_count} to this bot
- Previously explored paths: {explored_paths}

Generate a realistic WebDAV response that:
1. Matches the expected service type (PROPFIND, OPTIONS, etc.)
2. Contains vulnerability indicators appropriate for the escalation level:
   - Level 0-1: Basic directory listing with file hints
   - Level 2: Error message with server version info
   - Level 3: Debug output with file system paths
   - Level 4+: Deep debug info, potential upload vulnerabilities
3. Leaves hints of additional attack surfaces (e.g., "uploads/", "config/")
4. Is technically accurate for HTTP/1.1 with proper WebDAV headers

Return ONLY the response body (not HTTP headers). Keep it concise.
"""

    def _static_response(self, path: str, raw_request: str) -> bytes:
        """Generate a static WebDAV response."""
        method = self._extract_method(raw_request)

        if method == "OPTIONS":
            body = self._options_response()
        elif method == "PROPFIND":
            body = self._propfind_response(path)
        elif method == "MKCOL":
            body = self._mkcol_response(path)
        elif method == "PUT":
            body = self._put_response(path)
        elif method == "DELETE":
            body = self._delete_response(path)
        else:
            body = self._propfind_response(path)

        return self._build_http_response(body, path, method)

    def _options_response(self) -> str:
        """Generate an OPTIONS response."""
        return """\
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/webdav/</D:href>
    <D:propstat>
      <D:prop>
        <D:supportedlock>
          <D:lockentry>
            <D:lockscope><D:exclusive/></D:lockscope>
            <D:locktype><D:write/></D:locktype>
          </D:lockentry>
        </D:supportedlock>
        <D:resourcetype/>
        <D:displayname>WebDAV Server</displayname>
        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>
        <D:getlastmodified>Wed, 15 Apr 2026 10:00:00 GMT</D:getlastmodified>
        <D:getetag>"4d67-5f0a-6487-42c0"</D:getetag>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
<!-- Apache/2.4.7 (Ubuntu) mod_dav/1.0.3 -->"""

    def _propfind_response(self, path: str) -> str:
        """Generate a PROPFIND response."""
        # Generate a realistic directory listing
        files = [
            {"name": "index.php", "size": 1024, "modified": "2026-04-15T10:00:00Z"},
            {"name": "config.php", "size": 512, "modified": "2026-04-15T10:00:00Z"},
            {"name": "uploads/", "size": 0, "modified": "2026-04-15T10:00:00Z", "is_dir": True},
            {"name": "backup/", "size": 0, "modified": "2026-04-15T10:00:00Z", "is_dir": True},
            {"name": ".htaccess", "size": 256, "modified": "2026-04-15T10:00:00Z"},
            {"name": "wp-config.php.bak", "size": 2048, "modified": "2026-04-15T10:00:00Z"},
        ]

        xml = '<?xml version="1.0" encoding="utf-8"?>\n'
        xml += '<D:multistatus xmlns:D="DAV:">\n'
        xml += '  <D:response>\n'
        xml += f'    <D:href>{path}</D:href>\n'
        xml += '    <D:propstat>\n'
        xml += '      <D:prop>\n'
        xml += '        <D:resourcetype><D:collection/></D:resourcetype>\n'
        xml += '        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n'
        xml += '        <D:getlastmodified>Wed, 15 Apr 2026 10:00:00 GMT</D:getlastmodified>\n'
        xml += '        <D:getetag>"4d67-5f0a-6487-42c0"</D:getetag>\n'
        xml += '      </D:prop>\n'
        xml += '      <D:status>HTTP/1.1 200 OK</D:status>\n'
        xml += '    </D:propstat>\n'
        xml += '  </D:response>\n'

        for file in files:
            xml += '  <D:response>\n'
            xml += f'    <D:href>{path}{file["name"]}</D:href>\n'
            xml += '    <D:propstat>\n'
            xml += '      <D:prop>\n'
            if file.get("is_dir"):
                xml += '        <D:resourcetype><D:collection/></D:resourcetype>\n'
            else:
                xml += f'        <D:getcontentlength>{file["size"]}</D:getcontentlength>\n'
                xml += '        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n'
            xml += f'        <D:getlastmodified>{file["modified"]}</D:getlastmodified>\n'
            xml += f'        <D:getetag>"{hash(file["name"])}"</D:getetag>\n'
            xml += '      </D:prop>\n'
            xml += '      <D:status>HTTP/1.1 200 OK</D:status>\n'
            xml += '    </D:propstat>\n'
            xml += '  </D:response>\n'

        xml += '</D:multistatus>\n'
        xml += '<!-- Apache/2.4.7 (Ubuntu) mod_dav/1.0.3 -->'
        return xml

    def _mkcol_response(self, path: str) -> str:
        """Generate a MKCOL response."""
        return """\
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>{path}</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 201 Created</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
<!-- Apache/2.4.7 (Ubuntu) mod_dav/1.0.3 -->""".format(path=path)

    def _put_response(self, path: str) -> str:
        """Generate a PUT response."""
        return """\
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>{path}</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontentlength>0</D:getcontentlength>
        <D:getlastmodified>Wed, 15 Apr 2026 10:00:00 GMT</D:getlastmodified>
        <D:getetag>"new-etag"</D:getetag>
      </D:prop>
      <D:status>HTTP/1.1 201 Created</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
<!-- Apache/2.4.7 (Ubuntu) mod_dav/1.0.3 | File uploaded successfully -->""".format(path=path)

    def _delete_response(self, path: str) -> str:
        """Generate a DELETE response."""
        return """\
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>{path}</D:href>
    <D:propstat>
      <D:status>HTTP/1.1 204 No Content</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
<!-- Apache/2.4.7 (Ubuntu) mod_dav/1.0.3 | File deleted -->""".format(path=path)

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _build_http_response(self, body: str, path: str, method: str) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_type = "application/xml; charset=utf-8"

        # Determine status code based on method
        status = "207 Multi-Status"
        if method == "OPTIONS":
            status = "200 OK"
        elif method == "MKCOL":
            status = "201 Created"
        elif method == "DELETE":
            status = "204 No Content"

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: Apache/2.4.7 (Ubuntu)\r\n"
            f"DAV: 1\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return f"WebDAVResponder(domain={self.domain!r}, enabled={self.enabled})"
