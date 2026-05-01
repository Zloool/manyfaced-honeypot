"""WebDAVHandler – handles WebDAV specific paths and interactions.

Provides realistic WebDAV responses including:
- WebDAV directory listing (HTML)
- WebDAV PROPFIND responses (XML)
- WebDAV PUT/POST file upload attempts
- Captures credentials from Basic Auth headers

WebDAV (Web Distributed Authoring and Versioning) is a common target
for file upload exploits and credential harvesting.
"""

from __future__ import annotations

import datetime
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class WebDAVHandler(HTTPHandlerBase):
    """WebDAV honeypot handler."""

    domain = "webdav"
    PATH_PATTERNS = [
        "/webdav/", "/webdav",
        "/dav/", "/dav",
        "/files/", "/files",
        "/uploads/", "/uploads",
        "/share/", "/share",
        "/public/", "/public",
        "/remote/", "/remote",
        "/remote.php/", "/remote.php",
        "/caldav/", "/caldav",
        "/carddav/", "/carddav",
        "/.well-known/webdav",
        "/webdav/server.php",
        "/webdav/index.php",
        "/webdav/upload.php",
        "/webdav/download.php",
        "/webdav/list.php",
        "/webdav/proxy.php",
        "/webdav/dav.php",
        "/webdav/propfind.php",
        "/webdav/mkcol.php",
        "/webdav/put.php",
        "/webdav/delete.php",
        "/webdav/move.php",
        "/webdav/copy.php",
        "/webdav/lock.php",
        "/webdav/unlock.php",
        "/webdav/checkout.php",
        "/webdav/checkin.php",
        "/webdav/working_copy/",
        "/webdav/version.xml",
        "/webdav/lockdiscovery/",
        "/webdav/locks/",
        "/webdav/temp/",
        "/webdav/.htaccess",
        "/webdav/.htpasswd",
        "/webdav/config.php",
        "/webdav/setup.php",
        "/webdav/admin/",
        "/webdav/login/",
        "/webdav/auth/",
    ]
    DETECTED_ID = 1

    def matches_path(self, path: str) -> bool:
        """Check if this handler should handle the given path."""
        path_lower = path.lower().split("?")[0]
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a WebDAV response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {
            "path": path,
            "method": self._extract_method(raw_request),
            "headers": dict(headers) if headers else {},
            "raw": raw_request,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        path_lower = path.lower()
        headers_dict = dict(headers) if headers else {}

        # Extract Basic Auth credentials if present
        auth_header = headers_dict.get("Authorization", "")
        if auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8", errors="replace")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    profile.capture_credentials({"username": username, "password": password})
            except Exception:
                pass

        # Handle PROPFIND requests (WebDAV directory listing)
        if method == "PROPFIND":
            body = self._propfind_response(path)
            return self._build_http_response(body, 207, "Multi-Status", {
                "Content-Type": "application/xml; charset=utf-8",
                "DAV": "1, 2",
            }), self.DETECTED_ID

        # Handle OPTIONS requests (WebDAV capabilities probe)
        if method == "OPTIONS":
            return self._options_response()

        # Handle MKCOL requests (create directory)
        if method == "MKCOL":
            return self._build_http_response(b"", 201, "Created"), self.DETECTED_ID

        # Handle DELETE requests
        if method == "DELETE":
            return self._build_http_response(b"", 204, "No Content"), self.DETECTED_ID

        # Handle PUT requests (file upload attempt)
        if method == "PUT":
            profile.record_request({
                "path": path,
                "method": method,
                "headers": headers_dict,
                "raw": raw_request[:5000] + (" [truncated]" if len(raw_request) > 5000 else ""),
                "timestamp": datetime.datetime.utcnow().isoformat(),
            })
            profile.escalation_label = "file_upload_attempt"
            return self._build_http_response(
                b"", 201, "Created",
                {"Content-Type": "text/html; charset=utf-8"},
            ), self.DETECTED_ID

        # Handle POST requests (upload, login, etc.)
        if method == "POST":
            # Check for login POST
            if "login" in path_lower or "auth" in path_lower:
                credentials, response, detected = self.handle_login(path, raw_request, bot_ip, headers_dict)
                if credentials:
                    return self._login_failed_response()
            # Check for file upload POST
            content_type = headers_dict.get("Content-Type", "")
            if "multipart/form-data" in content_type or "application/octet-stream" in content_type:
                profile.record_request({
                    "path": path,
                    "method": method,
                    "headers": headers_dict,
                    "raw": raw_request[:5000] + (" [truncated]" if len(raw_request) > 5000 else ""),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                })
                profile.escalation_label = "file_upload_attempt"
                return self._build_http_response(
                    b"", 201, "Created",
                    {"Content-Type": "text/html; charset=utf-8"},
                ), self.DETECTED_ID

        # Handle GET requests (directory listing)
        if method == "GET":
            if "/server.php" in path_lower or "/index.php" in path_lower:
                body = self._webdav_portal_page()
            elif "/.htaccess" in path_lower or "/.htpasswd" in path_lower:
                return self._forbidden_response()
            elif "/config.php" in path_lower or "/setup.php" in path_lower:
                return self._forbidden_response()
            elif "/admin/" in path_lower or "/login/" in path_lower or "/auth/" in path_lower:
                body = self._webdav_login_page()
            else:
                body = self._directory_listing(path)

            return self._build_http_response(body, 200, "OK", {
                "Content-Type": "text/html; charset=utf-8",
                "DAV": "1, 2",
            }), self.DETECTED_ID

        # Handle other methods (HEAD, PATCH, COPY, MOVE, LOCK, UNLOCK)
        if method in ("HEAD", "PATCH", "COPY", "MOVE", "LOCK", "UNLOCK"):
            profile.escalation_label = f"webdav_{method.lower()}_attempt"
            return self._build_http_response(b"", 200, "OK"), self.DETECTED_ID

        # Default: 405 Method Not Allowed
        return self._build_http_response(b"", 405, "Method Not Allowed", {
            "Allow": "GET, HEAD, POST, OPTIONS, PROPFIND, MKCOL, PUT, DELETE, MOVE, COPY",
        }), self.DETECTED_ID

    def _directory_listing(self, path: str) -> str:
        """Generate a WebDAV directory listing page."""
        # Extract the directory name from the path
        dir_name = path.rstrip("/").split("/")[-1] or "webdav"
        now = datetime.datetime.utcnow().strftime("%d %b %Y %H:%M:%S GMT")

        return f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /{dir_name}</title>
 </head>
 <body>
<h1>Index of /{dir_name}</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a>       </td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="documents/">documents/</a>                </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="uploads/">uploads/</a>                    </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="shared/">shared/</a>                     </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="config/">config/</a>                     </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href=".htaccess">.htaccess</a>                   </td><td align="right">{now}</td><td align="right"> 128 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href=".htpasswd">.htpasswd</a>                   </td><td align="right">{now}</td><td align="right"> 256 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="index.php">index.php</a>                   </td><td align="right">{now}</td><td align="right"> 4096 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="server.php">server.php</a>                  </td><td align="right">{now}</td><td align="right"> 8192 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="upload.php">upload.php</a>                  </td><td align="right">{now}</td><td align="right"> 2048 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="download.php">download.php</a>                </td><td align="right">{now}</td><td align="right"> 1024 </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.57 (Ubuntu) Server at webdav.example.com Port 80</address>
</body>
</html>"""

    def _propfind_response(self, path: str) -> str:
        """Generate a WebDAV PROPFIND XML response."""
        dir_name = path.rstrip("/").split("/")[-1] or "webdav"
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

        return f"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:ns0="http://apache.org/dav/props/" xmlns:ns1="DAV:">
  <d:response>
    <d:href>/</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
      <d:prop>
        <d:creationdate>{datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}</d:creationdate>
        <d:displayname>webdav</d:displayname>
        <d:getcontentlength>0</d:getcontentlength>
        <d:getlastmodified>{now}</d:getlastmodified>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
        <d:supportedlock>
          <d:lockentry>
            <d:lockscope>
              <d:exclusive/>
            </d:lockscope>
            <d:locktype>
              <d:write/>
            </d:locktype>
          </d:lockentry>
          <d:lockentry>
            <d:lockscope>
              <d:shared/>
            </d:lockscope>
            <d:locktype>
              <d:write/>
            </d:locktype>
          </d:lockentry>
        </d:supportedlock>
        <d:lockdiscovery/>
        <ns0:readable/>
        <ns0:writable/>
      </d:prop>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/{dir_name}/documents/</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
      <d:prop>
        <d:creationdate>{datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}</d:creationdate>
        <d:displayname>documents</d:displayname>
        <d:getcontentlength>0</d:getcontentlength>
        <d:getlastmodified>{now}</d:getlastmodified>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
      </d:prop>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/{dir_name}/uploads/</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
      <d:prop>
        <d:creationdate>{datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}</d:creationdate>
        <d:displayname>uploads</d:displayname>
        <d:getcontentlength>0</d:getcontentlength>
        <d:getlastmodified>{now}</d:getlastmodified>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
      </d:prop>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/{dir_name}/shared/</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
      <d:prop>
        <d:creationdate>{datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}</d:creationdate>
        <d:displayname>shared</d:displayname>
        <d:getcontentlength>0</d:getcontentlength>
        <d:getlastmodified>{now}</d:getlastmodified>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
      </d:prop>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/{dir_name}/config/</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
      <d:prop>
        <d:creationdate>{datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}</d:creationdate>
        <d:displayname>config</d:displayname>
        <d:getcontentlength>0</d:getcontentlength>
        <d:getlastmodified>{now}</d:getlastmodified>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
      </d:prop>
    </d:propstat>
  </d:response>
</d:multistatus>"""

    def _options_response(self) -> bytes:
        """Generate WebDAV OPTIONS response (capabilities probe)."""
        return self._build_http_response(
            b"", 200, "OK",
            {
                "DAV": "1, 2",
                "MS-Author-Via": "DAV",
                "Allow": "GET, HEAD, POST, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, PUT, DELETE",
            },
        ), self.DETECTED_ID

    def _webdav_portal_page(self) -> str:
        """WebDAV portal/index page."""
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>WebDAV Server</title>
 </head>
 <body>
<h1>WebDAV Server</h1>
<p>This is a WebDAV server. Use a WebDAV client to connect.</p>
<p>Supported methods: GET, HEAD, POST, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, PUT, DELETE</p>
<p>Try using <code>PROPFIND</code> to list directories or <code>PUT</code> to upload files.</p>
<p><a href="/">/</a> | <a href="/webdav/">/webdav/</a> | <a href="/dav/">/dav/</a></p>
<address>Apache/2.4.57 (Ubuntu) Server with mod_dav</address>
</body>
</html>"""

    def _webdav_login_page(self) -> str:
        """WebDAV login page."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>WebDAV - Authentication Required</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; text-align: center; padding: 50px; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #333; }
        .form-group { margin-bottom: 15px; text-align: left; }
        label { display: block; margin-bottom: 5px; color: #555; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { background: #007cba; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; }
    </style>
</head>
<body>
<div class="container">
    <h2>WebDAV Server Authentication</h2>
    <p>Please enter your credentials to access this WebDAV share.</p>
    <form method="POST" action="/webdav/login/">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" name="username" id="username">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" id="password">
        </div>
        <div class="form-group">
            <input type="submit" value="Login">
        </div>
    </form>
</div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """WebDAV login failed response."""
        body = """<!DOCTYPE html>
<html>
<head>
    <title>WebDAV - Authentication Failed</title>
</head>
<body>
<h2>Authentication Failed</h2>
<p>Invalid credentials. Please try again.</p>
<p><a href="/webdav/">Return to WebDAV</a></p>
</body>
</html>"""
        return self._build_http_response(body, 401, "Unauthorized"), self.DETECTED_ID[0]

    def _forbidden_response(self) -> bytes:
        """Return 403 Forbidden for sensitive files."""
        body = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>403 Forbidden</title>
 </head>
 <body>
<h1>403 Forbidden</h1>
<p>You don't have permission to access this file.</p>
</body>
</html>"""
        return self._build_http_response(body, 403, "Forbidden"), self.DETECTED_ID

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _build_http_response(self, body: str | bytes, status_code: int = 200, status_text: str = "OK", headers: dict | None = None) -> bytes:
        """Build a complete HTTP response."""
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body
        
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        
        resp_headers = {
            "Server": "Apache/2.4.57 (Ubuntu)",
            "Date": now,
            "Connection": "close",
        }
        if headers:
            resp_headers.update(headers)
        
        header_lines = []
        for key, value in resp_headers.items():
            header_lines.append(f"{key}: {value}")
        
        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            + "\r\n".join(header_lines) + "\r\n"
            + "\r\n"
        )
        
        return response.encode("iso-8859-1") + body_bytes

    def __repr__(self) -> str:
        return f"WebDAVHandler(domain={self.domain!r})"
