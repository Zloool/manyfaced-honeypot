"""TomcatHandler – handles Apache Tomcat specific paths and interactions.

Provides realistic Tomcat responses including:
- Manager webapp (/manager/html)
- Host Manager (/host-manager/html)
- ROOT application (/)
- Status pages (/server-status)
- Captures login credentials from POST requests
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class TomcatHandler(HTTPHandlerBase):
    """Apache Tomcat honeypot handler."""

    domain = 'tomcat'
    PATH_PATTERNS = [
        '/manager',
        '/manager/',
        '/manager/html',
        '/host-manager',
        '/host-manager/',
        '/host-manager/html',
        '/tomcat',
        '/tomcat/',
        '/server-status',
        '/server-info',
        '/jmxproxy',
        '/jmxproxy/',
        '/examples',
        '/examples/',
        '/ROOT',
        '/ROOT/',
    ]
    DETECTED_ID = 1

    def matches_path(self, path: str) -> bool:
        """Check if this handler should handle the given path."""
        path_lower = path.lower().split('?')[0]
        return any(path_lower.startswith(pattern) for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Tomcat response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {
            'path': path,
            'method': self._extract_method(raw_request),
            'headers': dict(headers) if headers else {},
            'raw': raw_request,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        path_lower = path.lower()

        # Handle login POST requests
        if method == 'POST' and 'j_security_check' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if 'manager/html' in path_lower:
            body = self._manager_page()
        elif 'host-manager/html' in path_lower:
            body = self._host_manager_page()
        elif 'server-status' in path_lower:
            body = self._server_status()
        elif 'server-info' in path_lower:
            body = self._server_info()
        elif 'examples' in path_lower:
            body = self._examples_page()
        elif 'jmxproxy' in path_lower:
            body = self._jmx_proxy()
        else:
            body = self._root_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

    def _manager_page(self) -> str:
        """Generate the Tomcat Manager page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tomcat Manager</title>
    <link rel="stylesheet" href="/manager/css/tomcat.css" type="text/css">
</head>
<body>
    <div id="wrapper">
        <h1>Tomcat Web Application Manager</h1>
        <p>Apache Tomcat/9.0.87</p>
        <div id="manager">
            <h2>Manager</h2>
            <table>
                <tr><th>Path</th><th>Status</th><th>Running</th><th>Session Count</th></tr>
                <tr><td>/manager</td><td>OK</td><td>true</td><td>0</td></tr>
                <tr><td>/host-manager</td><td>OK</td><td>true</td><td>0</td></tr>
                <tr><td>/ROOT</td><td>OK</td><td>true</td><td>2</td></tr>
                <tr><td>/examples</td><td>OK</td><td>true</td><td>0</td></tr>
            </table>
            <h2>Actions</h2>
            <form action="/manager/html/deploy" method="post">
                <h3>Deploy web application</h3>
                <p>
                    <label for="war">WAR file to deploy:</label>
                    <input type="file" name="war" id="war" />
                    <input type="submit" value="Deploy" />
                </p>
            </form>
            <form action="/manager/html/undeploy" method="post">
                <h3>Undeploy web application</h3>
                <p>
                    <label for="path">Path:</label>
                    <select name="path" id="path">
                        <option value="/manager">/manager</option>
                        <option value="/host-manager">/host-manager</option>
                        <option value="/ROOT">/ROOT</option>
                        <option value="/examples">/examples</option>
                    </select>
                    <input type="submit" value="Undeploy" />
                </p>
            </form>
        </div>
        <div class="info">
            <p>Server Information:</p>
            <table>
                <tr><td>Catalina Base</td><td>/opt/tomcat</td></tr>
                <tr><td>OS</td><td>Linux 5.15.0-91-generic</td></tr>
                <tr><td>Java Home</td><td>/usr/lib/jvm/java-17-openjdk-amd64</td></tr>
                <tr><td>Java Version</td><td>17.0.9 (Eclipse Adoptium)</td></tr>
                <tr><td>Java VM</td><td>OpenJDK 64-Bit Server VM 17.0.9+9</td></tr>
                <tr><td>Memory</td><td>134 MB / 512 MB</td></tr>
            </table>
        </div>
    </div>
</body>
</html>"""

    def _host_manager_page(self) -> str:
        """Generate the Host Manager page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head><title>Tomcat Virtual Host Manager</title></head>
<body>
    <div id="wrapper">
        <h1>Tomcat Virtual Host Manager</h1>
        <p>Apache Tomcat/9.0.87</p>
        <div id="manager">
            <h2>Hosts</h2>
            <table>
                <tr><th>Host Name</th><th>Alias</th><th>App Base</th><th>Auto Deploy</th></tr>
                <tr><td>localhost</td><td>-</td><td>/var/lib/tomcat9/webapps</td><td>true</td></tr>
                <tr><td>example.com</td><td>www.example.com</td><td>/var/www/example.com</td><td>true</td></tr>
                <tr><td>staging.example.com</td><td>-</td><td>/var/www/staging</td><td>true</td></tr>
            </table>
            <h2>Actions</h2>
            <form action="/host-manager/html/add" method="post">
                <h3>Add Virtual Host</h3>
                <p>
                    <label for="name">Host Name:</label>
                    <input type="text" name="name" id="name" />
                    <label for="appBase">App Base:</label>
                    <input type="text" name="appBase" id="appBase" value="/var/www/{name}" />
                    <input type="submit" value="Add" />
                </p>
            </form>
        </div>
    </div>
</body>
</html>"""

    def _server_status(self) -> str:
        """Generate the server status page."""
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head><title>Server Status</title></head>
<body>
    <h1>Server Status</h1>
    <p>Apache Tomcat/9.0.87</p>
    <h2>Overall Statistics</h2>
    <table>
        <tr><td>Total requests served</td><td>124,567</td></tr>
        <tr><td>Total bytes served</td><td>456,789,012</td></tr>
        <tr><td>Current thread count</td><td>42</td></tr>
        <tr><td>Current thread busy</td><td>8</td></tr>
    </table>
    <h2>Worker Status</h2>
    <table>
        <tr><th>Worker Name</th><th>State</th><th>Busy Time</th><th>Request Count</th></tr>
        <tr><td>ajp-http-8009-1</td><td>idle</td><td>0.001s</td><td>12,345</td></tr>
        <tr><td>ajp-http-8009-2</td><td>idle</td><td>0.002s</td><td>12,340</td></tr>
        <tr><td>ajp-http-8009-3</td><td>processing</td><td>0.500s</td><td>12,335</td></tr>
    </table>
    <h2>Connector Status</h2>
    <table>
        <tr><th>Connector</th><th>Port</th><th>State</th></tr>
        <tr><td>HTTP/1.1</td><td>8080</td><td>Running</td></tr>
        <tr><td>AJP/1.3</td><td>8009</td><td>Running</td></tr>
        <tr><td>HTTPS/1.1</td><td>8443</td><td>Running</td></tr>
    </table>
    <p>Last updated: {now}</p>
</body>
</html>"""

    def _server_info(self) -> str:
        """Generate the server info page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head><title>Server Information</title></head>
<body>
    <h1>Server Information</h1>
    <h2>Server Information</h2>
    <table>
        <tr><td>Server info</td><td>Apache Tomcat/9.0.87</td></tr>
        <tr><td>Server number</td><td>0.0.0.0</td></tr>
        <tr><td>OS</td><td>Linux 5.15.0-91-generic</td></tr>
        <tr><td>Java Home</td><td>/usr/lib/jvm/java-17-openjdk-amd64</td></tr>
        <tr><td>Servlet spec</td><td>6.0</td></tr>
        <tr><td>JSP spec</td><td>3.1</td></tr>
        <tr><td>WebSocket spec</td><td>2.1</td></tr>
    </table>
    <h2>Connector Information</h2>
    <table>
        <tr><th>Protocol</th><th>Port</th><th>Address</th></tr>
        <tr><td>HTTP/1.1</td><td>8080</td><td>0.0.0.0</td></tr>
        <tr><td>AJP/1.3</td><td>8009</td><td>0.0.0.0</td></tr>
    </table>
</body>
</html>"""

    def _examples_page(self) -> str:
        """Generate the examples page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head><title>Tomcat Examples</title></head>
<body>
    <h1>Tomcat Examples</h1>
    <p>Apache Tomcat/9.0.87</p>
    <h2>Servlet Examples</h2>
    <ul>
        <li><a href="/examples/servlets/">Servlets</a></li>
        <li><a href="/examples/servlets/servlet/HelloWorldExample">Hello World</a></li>
        <li><a href="/examples/servlets/servlet/RequestInfoExample">Request Info</a></li>
        <li><a href="/examples/servlets/servlet/RequestParamExample">Request Parameters</a></li>
        <li><a href="/examples/servlets/servlet/ServletConfigExample">Servlet Config</a></li>
    </ul>
    <h2>JSP Examples</h2>
    <ul>
        <li><a href="/examples/jsp/">JSP Examples</a></li>
        <li><a href="/examples/jsp/snp/snoop.html">Servlet Snippet</a></li>
        <li><a href="/examples/jsp/cal/">Calendar</a></li>
        <li><a href="/examples/jsp/checkbox/">Checkbox</a></li>
        <li><a href="/examples/jsp/colors/">Color Chaser</a></li>
    </ul>
    <h2>WebSocket Examples</h2>
    <ul>
        <li><a href="/examples/websocket/">WebSocket</a></li>
    </ul>
</body>
</html>"""

    def _jmx_proxy(self) -> str:
        """Generate the JMX proxy page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head><title>JMX Proxy</title></head>
<body>
    <h1>JMX Proxy</h1>
    <p>Apache Tomcat/9.0.87</p>
    <div class="info">
        <p>JMX Proxy allows you to query Tomcat's JMX beans via HTTP.</p>
        <p>Available beans:</p>
        <ul>
            <li>Catalina:type=Server</li>
            <li>Catalina:type=Service</li>
            <li>Catalina:type=Connector,protocol="HTTP/1.1"</li>
            <li>Catalina:type=Engine</li>
            <li>Catalina:type=Host</li>
            <li>Catalina:type=WebappLoader</li>
        </ul>
        <p>Warning: JMX Proxy should be disabled in production environments.</p>
    </div>
</body>
</html>"""

    def _root_page(self) -> str:
        """Generate the ROOT page."""
        return """\
<!DOCTYPE html>
<html lang="en">
<head><title>Apache Tomcat/9.0.87</title></head>
<body>
    <h1>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h1>
    <h2>Important</h2>
    <p>Tomcat has been installed with a default configuration. You should review the configuration files and adjust settings as necessary.</p>
    <p>Configuration files:</p>
    <ul>
        <li>/opt/tomcat/conf/server.xml</li>
        <li>/opt/tomcat/conf/web.xml</li>
        <li>/opt/tomcat/conf/tomcat-users.xml</li>
    </ul>
    <p>Default credentials in tomcat-users.xml:</p>
    <pre>
&lt;tomcat-users&gt;
  &lt;role rolename="manager-gui"/&gt;
  &lt;role rolename="admin-gui"/&gt;
  &lt;user username="admin" password="admin123" roles="manager-gui,admin-gui"/&gt;
  &lt;user username="tomcat" password="tomcat" roles="manager-gui"/&gt;
&lt;/tomcat-users&gt;
    </pre>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Return a fake login failed response."""
        body = """\
<!DOCTYPE html>
<html lang="en">
<head><title>HTTP Status 401 – Unauthorized</title></head>
<body>
    <h1>HTTP Status 401 – Unauthorized</h1>
    <p>Authentication is required to access this resource.</p>
    <p>Please log in with valid credentials.</p>
    <form action="/manager/html/j_security_check" method="post">
        <p>
            <label for="j_username">Username:</label>
            <input type="text" name="j_username" id="j_username" />
        </p>
        <p>
            <label for="j_password">Password:</label>
            <input type="password" name="j_password" id="j_password" />
        </p>
        <input type="submit" value="Login" />
    </form>
    <p>Apache Tomcat/9.0.87</p>
</body>
</html>"""
        return self._build_http_response(body, '/manager/html', '401 Unauthorized')

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(self, body: str, path: str, status: str = '200 OK') -> bytes:
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status}\r\n'
            f'Server: Apache-Coyote/1.1\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: text/html;charset=UTF-8\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'TomcatHandler(domain={self.domain!r})'
