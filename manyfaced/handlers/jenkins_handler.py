"""JenkinsHandler – handles Jenkins CI/CD specific paths and interactions.

Provides realistic Jenkins responses including:
- Login page (/jenkins/login)
- Jenkins console / main page
- API endpoints (/jenkins/api/)
- Captures login credentials from POST requests
- Returns realistic responses for Jenkins-specific paths
"""

from __future__ import annotations

import datetime
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class JenkinsHandler(HTTPHandlerBase):
    """Jenkins CI/CD honeypot handler."""

    domain = "jenkins"
    PATH_PATTERNS = [
        "/jenkins", "/jenkins/", "/jenkins/login",
        "/jenkins/script", "/jenkins/manage",
        "/jenkins/api", "/jenkins/computer",
        "/jenkins/view", "/jenkins/job",
        "/hudson", "/hudson/", "/hudson/login",
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
        """Generate a Jenkins response for the given request."""
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

        # Handle login POST requests
        if method == "POST" and ("login" in path_lower or "j_security_check" in raw_request):
            credentials, response, detected = self.handle_login(path, raw_request, bot_ip, headers or {})
            if credentials:
                # Fake "login failed" response (encourages brute force)
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if "login" in path_lower:
            body = self._login_page()
        elif "manage" in path_lower:
            body = self._manage_page()
        elif "api" in path_lower:
            body = self._api_response()
        elif "computer" in path_lower:
            body = self._computer_page()
        elif "script" in path_lower:
            body = self._script_console()
        elif "job" in path_lower or "view" in path_lower:
            body = self._job_page()
        else:
            body = self._main_page()

        response = self._build_http_response(body, path)
        self._response_count += 1

        return response, self.DETECTED_ID

    def _login_page(self) -> str:
        """Generate a Jenkins login page."""
        return """\
<!DOCTYPE html>
<html>
<head>
    <title>Login [Jenkins]</title>
    <link rel="stylesheet" href="/static/css/styles.css" />
</head>
<body class="jenkins-ng" data-version="2.426">
    <div id="main-panel">
        <h1>Jenkins [enter login credentials to login]</h1>
        <form action="/jenkins/j_acegi_security_check" method="post" id="login-form">
            <table>
                <tr>
                    <td><label for="j_username">Username:</label></td>
                    <td><input type="text" id="j_username" name="j_username" /></td>
                </tr>
                <tr>
                    <td><label for="j_password">Password:</label></td>
                    <td><input type="password" id="j_password" name="j_password" /></td>
                </tr>
                <tr>
                    <td><input type="checkbox" id="remember_me" name="remember_me" /></td>
                    <td><label for="remember_me">Remember me</label></td>
                </tr>
            </table>
            <input type="submit" value="Login" />
            <input type="hidden" name="from" value="/" />
        </form>
        <p>
            <a href="/jenkins/hudson/securityRealm/userPasswordReset/">Forgot password?</a>
        </p>
    </div>
    <div id="footer">
        <span class="jenkins-version">Jenkins ver. 2.426</span>
        <span> | </span>
        <span>Powered by Apache Maven/3.9.5 | Java/17.0.9</span>
    </div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Return a fake login failed response."""
        body = """\
<!DOCTYPE html>
<html>
<head>
    <title>Login [Jenkins]</title>
</head>
<body>
    <div id="main-panel">
        <h1>Jenkins [enter login credentials to login]</h1>
        <div class="error">
            <p>Invalid login credentials</p>
        </div>
        <form action="/jenkins/j_acegi_security_check" method="post" id="login-form">
            <table>
                <tr>
                    <td><label for="j_username">Username:</label></td>
                    <td><input type="text" id="j_username" name="j_username" /></td>
                </tr>
                <tr>
                    <td><label for="j_password">Password:</label></td>
                    <td><input type="password" id="j_password" name="j_password" /></td>
                </tr>
            </table>
            <input type="submit" value="Login" />
        </form>
    </div>
    <div id="footer">
        <span class="jenkins-version">Jenkins ver. 2.426</span>
    </div>
</body>
</html>"""
        return self._build_http_response(body, "/jenkins/login")

    def _main_page(self) -> str:
        """Generate the Jenkins main page."""
        return """\
<!DOCTYPE html>
<html>
<head>
    <title>Jenkins [Jenkins]</title>
</head>
<body>
    <div id="main-panel">
        <h1>Welcome to Jenkins!</h1>
        <div class="panel">
            <h2>Quick Start</h2>
            <ul>
                <li><a href="/jenkins/newJob">Create a new job</a></li>
                <li><a href="/jenkins/computer/">Manage nodes</a></li>
                <li><a href="/jenkins/manage/">System configuration</a></li>
            </ul>
        </div>
        <div class="panel">
            <h2>Recent Builds</h2>
            <table>
                <tr><th>Job</th><th>Status</th><th>Last Build</th></tr>
                <tr><td><a href="/jenkins/job/build-app/">build-app</a></td><td class="success">SUCCESS</td><td>2 hours ago</td></tr>
                <tr><td><a href="/jenkins/job/deploy-staging/">deploy-staging</a></td><td class="failure">FAILURE</td><td>5 hours ago</td></tr>
                <tr><td><a href="/jenkins/job/test-suite/">test-suite</a></td><td class="success">SUCCESS</td><td>1 day ago</td></tr>
            </table>
        </div>
        <div class="info">
            <p>Jenkins ver. 2.426 | Java 17.0.9 | Ubuntu 22.04.4 LTS</p>
            <p>Home: /var/lib/jenkins | Workspace: /var/lib/jenkins/workspace</p>
        </div>
    </div>
</body>
</html>"""

    def _manage_page(self) -> str:
        """Generate the Jenkins manage page."""
        return """\
<!DOCTYPE html>
<html>
<head><title>Manage Jenkins [Jenkins]</title></head>
<body>
    <div id="main-panel">
        <h1>Manage Jenkins</h1>
        <div class="panel">
            <h2>System Configuration</h2>
            <ul>
                <li><a href="/jenkins/manage/configure">Configure System</a></li>
                <li><a href="/jenkins/manage/plugins">Manage Plugins</a></li>
                <li><a href="/jenkins/manage/users">Manage Users</a></li>
                <li><a href="/jenkins/manage/credentials">Credentials</a></li>
            </ul>
        </div>
        <div class="panel">
            <h2>Jenkins Configuration</h2>
            <table>
                <tr><td>Jenkins URL</td><td>http://localhost:8080/jenkins/</td></tr>
                <tr><td>Java Home</td><td>/usr/lib/jvm/java-17-openjdk-amd64</td></tr>
                <tr><td>Node Mode</td><td>Master</td></tr>
                <tr><td>Remoting</td><td>Enabled</td></tr>
                <tr><td>Security Realm</td><td>Jenkins' own user database</td></tr>
                <tr><td>Authorization</td><td>Matrix-based strategy</td></tr>
            </table>
        </div>
    </div>
</body>
</html>"""

    def _api_response(self) -> str:
        """Generate an API response."""
        return """\
<?xml version="1.0" encoding="UTF-8"?>
<apiVersion>2.426</apiVersion>
<jobs>
    <job>
        <name>build-app</name>
        <url>http://localhost:8080/jenkins/job/build-app/</url>
        <color>blue</color>
    </job>
    <job>
        <name>deploy-staging</name>
        <url>http://localhost:8080/jenkins/job/deploy-staging/</url>
        <color>red</color>
    </job>
    <job>
        <name>test-suite</name>
        <url>http://localhost:8080/jenkins/job/test-suite/</url>
        <color>blue</color>
    </job>
</jobs>
<!-- Jenkins 2.426 | API v2 -->"""

    def _computer_page(self) -> str:
        """Generate the computer (node) page."""
        return """\
<!DOCTYPE html>
<html>
<head><title>Nodes [Jenkins]</title></head>
<body>
    <div id="main-panel">
        <h1>Nodes</h1>
        <table>
            <tr><th>Name</th><th>Status</th><th>Labels</th><th>Executors</th></tr>
            <tr><td>master</td><td class="success">Online</td><td>master</td><td>4</td></tr>
            <tr><td>build-node-1</td><td class="success">Online</td><td>linux docker</td><td>8</td></tr>
            <tr><td>build-node-2</td><td class="warning">Idle</td><td>linux</td><td>4</td></tr>
        </table>
    </div>
</body>
</html>"""

    def _script_console(self) -> str:
        """Generate the Groovy script console page."""
        return """\
<!DOCTYPE html>
<html>
<head><title>Script Console [Jenkins]</title></head>
<body>
    <div id="main-panel">
        <h1>Script Console</h1>
        <form action="/jenkins/script" method="post">
            <textarea name="script" rows="10" cols="80">println "Hello from Jenkins Script Console"</textarea>
            <input type="submit" value="Run" />
        </form>
        <div class="info">
            <p>Jenkins Script Console | Groovy 3.0.17</p>
            <p>Warning: This console allows execution of arbitrary Groovy scripts.</p>
        </div>
    </div>
</body>
</html>"""

    def _job_page(self) -> str:
        """Generate a job page."""
        return """\
<!DOCTYPE html>
<html>
<head><title>build-app [Jenkins]</title></head>
<body>
    <div id="main-panel">
        <h1>build-app</h1>
        <div class="panel">
            <h2>Build History</h2>
            <table>
                <tr><th>#</th><th>Status</th><th>Date</th><th>Duration</th></tr>
                <tr><td><a href="/jenkins/job/build-app/42/">42</a></td><td class="success">SUCCESS</td><td>2026-04-21 14:30:00</td><td>3m 45s</td></tr>
                <tr><td><a href="/jenkins/job/build-app/41/">41</a></td><td class="success">SUCCESS</td><td>2026-04-21 10:15:00</td><td>4m 12s</td></tr>
                <tr><td><a href="/jenkins/job/build-app/40/">40</a></td><td class="failure">FAILURE</td><td>2026-04-20 22:00:00</td><td>1m 30s</td></tr>
            </table>
        </div>
        <div class="panel">
            <h2>Actions</h2>
            <ul>
                <li><a href="/jenkins/job/build-app/newBuild">Build Now</a></li>
                <li><a href="/jenkins/job/build-app/configure">Configure</a></li>
                <li><a href="/jenkins/job/build-app/console">Console Output</a></li>
            </ul>
        </div>
    </div>
</body>
</html>"""

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _build_http_response(self, body: str, path: str, status: str = "200 OK") -> bytes:
        """Build a complete HTTP response."""
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: Jetty(11.0.20)\r\n"
            f"X-Hudson: 1.400\r\n"
            f"X-Jenkins: 2.426\r\n"
            f"Set-Cookie: JSESSIONID=node0abc123def456; Path=/jenkins/; HttpOnly\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: text/html;charset=UTF-8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return f"JenkinsHandler(domain={self.domain!r})"
