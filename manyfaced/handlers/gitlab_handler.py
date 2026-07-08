"""GitLabHandler – handles GitLab specific paths and interactions.

Provides realistic GitLab (self-managed / gitlab.com) responses including:
- GitLab web UI sign-in page (/users/sign_in and /)
- GitLab REST API v4 (projects, users, version)
- GitLab Prometheus metrics endpoint (/-/metrics)
- GitLab admin, explore, assets, and grafana probe surfaces

GitLab is a popular DevOps platform frequently targeted by bots probing for
exposed instances, weak credentials, exposed .env files, and information
disclosure via the metrics endpoint.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import GITLAB_HTTP

logger = logging.getLogger(__name__)


class GitLabHandler(HTTPHandlerBase):
    """GitLab honeypot handler."""

    domain = 'gitlab'
    DETECTED_ID = GITLAB_HTTP
    VERSION = '16.9.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a GitLab response for the given request."""
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

        # Handle login POST requests (credential capture via base class)
        if method == 'POST' and ('login' in path_lower or 'sign_in' in path_lower):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to appropriate response
        if path_lower == '/api/v4/version':
            body, ctype = self._api_version(), 'application/json; charset=utf-8'
        elif path_lower == '/-/metrics':
            body, ctype = self._metrics(), 'text/plain; version=0.0.4; charset=utf-8'
        elif path_lower.startswith('/api/v4/'):
            body, ctype = self._api_endpoint(path_lower), 'application/json; charset=utf-8'
        elif path_lower == '/admin':
            body, ctype = self._admin_page(), 'text/html; charset=utf-8'
        elif path_lower.startswith('/explore'):
            body, ctype = self._explore_page(), 'text/html; charset=utf-8'
        elif '/grafana' in path_lower:
            body, ctype = self._grafana_page(), 'text/html; charset=utf-8'
        elif path_lower.startswith(('/gitlab/', '/assets/')):
            # .env disclosure probe (/gitlab/%2eenv) or asset probe
            if 'env' in path_lower or '%2eenv' in path_lower:
                body, ctype = self._env_disclosure(), 'text/plain; charset=utf-8'
            else:
                body, ctype = self._asset_response(), 'application/octet-stream'
        else:
            body, ctype = self._sign_in_page(), 'text/html; charset=utf-8'

        return self._build_http_response(body, 200, 'OK', ctype), self.DETECTED_ID

    # ------------------------------------------------------------------ pages

    def _sign_in_page(self) -> str:
        """GitLab sign-in / landing page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GitLab</title>
<meta name="description" content="GitLab">
<link rel="stylesheet" href="/assets/application-<%= css %>.css">
<link rel="shortcut icon" href="/assets/favicon-<%= fav %>.ico">
</head>
<body class="ui-indigo login-page">
<div class="login-page">
  <div class="container">
    <div class="login-box">
      <div class="login-logo">
        <svg class="tanuki-logo" viewBox="0 0 144 144" xmlns="http://www.w3.org/2000/svg" aria-label="GitLab">
          <path d="M72 0 L108 36 L72 54 L36 36 Z" fill="#e24329"/>
          <path d="M36 36 L72 54 L54 108 Z" fill="#fc6d26"/>
          <path d="M108 36 L72 54 L90 108 Z" fill="#fca326"/>
          <path d="M54 108 L72 54 L90 108 L72 144 Z" fill="#e24329"/>
        </svg>
        <h1 class="gl-font-size-h1">GitLab</h1>
      </div>
      <div class="login-body">
        <form class="new_user gl-show-field-errors" aria-label="Sign in" method="post" action="/users/sign_in">
          <input type="hidden" name="authenticity_token" value="<%= csrf %>">
          <div class="form-group">
            <label for="user_login">Username or email</label>
            <input autofocus="autofocus" autocapitalize="off" autocorrect="off" type="text" name="user[login]" id="user_login" class="form-control" data-qa-selector="login_field">
          </div>
          <div class="form-group">
            <label for="user_password">Password</label>
            <input autocomplete="current-password" type="password" name="user[password]" id="user_password" class="form-control" data-qa-selector="password_field">
          </div>
          <div class="remember-me">
            <label for="user_remember_me">
              <input name="user[remember_me]" type="checkbox" value="1" id="user_remember_me"> Remember me
            </label>
          </div>
          <div class="actions">
            <input type="submit" name="commit" value="Sign in" class="btn btn-confirm" data-qa-selector="sign_in_button">
          </div>
        </form>
        <div class="login-footer">
          <p><a href="/users/password/new">Forgot your password?</a></p>
          <p><a href="/users/sign_up">Register now</a> &middot; <a href="/explore">Explore</a></p>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>"""

    def _admin_page(self) -> str:
        """GitLab admin area page (fake — redirects to sign-in behavior)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GitLab</title>
<link rel="stylesheet" href="/assets/application.css">
</head>
<body class="ui-indigo">
<div class="container">
  <h1>Admin Area</h1>
  <nav class="admin-nav">
    <a href="/admin/overview">Overview</a>
    <a href="/admin/users">Users</a>
    <a href="/admin/projects">Projects</a>
    <a href="/admin/runners">Runners</a>
    <a href="/admin/application_settings">Settings</a>
  </nav>
  <p>GitLab Enterprise Edition &middot; 16.9.0</p>
</div>
</body>
</html>"""

    def _explore_page(self) -> str:
        """GitLab explore page (public projects)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Explore | GitLab</title>
<link rel="stylesheet" href="/assets/application.css">
</head>
<body class="ui-indigo">
<div class="container">
  <h1>Explore</h1>
  <ul class="projects-list">
    <li><a href="/explore/projects">Projects</a></li>
    <li><a href="/explore/groups">Groups</a></li>
    <li><a href="/explore/snippets">Snippets</a></li>
  </ul>
  <p>Discover the best projects on GitLab.</p>
</div>
</body>
</html>"""

    def _grafana_page(self) -> str:
        """GitLab bundled Grafana probe surface."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Grafana</title>
<link rel="stylesheet" href="/-/grafana/public/build/grafana.css">
</head>
<body class="theme-%%GRADIENT%">
<div class="login-box">
  <h1>Grafana</h1>
  <form action="/-/grafana/login" method="post">
    <input type="text" name="user" placeholder="email or username">
    <input type="password" name="password" placeholder="password">
    <button type="submit">Log in</button>
  </form>
  <p>GitLab bundled Grafana &middot; 16.9.0</p>
</div>
</body>
</html>"""

    def _env_disclosure(self) -> str:
        """Fake .env disclosure (responds to /gitlab/%2eenv probes)."""
        return (
            "APP_NAME=GitLab\\n"
            "APP_ENV=production\\n"
            "GITLAB_VERSION=16.9.0\\n"
            "DATABASE_URL=postgresql://gitlab:gitlab@127.0.0.1:5432/gitlabhq_production\\n"
            "REDIS_URL=redis://127.0.0.1:6379/0\\n"
            "SECRET_KEY_BASE=CHANGE_ME_DO_NOT_USE_IN_PRODUCTION\\n"
            "GITLAB_HOST=gitlab.example.com\\n"
        )

    def _asset_response(self) -> str:
        """Generic asset response (probes to /assets/...)."""
        return "/* GitLab static asset */"

    # ------------------------------------------------------------------- API

    def _api_version(self) -> str:
        """GitLab REST API version endpoint."""
        return '{"version":"16.9.0","revision":"abc1234"}'

    def _api_endpoint(self, path_lower: str) -> str:
        """GitLab REST API v4 responses for common probe endpoints."""
        if path_lower == '/api/v4/projects':
            return (
                '[{"id":1,"name":"example-project","path_with_namespace":'
                '"root/example-project","default_branch":"main","visibility":"public",'
                '"http_url_to_repo":"https://gitlab.example.com/root/example-project.git"}]'
            )
        if path_lower == '/api/v4/users':
            return (
                '[{"id":1,"username":"root","name":"Administrator",'
                '"email":"admin@example.com","state":"active"}]'
            )
        # Generic API 200 with empty-ish JSON for other /api/v4/* probes
        return '[]'

    def _metrics(self) -> str:
        """GitLab Prometheus metrics endpoint (/-/metrics)."""
        return (
            "# HELP gitlab_usage_ping_requests_total Total usage ping requests\n"
            "# TYPE gitlab_usage_ping_requests_total counter\n"
            "gitlab_usage_ping_requests_total 0\n"
            "# HELP gitlab_pipeline_duration_seconds Pipeline duration\n"
            "# TYPE gitlab_pipeline_duration_seconds histogram\n"
            "gitlab_pipeline_duration_seconds_sum 0\n"
            "gitlab_pipeline_duration_seconds_count 0\n"
            "# HELP ruby_gc_stat_bytes_allocated Total bytes allocated\n"
            "# TYPE ruby_gc_stat_bytes_allocated counter\n"
            "ruby_gc_stat_bytes_allocated 12345678\n"
            "# HELP gitlab_version_info GitLab version information\n"
            "# TYPE gitlab_version_info gauge\n"
            'gitlab_version_info{version="16.9.0",edition="ee"} 1\n'
        )

    # ------------------------------------------------------------ login error

    def _login_failed_response(self) -> bytes:
        """GitLab login failed / error response."""
        body = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GitLab</title>
</head>
<body class="ui-indigo login-page">
<div class="login-box">
  <div class="alert alert-danger">
    <h3>Error</h3>
    <p>Invalid login or password. Please try again.</p>
  </div>
  <form method="post" action="/users/sign_in">
    <input type="text" name="user[login]" placeholder="Username or email">
    <input type="password" name="user[password]" placeholder="Password">
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>"""
        return self._build_http_response(body, 200, 'OK')

    # ----------------------------------------------------------------- helpers

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _build_http_response(
        self,
        body: str,
        status_code: int = 200,
        status_text: str = 'OK',
        content_type: str = 'text/html; charset=utf-8',
    ) -> bytes:
        """Build a complete HTTP response."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: GitLab/{self.VERSION}\r\n'
            f'Cache-Control: no-cache\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'X-GitLab-Version: {self.VERSION}\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'GitLabHandler(domain={self.domain!r})'
