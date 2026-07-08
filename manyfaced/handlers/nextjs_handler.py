"""NextjsHandler – impersonates a Next.js (Vercel) app server.

Provides realistic Next.js / Vercel responses including:
- Next.js app shell home page (/) with the "Next.js" logo text
- Next.js production asset routes under /_next/ (static chunks, image
  optimization endpoint)
- Next.js API routes under /api/ (incl. /api/health health-check probe)
- Vercel platform probe responses at /vercel
- A /nextjs/ path namespace used to surface Next.js-specific probes (e.g.
  /.env / %2eenv traversal probes)

Next.js is one of the most-probed Node.js frameworks; Vercel's probe paths
(/api/health, /vercel, /_next/image) are hit constantly by scanners and
uptime checkers, so we answer them with believable payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from urllib.parse import unquote

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import NEXTJS_HTTP

logger = logging.getLogger(__name__)


class NextjsHandler(HTTPHandlerBase):
    """Next.js / Vercel honeypot handler."""

    domain = 'nextjs'
    DETECTED_ID = NEXTJS_HTTP
    VERSION = '14.2.0'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Next.js response for the given request."""
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
        # Decode percent-encoded probe paths: %2e -> '.', %2f -> '/'
        decoded = self._decode_path(path)
        path_lower = decoded.lower()

        # Handle login POST requests (Next.js API auth / app login forms)
        if method == 'POST' and 'login' in path_lower:
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                response = self._login_failed_response()
                return response, detected

        # Route to the appropriate Next.js response
        if decoded == '/':
            body, ctype, status = self._main_page(), 'text/html; charset=UTF-8', 200
        elif path_lower == '/api/health':
            body, ctype, status = self._api_health(), 'application/json', 200
        elif path_lower.startswith('/api'):
            body, ctype, status = self._api_response(decoded), 'application/json', 200
        elif path_lower.startswith('/_next/image'):
            body, ctype, status = self._next_image_error(), 'application/json', 400
        elif path_lower.startswith('/_next'):
            body, ctype, status = self._next_asset(decoded), 'application/javascript; charset=UTF-8', 200
        elif path_lower == '/vercel' or path_lower.startswith('/vercel/'):
            body, ctype, status = self._vercel_probe(), 'application/json', 200
        elif path_lower.startswith('/nextjs'):
            body, ctype, status = self._nextjs_probe(decoded), 'text/html; charset=UTF-8', 200
        else:
            # Default app shell keeps the bot engaged on unknown Next.js paths
            body, ctype, status = self._main_page(), 'text/html; charset=UTF-8', 200

        return (
            self._build_http_response(body, status, self._status_text(status), ctype),
            self.DETECTED_ID,
        )

    # -- response builders --------------------------------------------------

    def _main_page(self) -> str:
        """Next.js app shell home page (production build)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charSet="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="next-head-count" content="2"/>
<link rel="icon" href="/favicon.ico" type="image/x-icon" sizes="any"/>
<link rel="preload" href="/_next/static/css/app/layout.css?v=14.2.0" as="style"/>
<link rel="preload" href="/_next/static/chunks/webpack-<BUILD_ID>.js" as="script"/>
<link rel="preload" href="/_next/static/chunks/main-app-<BUILD_ID>.js" as="script"/>
<link rel="preload" href="/_next/static/chunks/app/page-<BUILD_ID>.js" as="script"/>
<link rel="stylesheet" href="/_next/static/css/app/layout.css?v=14.2.0"/>
<title>Next.js</title>
<meta name="description" content="Welcome to the Next.js application."/>
</head>
<body>
<div id="__next">
<div class="page-shell">
<header class="site-header">
<a class="logo" href="/"><span class="logo-text">Next.js</span></a>
<nav class="site-nav">
<a href="/">Home</a>
<a href="/api/health">API</a>
<a href="/vercel">Status</a>
</nav>
</header>
<main class="site-main">
<section class="hero">
<h1>Next.js</h1>
<p>This is a Next.js application served by the Vercel platform.</p>
<p class="version">Powered by Next.js 14.2.0</p>
</section>
</main>
<footer class="site-footer">
<p>&copy; 2024 Next.js &mdash; Deployed on Vercel</p>
</footer>
</div>
</div>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}},"page":"/","query":{},"buildId":"<BUILD_ID>","assetPrefix":"/_next/","isFallback":false,"dynamicIds":[],"err":null}</script>
<script>self.__next_f.push([1,"{\\"ENV\\":{\\"NEXT_PUBLIC_APP_ENV\\":\\"production\\"}}"])</script>
<script src="/_next/static/chunks/webpack-<BUILD_ID>.js" async=""></script>
<script src="/_next/static/chunks/main-app-<BUILD_ID>.js" async=""></script>
<script src="/_next/static/chunks/app/page-<BUILD_ID>.js" async=""></script>
</body>
</html>"""

    def _api_health(self) -> str:
        """/api/health JSON health-check probe response."""
        return (
            '{"status":"ok","service":"nextjs",'
            '"version":"14.2.0","uptime":1337,"region":"iad1"}'
        )

    def _api_response(self, path: str) -> str:
        """Generic Next.js API route JSON response."""
        return (
            '{"message":"OK","path":' + f'"{path}"' + ','
            '"framework":"next.js","runtime":"nodejs"}'
        )

    def _next_asset(self, path: str) -> str:
        """Next.js production static asset (/_next/static, /_next/image)."""
        if path.lower().endswith('.css'):
            return '/* Next.js compiled stylesheet */\n'
        # Realistic-looking webpack chunk stub
        return (
            '// Next.js webpack chunk\n'
            'self.__next_f=window.__next_f||[];'
            'self.__next_f.push([1,"{\\"app\\":\\"nextjs\\"}"]);\n'
        )

    def _next_image_error(self) -> str:
        """Next.js image optimization endpoint error (missing params)."""
        return (
            '{"error":"url parameter is valid but image type is not allowed"}'
        )

    def _vercel_probe(self) -> str:
        """Vercel platform probe response (/vercel)."""
        return (
            '{"framework":"next.js","frameworkVersion":"14.2.0",'
            '"region":"iad1","environment":"production","vercel":true}'
        )

    def _nextjs_probe(self, path: str) -> str:
        """Sensitive Next.js probe namespace (/nextjs/<target>).

        Handles traversal/env probes such as /nextjs/%2eenv -> /nextjs/.env.
        Returns a believable 403 shell for sensitive files, else a Next.js shell.
        """
        decoded = path.lower()
        if '.env' in decoded or 'wp-config' in decoded or 'passwd' in decoded:
            return (
                '<!DOCTYPE html><html><head><title>403 Forbidden</title></head>'
                '<body><h1>403 Forbidden</h1>'
                '<p>Access to this Next.js resource is denied.</p>'
                '<p>Server: Next.js/14.2.0 (Vercel)</p></body></html>'
            )
        return self._main_page()

    def _login_failed_response(self) -> bytes:
        """Login failed response – keeps the bot trying credentials."""
        body = (
            '<!DOCTYPE html><html><head><title>Error</title></head>'
            '<body><div class="error-box"><h3>Error</h3>'
            '<p>Invalid login or password. Please try again.</p>'
            '<p><a href="/login">Return to login</a></p></div></body></html>'
        )
        return self._build_http_response(body, 200, 'OK', 'text/html; charset=UTF-8')

    # -- helpers ------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Decode percent-encoded probe characters (%2e -> '.', %2f -> '/')."""
        try:
            return unquote(path)
        except Exception:
            return path

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return 'GET'

    def _status_text(self, status_code: int) -> str:
        return {
            200: 'OK',
            400: 'Bad Request',
            403: 'Forbidden',
            404: 'Not Found',
        }.get(status_code, 'OK')

    def _build_http_response(
        self,
        body: str,
        status_code: int = 200,
        status_text: str = 'OK',
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response (iso-8859-1 wire encoding)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Next.js/{self.VERSION}\r\n'
            f'X-Powered-By: Next.js\r\n'
            f'X-Nextjs-Cache: MISS\r\n'
            f'Vary: Accept-Encoding\r\n'
            f'Cache-Control: public, max-age=0, must-revalidate\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'NextjsHandler(domain={self.domain!r})'
