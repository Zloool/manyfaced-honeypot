"""ThinkPHPHandler – emulates the ThinkPHP PHP framework (issue #287).

ThinkPHP is a widely used Chinese (CN-targeted) PHP framework. Its most
scanned-for weakness is the ``think\app/invokefunction`` remote-code-execution
chain reachable via the ``s=`` routing parameter (``?s=/index/think\app/
invokefunction&function=call_user_func_array&vars[0]=md5&...``).

This honeypot face returns a realistic ThinkPHP 5/6 *exception / error* page
for those probe paths (the emulated framework "throws" instead of executing
arbitrary PHP), plus a credential-capturing login failure page for POSTs to
login-like endpoints.

Mirror of BitrixHandler's architecture.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import THINKPHP_HTTP

logger = logging.getLogger(__name__)


class ThinkPHPHandler(HTTPHandlerBase):
    """ThinkPHP framework honeypot handler."""

    domain = 'thinkphp'
    DETECTED_ID = THINKPHP_HTTP
    VERSION = '8.0.0'

    # Markers that identify the production RCE probe (the ``s=`` routing chain).
    RCE_PROBE_MARKERS = (
        'invokefunction',
        'call_user_func_array',
        'think\\app',
        'think/app',
    )

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a ThinkPHP response for the given request."""
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

        # Handle login POST requests and capture credentials.
        if method == 'POST' and ('login' in path_lower or 'auth' in path_lower):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # The RCE probe (and any direct hit on an index.php entry script) is
        # answered with the framework's exception/error page. A real vulnerable
        # install would execute the attacker's callback; the honeypot "throws".
        if self._is_rce_probe(raw_request):
            body = self._rce_error_page(raw_request)
        else:
            body = self._main_error_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    def _is_rce_probe(self, raw_request: str) -> bool:
        """Heuristically detect the invokefunction RCE chain in the request."""
        lowered = raw_request.lower()
        return any(marker in lowered for marker in self.RCE_PROBE_MARKERS)

    def _main_error_page(self) -> str:
        """Default ThinkPHP exception/error page for index.php hits."""
        return self._thinkphp_exception_page(
            exception_class='think\\exception\\HttpException',
            message='\u6a21\u5757\u4e0d\u5b58\u5728:index',
            file='/www/web/application/',
            line='0',
            trace=[
                "0  think\\App::module()",
                "1  think\\App::exec()",
                "2  think\\App::run()",
                "3  think\\App::start()",
                "4  require('/www/web/thinkphp/start.php')",
            ],
        )

    def _rce_error_page(self, raw_request: str) -> str:
        """Exception page returned for the invokefunction RCE probe."""
        return self._thinkphp_exception_page(
            exception_class='think\\exception\\ErrorException',
            message=(
                'Function call_user_func_array() could not be invoked: '
                'the application sandbox rejected the requested callback'
            ),
            file='/www/web/thinkphp/library/think/App.php',
            line='343',
            trace=[
                "0  call_user_func_array()",
                "1  think\\App::invokefunction()",
                "2  think\\App::module()",
                "3  think\\App::exec()",
                "4  think\\App::run()",
                "5  think\\App::start()",
                "6  require('/www/web/thinkphp/start.php')",
            ],
        )

    def _thinkphp_exception_page(
        self,
        exception_class: str,
        message: str,
        file: str,
        line: str,
        trace: list[str],
    ) -> str:
        """Render a realistic ThinkPHP 5/6 exception/error page."""
        trace_html = ''.join(
            f'<li><span class="num">{i}</span> {row}</li>'
            for i, row in enumerate(trace)
        )
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>系统发生错误 - ThinkPHP</title>
<style>
body {{ font-family: "Microsoft YaHei", Arial, sans-serif; background: #fff; color: #333; margin: 0; padding: 20px; }}
.exception-wrap {{ max-width: 980px; margin: 40px auto; }}
.exception-logo {{ font-size: 22px; font-weight: bold; color: #2a6496; margin-bottom: 20px; }}
.exception-logo small {{ color: #999; font-weight: normal; font-size: 14px; }}
.exception {{ border-left: 4px solid #dd514c; background: #fff8f7; padding: 15px 20px; margin-bottom: 20px; }}
.exception h2 {{ margin: 0 0 10px; font-size: 16px; color: #dd514d; }}
.exception p {{ margin: 6px 0; font-size: 14px; }}
.exception .file {{ color: #666; font-family: Consolas, monospace; }}
.trace {{ background: #fafafa; border: 1px solid #eee; padding: 15px 20px; }}
.trace h3 {{ margin: 0 0 10px; font-size: 14px; color: #555; }}
.trace ol {{ margin: 0; padding-left: 24px; }}
.trace li {{ font-family: Consolas, monospace; font-size: 13px; line-height: 1.8; }}
.trace .num {{ color: #999; }}
.footer {{ margin-top: 30px; color: #aaa; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<div class="exception-wrap">
    <div class="exception-logo">
        ThinkPHP V{self.VERSION}
        <small>PHP Runtime Exception</small>
    </div>
    <div class="exception">
        <h2>[{exception_class}]</h2>
        <p>{message}</p>
        <p class="file">File: {file}</p>
        <p class="file">Line: {line}</p>
    </div>
    <div class="trace">
        <h3>Stack trace:</h3>
        <ol>
{trace_html}
        </ol>
    </div>
    <div class="footer">
        Powered by ThinkPHP &copy; 2006-{datetime.now(timezone.utc).year} www.thinkphp.cn
    </div>
</div>
</body>
</html>"""

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>登录失败 - ThinkPHP</title></head>
<body>
<div class="exception-wrap">
    <h2>Authorization Error</h2>
    <p>Invalid username or password. Please try again.</p>
    <p><a href="/index.php/login">Return to login page</a></p>
</div>
</body>
</html>"""
        return self._build_http_response(body, 200, 'OK')

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
        content_type: str = 'text/html; charset=UTF-8',
    ) -> bytes:
        """Build a complete HTTP response (UTF-8 encoded for CJK content)."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: nginx/1.24.0\r\n'
            f'X-Powered-By: PHP/8.1.27\r\n'
            f'Set-Cookie: PHPSESSID=thinkphp_{self.VERSION.replace(".", "")}; path=/\r\n'
            f'X-Frame-Options: SAMEORIGIN\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("utf-8"))}\r\n'
            f'\r\n'
            f'{body}'
        )

        return response.encode('utf-8')

    def __repr__(self) -> str:
        return f'ThinkPHPHandler(domain={self.domain!r})'
