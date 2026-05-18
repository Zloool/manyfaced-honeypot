---
name: add-service-handler
description: Recipe for adding a new fake service "face" to the honeypot — handler class, route registration, monster page entry, and tests. Based on current Router + per-service route files architecture (not the stale registry.py pattern).
---

# Add a New Service Handler Skill

Use this skill when you need to **add a new impersonation face** to the honeypot — e.g., "impersonate Jenkins", "add a Drupal handler", "create a fake service for X". This covers the full lifecycle: handler class, route registration, monster page entry, and tests.

## Triggers

- "add a new face" / "add a new service handler" / "impersonate a new service"
- "register a new handler" / "make the honeypot respond like X"
- References to adding handlers, routes, or service impersonation

**Do NOT use this skill for:**
- Editing routing of existing handlers or the route table order (that's an operational change)
- Editing server-side BaseHandler hierarchy (server-side is separate from client-side HTTP handlers)
- Quick health checks — use **prod-healthcheck** instead

## Prerequisites

- Familiarity with `manyfaced/handlers/base_handler.py` (`HTTPHandlerBase`)
- Reference implementation: `bitrix_handler.py` + `routes_bitrix.py` (simple, clean example)
- Also see DEVELOPER.md "How to Add a New Service Handler" section (updated alongside this skill)

## Current Architecture (NOT the stale registry.py pattern)

The old DEVELOPER.md described registering handlers in `handlers/registry.py`. **That file no longer exists** (replaced by explicit Router + per-service route files). The current architecture:

```
manyfaced/handlers/
├── base_handler.py          # HTTPHandlerBase ABC — subclass this
├── http_handler.py           # Main entry point, dispatches via Router
├── __init__.py               # Imports all handlers + exports in __all__
├── <svc>_handler.py          # Your new handler class
│
└── routes/                   # Per-service route files (NOT a single routes.py)
    ├── __init__.py           # Concatenates per-service ROUTES lists into one table
    ├── routes_bitrix.py      # Example: Bitrix routes
    ├── routes_wordpress.py   # WordPress routes
    └── ...
```

**Routing mechanics:** `Router` walks an ordered list of `Route(matcher, handler_cls, detected_id, name)` entries. First match wins. Order = dispatch policy.

## Step-by-Step Recipe

### Step 1: Create the Handler Class

Create `manyfaced/handlers/<svc>_handler.py`:

```python
"""<Svc>Handler – handles <service description>.

Provides realistic <service> responses including:
- Key paths and pages
- Credential capture from login attempts (if applicable)
- Realistic error/redirect responses to encourage further probing
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class <Svc>Handler(HTTPHandlerBase):
    """<Service> honeypot handler."""

    domain = '<svc>'
    DETECTED_ID = 1  # See status.py for special IDs (4294967294=UNKNOWN_HTTP, etc.)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a <service> response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        # Record the request in bot profile
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

        # Handle login POST requests (if service has auth)
        if method == 'POST' and any(kw in path_lower for kw in ['login', 'auth']):
            credentials, response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                # Return login-failed page to encourage brute-force probing
                return self._login_failed_response(), detected

        # Route to appropriate response based on path
        if '/admin/' in path_lower or '/admin' == path_lower:
            body = self._admin_page()
        else:
            body = self._main_page()

        return self._build_http_response(body, 200, 'OK'), self.DETECTED_ID

    def _main_page(self) -> str:
        """Main service page HTML."""
        raise NotImplementedError("Subclasses must implement this")

    def _admin_page(self) -> str:
        """Admin/login page HTML."""
        return self._main_page()  # Default fallback

    def _login_failed_response(self) -> bytes:
        """Login failed response — encourages further probing."""
        body = "<html><body><h3>Authorization Error</h3><p>Invalid credentials.</p></body></html>"
        return self._build_http_response(body, 200, 'OK')

    def _extract_method(self, raw_request: str) -> str:
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
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Apache/2.4.57 (Ubuntu)\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'<Svc>Handler(domain={self.domain!r})'
```

**Key patterns from `bitrix_handler.py` (canonical example):**
- Each page type gets its own `_page()` method returning HTML string
- POST to login-like paths triggers `handle_login()` for credential capture
- Login failures return a page that encourages further probing (brute-force)
- Use `iso-8859-1` encoding for HTTP responses (standard for web servers)

### Step 2: Export from `handlers/__init__.py`

Add two lines to `manyfaced/handlers/__init__.py`:

```python
# Import the handler class
from manyfaced.handlers.<svc>_handler import <Svc>Handler

# Add to __all__ list (keep alphabetical order within service handlers section)
__all__ = [
    # ... existing entries ...
    '<Svc>Handler',  # <-- add here, alphabetically among other handlers
]
```

### Step 3: Register Routes

Create `manyfaced/handlers/routes/routes_<svc>.py`:

```python
"""<Service> routes."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route


def _<svc>() -> type:
    from manyfaced.handlers.<svc>_handler import <Svc>Handler
    return <Svc>Handler


ROUTES: list[Route] = [
    # ---- <Service> -----------------------------------------------------------
    Route(PathExact('/<path1>'), _<svc>(), 1, '<svc>_path1'),
    Route(PathPrefix('/<path1>/'), _<svc>(), 1, '<svc>_path1_slash'),
    Route(PathExact('/<path2>'), _<svc>(), 1, '<svc>_path2'),
]
```

**Matcher types:**
- `PathExact('/path')` — exact match (case-insensitive)
- `PathPrefix('/path/')` — prefix match (case-insensitive)

Then register in `manyfaced/handlers/routes/__init__.py`:

1. Add import:
   ```python
   from manyfaced.handlers.routes.routes_<svc> import ROUTES as _<svc>_routes  # noqa: E402
   ```

2. Add to the concatenation (insert in the correct position for dispatch priority):
   ```python
   ROUTES: list[Route] = (
       list(_wordpress_routes)
       + list(_phpmyadmin_routes)
       # ... existing services ...
       + list(_<svc>_routes)  # <-- add here, in desired dispatch order
       + list(_config_disclosure_routes)
       + [Route(Any(), _generic(), 4294967294, 'catchall_monster_page')]
   )
   ```

**⚠️ Ordering = Dispatch Policy (first match wins):**
- The order of ROUTES is the dispatch policy. To change which handler wins for a given path, reorder entries in `routes/__init__.py`.
- **Overlap resolution:** Higher-priority routes listed first take precedence. E.g., `/xmlrpc.php` → WordPressHandler (not ConfigDisclosure), `/mysql` → PhpMyAdminHandler.
- **WebDAV is deliberately NOT route-registered** — it uses a separate mechanism.

### Step 4: Add to Monster Page (`_SERVICE_INFO`)

Add an entry in `manyfaced/handlers/generic_handler.py`:

```python
_SERVICE_INFO: dict[str, tuple[str, str, str]] = {
    # ... existing entries ...
    '<svc>': ('<Display Name>', '<Version>', 'Running (v<Version>)'),
}

# Optional: representative paths for the monster page table
_SERVICE_PATHS: dict[str, list[str]] = {
    # ... existing entries ...
    '<svc>': ['/<path1>', '/<path2>'],
}
```

### Step 5: Write Tests

Add test methods to `test/test_handlers/test_service_handlers.py` mirroring the pattern of an existing handler's tests (e.g., `TestBitrixHandler`):

```python
class Test<Svc>Handler(unittest.TestCase):
    """Test <Svc>Handler responses."""

    def setUp(self):
        self.handler = <Svc>Handler()

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/<path>',
            'GET /<path> HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'<Service Keyword>', response)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/<login_path>',
            'POST /<login_path> HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=secret',
            '1.2.3.4',
        )
        self.assertIn(b'Error', response)  # or whatever login-fail indicator
```

Also add the import at the top of `test_service_handlers.py`:
```python
from manyfaced.handlers import <Svc>Handler
```

### Step 6: Verify CI Passes

```bash
# Run tests (coverage gate is 76%)
pytest -v --tb=short test/test_handlers/test_service_handlers.py

# Lint check
ruff check . && ruff format .
```

## Common Pitfalls

1. **Lazy imports in routes:** Always use lazy `import` inside the `_<svc>()` helper function to avoid circular imports. The handler class must not be imported at module level in route files.

2. **DETECTED_ID values:** Use `1` for known service detections. Special IDs are defined in `manyfaced/common/status.py`:
   - `4294967294` = UNKNOWN_HTTP (Generic/Monster Page)
   - `4294967293` = SSH_CLIENT (Unknown SSH Probe)
   - `4294967292` = UNKNOWN_NON_HTTP (Unknown Telnet/RDP Probe)
   - `4294967291` = EMPTY_CONNECTION (Zero-byte TCP connection, port scan)

3. **Path matching is case-insensitive:** Both `PathExact` and `PathPrefix` lower-case the request path before comparing. You don't need to handle case in your handler logic.

4. **WebDAV exception:** WebDAVHandler exists but is NOT registered in the route table. It uses a separate dispatch mechanism. Do not follow its pattern for new handlers.

5. **Encoding:** Always use `iso-8859-1` encoding for HTTP responses (not UTF-8). This matches real Apache/Nginx behavior and avoids bot confusion.

## Cross-Reference

- For the full handler architecture overview, see DEVELOPER.md "Codebase Deep Dive" section
- For quick service health checks, use **prod-healthcheck** skill
- For analyzing production data from your new face, use **prod-analysis** skill
