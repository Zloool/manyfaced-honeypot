"""KubernetesHandler – emulates a kube-apiserver and Kubernetes Dashboard.

Provides realistic Kubernetes API server responses for the probe paths that
botnets and CVE scanners actually hit:

    /                       root API discovery document
    /api                    core API group versions
    /api/v1                 core API resource list (kind=APIResourceList)
    /api/v1/namespaces     namespace collection
    /apis                   aggregated API group list
    /healthz                liveness probe
    /readyz                 readiness probe
    /dashboard              Kubernetes Dashboard login page
    /kubernetes/.env        dashboard .env disclosure probe (decoded %2e%2f)

The Server header is advertised as ``kube-apiserver`` so the response bytes
themselves are identifiable as Kubernetes traffic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote

import logging

import json

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import KUBERNETES_HTTP

logger = logging.getLogger(__name__)


class KubernetesHandler(HTTPHandlerBase):
    """Kubernetes / API server honeypot handler."""

    domain = 'kubernetes'
    DETECTED_ID = KUBERNETES_HTTP
    VERSION = '1.29.0'

    JSON_CONTENT_TYPE = 'application/json'
    HTML_CONTENT_TYPE = 'text/html; charset=utf-8'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Kubernetes response for the given request."""
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
        # Decode percent-encoded probe paths (%2e -> '.', %2f -> '/') and
        # normalise casing for routing decisions.
        decoded = unquote(path).lower()

        # Handle dashboard login POST requests. The Kubernetes Dashboard
        # submits credentials via a POST; any POST carrying credentials is
        # treated as a login attempt so we can capture them and return a
        # believable "authorization failed" page.
        if method == 'POST':
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Route to the appropriate Kubernetes response. Real kube-apiserver
        # enforces auth: anonymous requests to protected /api/v1/* endpoints
        # return 401/403 Status objects, and unknown /api/... paths return 404
        # with kind:Status. A real cluster with anonymous-auth disabled (the
        # default) never answers those with 200 (issue #489).
        body, content_type, status_code, status_text = self._route(decoded, headers or {})

        return (
            self._build_http_response(body, status_code, status_text, content_type),
            self.DETECTED_ID,
        )

    # ------------------------------------------------------------------ #

    def _route(
        self, decoded_path: str, headers: dict[str, str] | None = None
    ) -> tuple[str, str, int, str]:
        """Return (body, content_type, status_code, status_text) for a path.

        Mirrors real kube-apiserver authz + routing (issue #489):
          * protected /api/v1/* (secrets, namespaces, pods, ...) -> 403 Forbidden
            Status when unauthenticated (anonymous-auth is disabled by default).
          * unauthenticated /api/v1/namespaces write/etc. also 403.
          * unknown /api/... or /apis/... paths -> 404 Status (kind:"Status").
          * public discovery docs (/, /api, /apis, /healthz, /readyz) -> 200.
          * dashboard paths -> 200 HTML.
        """
        json_ct = 'application/json'

        # Public discovery endpoints stay 200.
        if decoded_path in ('/', ''):
            return self._root_discovery(), json_ct, 200, 'OK'
        if decoded_path == '/api':
            return self._api_versions(), json_ct, 200, 'OK'
        if decoded_path == '/apis':
            return self._apis(), json_ct, 200, 'OK'
        if decoded_path == '/healthz':
            return self._healthz(), 'text/plain; charset=utf-8', 200, 'OK'
        if decoded_path == '/readyz':
            return self._readyz(), 'text/plain; charset=utf-8', 200, 'OK'
        if decoded_path == '/dashboard':
            return self._dashboard_login(), self.HTML_CONTENT_TYPE, 200, 'OK'
        if decoded_path.startswith('/kubernetes/'):
            return self._dashboard_env_error(), self.HTML_CONTENT_TYPE, 200, 'OK'

        # Protected core API: any /api/v1/* resource (secrets, namespaces,
        # pods, ...) must require auth. Anonymous requests (no Authorization
        # header) are rejected with 403 Forbidden Status (issue #489).
        if decoded_path == '/api/v1' or decoded_path.startswith('/api/v1/'):
            if self._is_authenticated(headers):
                # Authenticated-but-missing: 404 for unknown subresources,
                # but the well-known collections still resolve. Default to a
                # believable 403 to keep the "require auth" signal consistent.
                return self._api_v1(), json_ct, 200, 'OK'
            return (
                self._status_object(
                    403,
                    'Forbidden',
                    'forbidden',
                    'User "system:anonymous" cannot get path "%s"' % decoded_path,
                ),
                json_ct,
                403,
                'Forbidden',
            )

        # Anything else under /api or /apis that we don't recognise is an
        # unknown API path on a real cluster -> 404 Status (issue #489).
        if decoded_path.startswith('/api') or decoded_path.startswith('/apis'):
            return (
                self._status_object(
                    404,
                    'Not Found',
                    'NotFound',
                    'the server could not find the requested resource: %s' % decoded_path,
                ),
                json_ct,
                404,
                'Not Found',
            )

        # Unknown top-level path: a real apiserver answers 404 Status too.
        return (
            self._status_object(
                404,
                'Not Found',
                'NotFound',
                'the server could not find the requested resource: %s' % decoded_path,
            ),
            json_ct,
            404,
            'Not Found',
        )

    def _is_authenticated(self, headers: dict[str, str] | None) -> bool:
        """Return True if the request carries an Authorization header."""
        if not headers:
            return False
        lowered = {k.lower(): headers[k] for k in headers}
        auth = lowered.get('authorization')
        return bool(auth and auth.strip())

    def _status_object(self, code: int, status: str, reason: str, message: str) -> str:
        """Build a kube-apiserver ``Status`` JSON error object."""
        return json.dumps(
            {
                'kind': 'Status',
                'apiVersion': 'v1',
                'metadata': {},
                'status': status,
                'message': message,
                'reason': reason,
                'code': code,
            },
            separators=(',', ':'),
        )

    # ------------------------------------------------------------------ #
    # kube-apiserver JSON responses                                      #
    # ------------------------------------------------------------------ #

    def _root_discovery(self) -> str:
        """Root API discovery document (GET /)."""
        return (
            '{"kind":"APIVersions","versions":["v1"],"server":"Kubernetes",'
            '"serverAddressByClientCIDRs":['
            '{"clientCIDR":"0.0.0.0/0",'
            '"serverAddress":"10.96.0.1:443"}]}'
        )

    def _api_versions(self) -> str:
        """Core API group version list (GET /api)."""
        return (
            '{"kind":"APIVersions","versions":["v1"],"server":"Kubernetes",'
            '"serverAddressByClientCIDRs":['
            '{"clientCIDR":"0.0.0.0/0",'
            '"serverAddress":"10.96.0.1:443"}]}'
        )

    def _api_v1(self) -> str:
        """Core API resource list (GET /api/v1)."""
        return (
            '{"kind":"APIResourceList","groupVersion":"v1",'
            '"apiVersion":"v1","resources":['
            '{"name":"bindings","singularName":"","namespaced":false,'
            '"kind":"Binding","verbs":["create"]},'
            '{"name":"componentstatuses","singularName":"",'
            '"namespaced":false,"kind":"ComponentStatus",'
            '"verbs":["get","list"],"shortNames":["cs"]},'
            '{"name":"configmaps","singularName":"","namespaced":true,'
            '"kind":"ConfigMap","verbs":["create","delete","get","list",'
            '"patch","update","watch"],"shortNames":["cm"]},'
            '{"name":"endpoints","singularName":"","namespaced":true,'
            '"kind":"Endpoints","verbs":["create","delete","get","list",'
            '"patch","update","watch"],"shortNames":["ep"]},'
            '{"name":"namespaces","singularName":"namespace",'
            '"namespaced":false,"kind":"Namespace","verbs":["create",'
            '"delete","get","list","patch","update","watch"],'
            '"shortNames":["ns"]},'
            '{"name":"nodes","singularName":"","namespaced":false,'
            '"kind":"Node","verbs":["create","delete","get","list","patch",'
            '"update","watch"],"shortNames":["no"]},'
            '{"name":"pods","singularName":"","namespaced":true,'
            '"kind":"Pod","verbs":["create","delete","deletecollection",'
            '"get","list","patch","update","watch"],"shortNames":["po"]},'
            '{"name":"secrets","singularName":"","namespaced":true,'
            '"kind":"Secret","verbs":["create","delete","get","list",'
            '"patch","update","watch"],"shortNames":["secrets"]},'
            '{"name":"services","singularName":"","namespaced":true,'
            '"kind":"Service","verbs":["create","delete","get","list",'
            '"patch","update","watch"],"shortNames":["svc"]}'
            '],"name":"v1"}'
        )

    def _api_v1_namespaces(self) -> str:
        """Namespace collection (GET /api/v1/namespaces)."""
        return (
            '{"kind":"NamespaceList","apiVersion":"v1",'
            '"metadata":{"resourceVersion":"1028"},'
            '"items":['
            '{"metadata":{"name":"default","uid":"00000000-0000-0000-'
            '0000-000000000000","resourceVersion":"1","creationTimestamp":'
            'null},"spec":{"finalizers":["kubernetes"]},'
            '"status":{"phase":"Active"}},'
            '{"metadata":{"name":"kube-system","uid":"00000000-0000-0000-'
            '0000-000000000001","resourceVersion":"2","creationTimestamp":'
            'null},"spec":{"finalizers":["kubernetes"]},'
            '"status":{"phase":"Active"}},'
            '{"metadata":{"name":"kube-public","uid":"00000000-0000-0000-'
            '0000-000000000002","resourceVersion":"3","creationTimestamp":'
            'null},"spec":{"finalizers":["kubernetes"]},'
            '"status":{"phase":"Active"}}'
            ']}'
        )

    def _apis(self) -> str:
        """Aggregated API group list (GET /apis)."""
        return (
            '{"kind":"APIGroupList","apiVersion":"v1","groups":['
            '{"name":"apps","versions":[{"groupVersion":"apps/v1",'
            '"version":"v1"}],"preferredVersion":{"groupVersion":"apps/v1",'
            '"version":"v1"}},'
            '{"name":"batch","versions":[{"groupVersion":"batch/v1",'
            '"version":"v1"}],"preferredVersion":{"groupVersion":"batch/v1",'
            '"version":"v1"}},'
            '{"name":"networking.k8s.io","versions":['
            '{"groupVersion":"networking.k8s.io/v1","version":"v1"}],'
            '"preferredVersion":{"groupVersion":"networking.k8s.io/v1",'
            '"version":"v1"}},'
            '{"name":"rbac.authorization.k8s.io","versions":['
            '{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}],'
            '"preferredVersion":{"groupVersion":'
            '"rbac.authorization.k8s.io/v1","version":"v1"}}'
            ']}'
        )

    def _healthz(self) -> str:
        """kube-apiserver liveness probe (GET /healthz)."""
        return 'ok'

    def _readyz(self) -> str:
        """kube-apiserver readiness probe (GET /readyz)."""
        return 'ok'

    # ------------------------------------------------------------------ #
    # Dashboard HTML responses                                           #
    # ------------------------------------------------------------------ #

    def _dashboard_login(self) -> str:
        """Kubernetes Dashboard login page (GET /dashboard)."""
        return (
            '<!DOCTYPE html>\n'
            '<html lang="en">\n'
            '<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<title>Kubernetes Dashboard</title>\n'
            '<style>\n'
            'body{font-family:"Roboto",Arial,sans-serif;background:#f4f4f4;margin:0;}\n'
            '.login-wrap{max-width:420px;margin:80px auto;background:#fff;padding:30px;\n'
            '  border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.1);}\n'
            'h1{font-size:20px;color:#326de6;margin:0 0 4px;}\n'
            '.sub{color:#888;font-size:13px;margin-bottom:24px;}\n'
            '.field{margin-bottom:16px;}\n'
            'label{display:block;font-size:13px;color:#444;margin-bottom:6px;}\n'
            'input[type=text],input[type=password]{width:100%;padding:10px;border:1px solid\n'
            '  #ccc;border-radius:4px;box-sizing:border-box;font-size:14px;}\n'
            '.btn{background:#326de6;color:#fff;border:none;padding:10px 16px;border-radius:4px;\n'
            '  font-size:14px;cursor:pointer;width:100%;}\n'
            '.btn:hover{background:#2857b8;}\n'
            '.foot{margin-top:18px;font-size:12px;color:#999;text-align:center;}\n'
            '</style>\n'
            '</head>\n'
            '<body>\n'
            '<div class="login-wrap">\n'
            '  <h1>Kubernetes Dashboard</h1>\n'
            '  <div class="sub">Sign in to your Kubernetes cluster</div>\n'
            '  <form method="POST"\n'
            '        action="/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/api/v1/login">\n'
            '    <div class="field">\n'
            '      <label for="username">Username</label>\n'
            '      <input type="text" id="username" name="username" autocomplete="off">\n'
            '    </div>\n'
            '    <div class="field">\n'
            '      <label for="password">Password</label>\n'
            '      <input type="password" id="password" name="password">\n'
            '    </div>\n'
            '    <div class="field">\n'
            '      <label for="kubeconfig">Kubeconfig (optional)</label>\n'
            '      <input type="text" id="kubeconfig" name="kubeconfig" placeholder="/etc/kubernetes/admin.conf">\n'
            '    </div>\n'
            '    <button class="btn" type="submit">Sign in</button>\n'
            '  </form>\n'
            '  <div class="foot">Kubernetes v1.29.0 &middot; Dashboard 2.7.0</div>\n'
            '</div>\n'
            '</body>\n'
            '</html>'
        )

    def _dashboard_env_error(self) -> str:
        """Fake error page for /kubernetes/.env disclosure probes.

        Real misconfigured dashboards sometimes serve a 500 when a scanner
        reaches a leaked environment file; we answer with a believable
        dashboard-flavoured error page that still admits it is Kubernetes.
        """
        return (
            '<!DOCTYPE html>\n'
            '<html lang="en">\n'
            '<head>\n'
            '<meta charset="utf-8">\n'
            '<title>Kubernetes Dashboard - Error</title>\n'
            '</head>\n'
            '<body>\n'
            '<h1>Kubernetes Dashboard</h1>\n'
            '<h3>Internal Server Error</h3>\n'
            '<p>The Kubernetes Dashboard could not load the requested resource.</p>\n'
            '<p>Please contact your cluster administrator. (kube-apiserver v1.29.0)</p>\n'
            '</body>\n'
            '</html>'
        )

    def _login_failed_response(self) -> bytes:
        """Dashboard login failed response - encourages further probing."""
        body = (
            '<!DOCTYPE html><html><head><title>Kubernetes Dashboard'
            '</title></head><body>'
            '<h3>Authorization Error</h3>'
            '<p>Invalid login or password. Please try again.</p>'
            '</body></html>'
        )
        return self._build_http_response(body, 200, 'OK', self.HTML_CONTENT_TYPE)

    # ------------------------------------------------------------------ #
    # Helpers                                                            #
    # ------------------------------------------------------------------ #

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
        content_type: str = 'application/json',
    ) -> bytes:
        """Build a complete HTTP response encoded as iso-8859-1."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        body_bytes = body.encode('utf-8')
        body_len = len(body_bytes)
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: kube-apiserver/{self.VERSION}\r\n'
            f'Cache-Control: no-cache, private\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Content-Length: {body_len}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        ).encode('iso-8859-1') + body_bytes
        return response

    def __repr__(self) -> str:
        return f'KubernetesHandler(domain={self.domain!r})'
