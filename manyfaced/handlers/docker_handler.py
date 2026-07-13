"""DockerHandler – Docker Registry v2 + daemon API honeypot handler.

Emulates the Docker Hub / Registry v2 API and the local Docker daemon HTTP
API (``dockerd``'s ``/var/run/docker.sock`` surface exposed over TCP). Real
bot/scan probes hit a predictable set of paths:

    /v2/                      Registry v2 API "ping" / distribution check
    /v2/_catalog              List all repositories in the registry
    /v2/<name>/tags/list      List tags for a given repository
    /info                     Daemon ``GET /info`` (system info)
    /version                  Daemon ``GET /version`` (engine version)
    /containers/json          Daemon ``GET /containers/json`` (ps)
    /docker/.env              Path-traversal probe for a leaked .env file

URL-encoded variants are decoded (``%2e`` -> ``.``, ``%2f`` -> ``/``) so
probes such as ``/docker/%2eenv`` are recognised.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from urllib.parse import unquote

from manyfaced.handlers.base_handler import HTTPHandlerBase

from manyfaced.common.status import DOCKER_HTTP

logger = logging.getLogger(__name__)


class DockerHandler(HTTPHandlerBase):
    """Docker Registry / daemon API honeypot handler."""

    domain = 'docker'
    DETECTED_ID = DOCKER_HTTP
    VERSION = '26.0.0'

    # Engine / distribution version strings reported back to probes.
    ENGINE_VERSION = '26.0.0'
    API_VERSION = '1.45'
    GO_VERSION = 'go1.21.8'
    OS = 'linux'
    ARCH = 'amd64'

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a Docker Registry/daemon response for the given request."""
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
        # Decode URL-encoding so %2e / %2f probes resolve to . / paths.
        decoded = unquote(path)
        path_lower = decoded.lower()

        # Capture credentials from login/registry auth attempts.
        if method == 'POST' and (
            'login' in path_lower or 'auth' in path_lower or 'token' in path_lower
        ):
            credentials, _response, detected = self.handle_login(
                path, raw_request, bot_ip, headers or {}
            )
            if credentials:
                return self._login_failed_response(), detected

        # Registry v2 "ping" endpoint.
        if decoded in ('/v2', '/v2/'):
            body = self._registry_ping()
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

        # Registry v2 catalog.
        if decoded == '/v2/_catalog':
            body = self._registry_catalog()
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

        # Registry v2 repository tags: /v2/<name>/tags/list
        if decoded.endswith('/tags/list') and decoded.startswith('/v2/'):
            repo = decoded[len('/v2/') : -len('/tags/list')].rstrip('/')
            body = self._registry_tags(repo)
            return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

        # Registry v2 manifest / blob probes -> 404 like a real empty registry.
        if decoded.startswith('/v2/'):
            body = self._registry_manifest_missing(decoded)
            return self._build_http_response(
                body, 404, 'Not Found', 'application/json'
            ), self.DETECTED_ID

        # Daemon info endpoint. The bare /version, /info and /containers/json
        # paths are also hit by generic uptime probes / other services' health
        # checks; only answer with Docker daemon JSON when the request looks
        # Docker-shaped (real docker CLI/dockerd send a `Docker/*` User-Agent or
        # the distribution API header). Otherwise return a neutral 404 so we
        # don't steal non-Docker traffic (issue #522).
        if decoded in ('/info', '/_info'):
            if self._is_docker_shaped(headers):
                body = self._daemon_info()
                return self._build_http_response(
                    body, 200, 'OK', 'application/json'
                ), self.DETECTED_ID
            return self._not_docker(), self.DETECTED_ID

        # Daemon version endpoint.
        if decoded in ('/version', '/_version'):
            if self._is_docker_shaped(headers):
                body = self._daemon_version()
                return self._build_http_response(
                    body, 200, 'OK', 'application/json'
                ), self.DETECTED_ID
            return self._not_docker(), self.DETECTED_ID

        # Daemon container listing endpoint.
        if decoded in ('/containers/json', '/containers'):
            if self._is_docker_shaped(headers):
                body = self._daemon_containers()
                return self._build_http_response(
                    body, 200, 'OK', 'application/json'
                ), self.DETECTED_ID
            return self._not_docker(), self.DETECTED_ID

        # Path-traversal probe for a leaked .env (e.g. /docker/.env, /docker/%2eenv).
        if path_lower.endswith('.env'):
            body = self._env_disclosure()
            return self._build_http_response(
                body, 200, 'OK', 'text/plain; charset=UTF-8'
            ), self.DETECTED_ID

        # Fallback: registry v2 ping is the safest default for this face.
        body = self._registry_ping()
        return self._build_http_response(body, 200, 'OK', 'application/json'), self.DETECTED_ID

    # -- Registry v2 API ---------------------------------------------------

    def _registry_ping(self) -> str:
        """Registry v2 'ping' / distribution check response."""
        return json.dumps({'docker_distribution': 'registry'})

    def _registry_catalog(self) -> str:
        """Registry v2 catalog listing (no repositories by default)."""
        return json.dumps({'repositories': []})

    def _registry_tags(self, repo: str) -> str:
        """Registry v2 tags listing for a repository."""
        return json.dumps({'name': repo, 'tags': []})

    def _registry_manifest_missing(self, path: str) -> str:
        """404 for manifest/blob lookups, mirroring a real empty registry."""
        return json.dumps(
            {
                'errors': [
                    {
                        'code': 'MANIFEST_UNKNOWN',
                        'message': 'manifest unknown',
                        'detail': {'Name': path, 'Tag': 'latest'},
                    }
                ],
            }
        )

    # -- Docker daemon API --------------------------------------------------

    def _daemon_version(self) -> str:
        """Daemon ``GET /version`` response."""
        return json.dumps(
            {
                'Platform': {'Name': 'Docker Engine - Community'},
                'Components': [
                    {
                        'Name': 'Engine',
                        'Version': self.ENGINE_VERSION,
                        'Details': {
                            'ApiVersion': self.API_VERSION,
                            'Arch': self.ARCH,
                            'BuildTime': '2024-03-20T10:36:13.000000000+00:00',
                            'Experimental': 'false',
                            'GitCommit': '8e96db1',
                            'GoVersion': self.GO_VERSION,
                            'KernelVersion': '5.15.0',
                            'MinAPIVersion': '1.24',
                            'Os': self.OS,
                        },
                    },
                ],
                'Version': self.ENGINE_VERSION,
                'ApiVersion': self.API_VERSION,
                'MinAPIVersion': '1.24',
                'GitCommit': '8e96db1',
                'GoVersion': self.GO_VERSION,
                'Os': self.OS,
                'Arch': self.ARCH,
                'KernelVersion': '5.15.0',
                'BuildTime': '2024-03-20T10:36:13.000000000+00:00',
            }
        )

    def _daemon_info(self) -> str:
        """Daemon ``GET /info`` response."""
        return json.dumps(
            {
                'ID': 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123',
                'Containers': 0,
                'ContainersRunning': 0,
                'ContainersPaused': 0,
                'ContainersStopped': 0,
                'Images': 0,
                'Driver': 'overlay2',
                'DriverStatus': [['Backing Filesystem', 'extfs']],
                'SystemStatus': None,
                'Plugins': {
                    'Volume': ['local'],
                    'Network': ['bridge', 'host', 'none', 'overlay'],
                    'Authorization': None,
                    'Log': ['json-file', 'syslog', 'journald'],
                },
                'MemoryLimit': True,
                'SwapLimit': True,
                'CpuCfsPeriod': True,
                'CpuCfsQuota': True,
                'CPUShares': True,
                'CPUSet': True,
                'PidsLimit': True,
                'IPv4Forwarding': True,
                'BridgeNfIptables': True,
                'BridgeNfIp6tables': True,
                'Debug': False,
                'NFd': 23,
                'NGoroutines': 45,
                'SystemTime': datetime.now(timezone.utc).isoformat(),
                'LoggingDriver': 'json-file',
                'CgroupDriver': 'systemd',
                'CgroupVersion': '2',
                'KernelVersion': '5.15.0',
                'OperatingSystem': 'Ubuntu 22.04.4 LTS',
                'OSVersion': '22.04',
                'OSType': self.OS,
                'Architecture': self.ARCH,
                'NCPU': 4,
                'MemTotal': 16777216000,
                'IndexServerAddress': 'https://index.docker.io/v1/',
                'RegistryConfig': {
                    'InsecureRegistryCIDRs': ['127.0.0.0/8'],
                    'IndexConfigs': {
                        'docker.io': {
                            'Name': 'docker.io',
                            'Mirrors': [],
                            'Secure': True,
                            'Official': True,
                        },
                    },
                    'Mirrors': [],
                },
                'DockerRootDir': '/var/lib/docker',
                'Name': 'docker-host',
                'ServerVersion': self.ENGINE_VERSION,
            }
        )

    def _daemon_containers(self) -> str:
        """Daemon ``GET /containers/json`` response (empty ps)."""
        return json.dumps([])

    # -- Misc ---------------------------------------------------------------

    def _env_disclosure(self) -> str:
        """Fake leaked ``.env`` file to entice further credential probing."""
        return (
            'APP_ENV=production\n'
            'APP_DEBUG=false\n'
            'APP_KEY=base64:abcdefghijklmnopqrstuvwxyz0123456789=\n'
            'DB_CONNECTION=mysql\n'
            'DB_HOST=db\n'
            'DB_PORT=3306\n'
            'DB_DATABASE=app\n'
            'DB_USERNAME=appuser\n'
            'DB_PASSWORD=Sup3rS3cretP@ss\n'
            'REDIS_HOST=redis\n'
            'REDIS_PASSWORD=\n'
            'MAIL_HOST=smtp\n'
            'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
            'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
        )

    def _is_docker_shaped(self, headers: dict[str, str] | None) -> bool:
        """Return True when the request looks like a real Docker client.

        Real ``docker`` CLI / ``dockerd`` HTTP API clients identify themselves
        with a ``Docker/*`` User-Agent and/or send the registry distribution
        API header (issue #522). Generic uptime probes (Kubernetes, ES health
        checks, fuzzers) do not, so we should not answer them with Docker JSON.
        """
        if not headers:
            return False
        ua = (headers.get('User-Agent') or headers.get('user-agent') or '').lower()
        if ua.startswith('docker/'):
            return True
        lowered = {k.lower(): headers[k] for k in headers}
        if 'docker-distribution-api-version' in lowered:
            return True
        return False

    def _not_docker(self) -> bytes:
        """Neutral 404 for non-Docker-shaped probes on Docker daemon paths.

        Keeps the Docker Server header (this face is still the owner of the
        path) but returns no Docker-specific payload, so a non-Docker scanner
        that happens to hit /version does not get a Docker daemon fingerprint.
        """
        return self._build_http_response(
            json.dumps({'message': 'Not found'}), 404, 'Not Found', 'application/json'
        )

    def _login_failed_response(self) -> bytes:
        """Login failed response - encourages further probing."""
        body = '<html><body><h3>Error</h3><p>Invalid username or password.</p></body></html>'
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
        """Build a complete HTTP response, iso-8859-1 encoded."""
        now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = (
            f'HTTP/1.1 {status_code} {status_text}\r\n'
            f'Server: Docker/{self.VERSION}\r\n'
            f'Docker-Distribution-Api-Version: registry/2.0\r\n'
            f'X-Content-Type-Options: nosniff\r\n'
            f'Date: {now}\r\n'
            f'Content-Type: {content_type}\r\n'
            f'Connection: close\r\n'
            f'Content-Length: {len(body.encode("iso-8859-1"))}\r\n'
            f'\r\n'
            f'{body}'
        )
        return response.encode('iso-8859-1')

    def __repr__(self) -> str:
        return f'DockerHandler(domain={self.domain!r})'
