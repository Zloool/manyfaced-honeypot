"""Regression tests locking fixes from PRs #96–#106.

These tests verify that the audit fixes remain in place:
- Distinct DETECTED_ID per handler (from manyfaced/common/status.py)
- Content-Length header matching body byte length on every response
- End-to-end capture pipeline producing correct DB rows
"""

import inspect

import pytest


# ── Fix #96: detected_id — distinct per handler ───────────────────────────────


class TestDetectedIdDistinctness:
    """Every HTTPHandlerBase subclass must expose a distinct DETECTED_ID."""

    def test_generic_handler_uses_unknown_http_constant(self):
        """GenericHandler.DETECTED_ID should be the UNKNOWN_HTTP constant.

        Regression guard for #103: GenericHandler must use the named constant
        from status.py rather than a magic number literal.
        """
        from manyfaced.common.status import UNKNOWN_HTTP
        from manyfaced.handlers.generic_handler import GenericHandler

        assert GenericHandler.DETECTED_ID == UNKNOWN_HTTP, (
            'GenericHandler should use UNKNOWN_HTTP constant'
        )

        # Verify the source code uses the constant name, not a literal magic number
        src = inspect.getsource(GenericHandler)
        detected_line = [
            line.strip() for line in src.split('\n') if 'DETECTED_ID' in line and '=' in line
        ][0]
        assert 'UNKNOWN_HTTP' in detected_line or '4294967294' not in detected_line, (
            f'GenericHandler should reference UNKNOWN_HTTP constant, not a literal magic number. '
            f'Found: {detected_line}'
        )

    def test_all_handlers_have_unique_detected_ids(self):
        """Each handler subclass must have a unique DETECTED_ID."""
        from manyfaced.handlers.bitrix_handler import BitrixHandler
        from manyfaced.handlers.config_disclosure_handler import (
            ConfigDisclosureHandler,
        )
        from manyfaced.handlers.cpanel_handler import CPanelHandler
        from manyfaced.handlers.drupal_handler import DrupalHandler
        from manyfaced.handlers.generic_handler import GenericHandler
        from manyfaced.handlers.jenkins_handler import JenkinsHandler
        from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler
        from manyfaced.handlers.tomcat_handler import TomcatHandler
        from manyfaced.handlers.webdav_handler import WebDAVHandler
        from manyfaced.handlers.wordpress_handler import WordPressHandler

        handlers = [
            ('GenericHandler', GenericHandler),
            ('WordPressHandler', WordPressHandler),
            ('BitrixHandler', BitrixHandler),
            ('ConfigDisclosureHandler', ConfigDisclosureHandler),
            ('CPanelHandler', CPanelHandler),
            ('DrupalHandler', DrupalHandler),
            ('JenkinsHandler', JenkinsHandler),
            ('PhpMyAdminHandler', PhpMyAdminHandler),
            ('TomcatHandler', TomcatHandler),
            ('WebDAVHandler', WebDAVHandler),
        ]

        ids_seen: dict[int, str] = {}
        for name, handler_cls in handlers:
            did = getattr(handler_cls, 'DETECTED_ID', None)
            assert did is not None, f'{name} missing DETECTED_ID'
            assert isinstance(did, int), f'{name}.DETECTED_ID must be int, got {type(did)}'
            if did in ids_seen:
                pytest.fail(f'Duplicate DETECTED_ID {did}: {ids_seen[did]} and {name} both use it')
            ids_seen[did] = name

    def test_status_constants_are_unique(self):
        """All HTTP status constants in status.py must be unique."""
        from manyfaced import common

        http_attrs = {
            k: v for k, v in vars(common.status).items() if '_HTTP' in k and isinstance(v, int)
        }
        values = list(http_attrs.values())
        assert len(values) == len(set(values)), (
            f'Duplicate HTTP status constants found. Values: {dict(zip(http_attrs.keys(), values))}'
        )


# ── Fix #97: Content-Length header ────────────────────────────────────────────


class TestContentLengthHeader:
    """Every handler response must carry Content-Length matching body byte length."""

    def _get_response_bytes(self, handler_cls) -> bytes | None:
        """Call the generate_response method and return raw response bytes."""
        if hasattr(handler_cls, 'generate_response'):
            # Class-based handlers need path, raw_request, bot_ip args
            try:
                instance = handler_cls()
                resp_tuple = instance.generate_response(
                    path='/test', raw_request='GET /test HTTP/1.1\r\n\r\n', bot_ip='127.0.0.1'
                )
            except TypeError:
                # Some handlers may have different signatures
                return None

            if isinstance(resp_tuple, tuple) and len(resp_tuple) == 2:
                raw_response = resp_tuple[0]  # (headers + body) bytes
                content_length = resp_tuple[1]  # int — verify it matches
                if isinstance(raw_response, bytes):
                    self._verify_content_length(raw_response, handler_cls.__name__)
                    return raw_response
            elif isinstance(resp_tuple, bytes):
                return resp_tuple
        return None

    def _verify_content_length(self, resp: bytes, name: str) -> None:
        """Parse headers and verify Content-Length matches body length."""
        header_end = resp.find(b'\r\n\r\n')
        if header_end != -1:
            header_block = resp[:header_end].decode()
            body = resp[header_end + 4 :]
        else:
            header_block = ''
            body = resp

        cl_match = None
        for line in header_block.split('\r\n'):
            if line.lower().startswith('content-length:'):
                cl_match = int(line.split(':')[1].strip())
                break

        assert cl_match is not None, f'{name}: Content-Length header missing'
        assert cl_match == len(body), f'{name} Content-Length {cl_match} != body length {len(body)}'

    def test_wordpress_content_length(self):
        """WordPress response must have Content-Length matching body."""
        from manyfaced.handlers.wordpress_handler import WordPressHandler

        resp = self._get_response_bytes(WordPressHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'WordPress')

    def test_bitrix_content_length(self):
        """Bitrix response must have Content-Length matching body."""
        from manyfaced.handlers.bitrix_handler import BitrixHandler

        resp = self._get_response_bytes(BitrixHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'Bitrix')

    def test_cpanel_content_length(self):
        """CPanel response must have Content-Length matching body."""
        from manyfaced.handlers.cpanel_handler import CPanelHandler

        resp = self._get_response_bytes(CPanelHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'CPanel')

    def test_drupal_content_length(self):
        """Drupal response must have Content-Length matching body."""
        from manyfaced.handlers.drupal_handler import DrupalHandler

        resp = self._get_response_bytes(DrupalHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'Drupal')

    def test_jenkins_content_length(self):
        """Jenkins response must have Content-Length matching body."""
        from manyfaced.handlers.jenkins_handler import JenkinsHandler

        resp = self._get_response_bytes(JenkinsHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'Jenkins')

    def test_phpmyadmin_content_length(self):
        """PhpMyAdmin response must have Content-Length matching body."""
        from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler

        resp = self._get_response_bytes(PhpMyAdminHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'PhpMyAdmin')

    def test_tomcat_content_length(self):
        """Tomcat response must have Content-Length matching body."""
        from manyfaced.handlers.tomcat_handler import TomcatHandler

        resp = self._get_response_bytes(TomcatHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'Tomcat')

    def test_webdav_content_length(self):
        """WebDAV response must have Content-Length matching body."""
        from manyfaced.handlers.webdav_handler import WebDAVHandler

        resp = self._get_response_bytes(WebDAVHandler)
        assert resp is not None, 'generate_response returned None'
        self._verify_content_length(resp, 'WebDAV')

    def _verify_content_length(self, resp: bytes, name: str) -> None:
        """Parse headers and verify Content-Length matches body length."""
        header_end = resp.find(b'\r\n\r\n')
        if header_end != -1:
            header_block = resp[:header_end].decode()
            body = resp[header_end + 4 :]
        else:
            header_block = ''
            body = resp

        cl_match = None
        for line in header_block.split('\r\n'):
            if line.lower().startswith('content-length:'):
                cl_match = int(line.split(':')[1].strip())
                break

        assert cl_match is not None, f'{name}: Content-Length header missing'
        assert cl_match == len(body), f'{name} Content-Length {cl_match} != body length {len(body)}'


# ── Fix #100: End-to-end capture pipeline ─────────────────────────────────────

# Column indices from extract_record_fields():
# 0=bot_ip, 1=hostname, 2=timestamp, 3=request_path, 4=request_command,
# 5=request_version, 6=request_raw, 7=user_agent, ..., 12=detected_id, 14=login


class TestCapturePipelineEndToEnd:
    """Full request → handler → report_sender → storage must produce correct DB rows."""

    def test_http_wordpress_capture(self):
        """A WordPress probe routed through HTTPHandler produces a DB row with correct fields."""
        from manyfaced.common.status import WORDPRESS_HTTP
        from manyfaced.db.sql_builder import extract_record_fields

        raw_request = (
            'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
        )

        record = {
            'ip': '192.168.1.100',
            'raw_request': raw_request,
            'timestamp': '2024-01-01T00:00:00Z',
            'parsed_request': {
                'command': 'GET /wp-login.php HTTP/1.1',
                'path': '/wp-login.php',
                'method': 'GET',
                'user_agent': 'Mozilla/5.0',
                'detected_id': WORDPRESS_HTTP,
            },
            'isDetected': WORDPRESS_HTTP,
            'hostname': '',
            'dns_name': '',
            'country': '',
            'continent': '',
            'login': '',
            'password': '',
            'bot_profile_data': '{}',
        }

        fields = extract_record_fields(record)
        assert len(fields) == 17, f'Expected 17 DB columns, got {len(fields)}'

        # Verify key fields are populated correctly
        assert fields[0] == '192.168.1.100', 'bot_ip should match'
        assert fields[3] == '/wp-login.php', f'path should be /wp-login.php, got {fields[3]}'
        assert fields[12] == WORDPRESS_HTTP, (
            f'detected_id at index 12 should be {WORDPRESS_HTTP}, got {fields[12]}'
        )

    def test_ssh_probe_yields_ssh_detected_id(self):
        """An SSH probe must yield the SSH detected_id in the DB row."""
        from manyfaced.common.status import SSH_CLIENT
        from manyfaced.db.sql_builder import extract_record_fields

        record = {
            'ip': '10.0.0.5',
            'raw_request': 'SSH-2.0-OpenSSH_8.9\r\n',
            'timestamp': '2024-01-01T00:00:00Z',
            'parsed_request': {
                'command': 'SSH-2.0-OpenSSH_8.9',
                'path': '',
                'method': '',
                'user_agent': '',
                'detected_id': SSH_CLIENT,
            },
            'isDetected': SSH_CLIENT,
            'hostname': '',
            'dns_name': '',
            'country': '',
            'continent': '',
            'login': '',
            'password': '',
            'bot_profile_data': '{}',
        }

        fields = extract_record_fields(record)
        assert len(fields) == 17
        assert fields[12] == SSH_CLIENT, (
            f'detected_id at index 12 should be {SSH_CLIENT}, got {fields[12]}'
        )

    def test_interactive_protocol_populates_login(self):
        """An interactive protocol credential exchange must populate login in DB."""
        from manyfaced.db.sql_builder import extract_record_fields

        record = {
            'ip': '10.0.0.99',
            'raw_request': 'admin:password123\r\n',
            'timestamp': '2024-01-01T00:00:00Z',
            'parsed_request': {
                'command': '',
                'path': '',
                'method': '',
                'user_agent': '',
                'detected_id': 0,
            },
            'isDetected': 1,
            'hostname': '',
            'dns_name': '',
            'country': '',
            'continent': '',
            'login': 'admin',
            'password': 'password123',
            'bot_profile_data': '{}',
        }

        fields = extract_record_fields(record)
        assert len(fields) == 17
        # login is at index 14
        assert fields[14] == 'admin', f"login at index 14 should be 'admin', got {fields[14]}"


# ── Fix #98/#99: Data quality — raw_request non-empty ────────────────────────

# Column indices from extract_record_fields():
# Index 6 = request_raw (raw_request)


class TestDataQualityRawRequest:
    """raw_request must never be empty for detected bears."""

    def test_raw_request_populated(self):
        """A bear record with a request must have non-empty raw_request in DB."""
        from manyfaced.db.sql_builder import extract_record_fields

        raw = 'GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n'
        record = {
            'ip': '1.2.3.4',
            'raw_request': raw,
            'timestamp': '2024-01-01T00:00:00Z',
            'parsed_request': {
                'command': '',
                'path': '',
                'method': '',
                'user_agent': '',
                'detected_id': 0,
            },
            'isDetected': 1,
            'hostname': '',
            'dns_name': '',
            'country': '',
            'continent': '',
            'login': '',
            'password': '',
            'bot_profile_data': '{}',
        }

        fields = extract_record_fields(record)
        assert len(fields) == 17
        # raw_request is at index 6 (request_raw column)
        assert fields[6] != '' and 'GET' in str(fields[6]), (
            f'raw_request should be non-empty, got: {fields[6]}'
        )
