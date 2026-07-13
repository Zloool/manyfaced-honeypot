"""Regression tests for CLUSTER G1 — geo/ASN attribution promotion, orphan
port=0 recovery, empty bot_profile_data drop, and HTTP-on-SSH-port mismatch.

Covers issues #516 / #517 / #450 / #488 / #445.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root importable for direct test runs.
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.server import server as server_mod
from manyfaced.server.server import (
    _port_from_host,
    _promote_attribution,
    ServerHandler,
)


# ---------------------------------------------------------------------------
# _port_from_host
# ---------------------------------------------------------------------------


def test_port_from_host_with_port_suffix():
    assert _port_from_host('68.183.114.1:10110') == 10110
    assert _port_from_host('host.example.com:22') == 22
    assert _port_from_host('[::1]:8080') == 8080


def test_port_from_host_no_port():
    assert _port_from_host('68.183.114.1') == 0
    assert _port_from_host('') == 0
    assert _port_from_host(None) == 0
    assert _port_from_host('host:notaport') == 0


# ---------------------------------------------------------------------------
# _promote_attribution — JSON -> flat column promotion (issue #516 / #517)
# ---------------------------------------------------------------------------


def test_promote_bot_ip_from_json():
    """Empty top-level ip is recovered from bot_profile_data.bot_ip."""
    data = {
        'ip': '',
        'asn': '',
        'org': '',
        'bot_profile_data': {
            'bot_ip': '66.132.172.188',
            'metadata': {'host': '68.183.114.1:10110'},
        },
    }
    promoted = _promote_attribution(data)
    assert promoted['ip'] == '66.132.172.188'


def test_promote_listen_port_from_metadata_host():
    """Orphan port=0 is recovered from metadata.host port suffix (issue #450)."""
    data = {
        'ip': '5.61.209.92',
        'listen_port': 0,
        'bot_profile_data': {
            'bot_ip': '5.61.209.92',
            'metadata': {'host': '68.183.114.1:80'},
        },
    }
    promoted = _promote_attribution(data)
    assert promoted['listen_port'] == 80


def test_promote_port_when_json_string():
    """bot_profile_data may arrive already JSON-encoded as a string."""
    data = {
        'ip': '1.2.3.4',
        'listen_port': 0,
        'bot_profile_data': '{"bot_ip": "1.2.3.4", "metadata": {"host": "9.9.9.9:10445"}}',
    }
    promoted = _promote_attribution(data)
    assert promoted['listen_port'] == 10445


def test_promote_asn_org_from_json():
    """Network signals embedded in JSON are recovered when flat cols empty."""
    data = {
        'ip': '6.7.8.9',
        'asn': '',
        'org': '',
        'bot_profile_data': {
            'bot_ip': '6.7.8.9',
            'asn': 'AS13335',
            'org': 'Cloudflare, Inc.',
        },
    }
    promoted = _promote_attribution(data)
    assert promoted['asn'] == 'AS13335'
    assert promoted['org'] == 'Cloudflare, Inc.'


def test_flat_fields_win_over_json():
    """Top-level flat fields are authoritative when populated."""
    data = {
        'ip': '1.1.1.1',
        'asn': 'AS11111',
        'org': 'Real Org',
        'listen_port': 1234,
        'bot_profile_data': {
            'bot_ip': '2.2.2.2',  # should be ignored
            'asn': 'AS22222',
            'metadata': {'host': 'x:9999'},
        },
    }
    promoted = _promote_attribution(data)
    assert promoted['ip'] == '1.1.1.1'
    assert promoted['asn'] == 'AS11111'
    assert promoted['org'] == 'Real Org'
    assert promoted['listen_port'] == 1234


def test_no_bot_profile_data_returns_flat():
    """When there is no bot_profile_data, the flat dict is returned untouched."""
    data = {'ip': '3.3.3.3', 'asn': 'AS3', 'listen_port': 22}
    promoted = _promote_attribution(data)
    assert promoted['ip'] == '3.3.3.3'
    assert promoted['listen_port'] == 22


# ---------------------------------------------------------------------------
# ServerHandler.save_data — full-row promotion, synthetic BotProfile
# ---------------------------------------------------------------------------


def _make_args():
    args = MagicMock()
    args.verbose = False
    args.server = 8888
    return args


@patch.object(server_mod, 'Insert')
def test_save_data_promotes_json_to_flat_columns(mock_insert):
    """Synthetic BotProfile with bot_ip+host:port -> stored row populated (#517/#450)."""
    handler = ServerHandler(_make_args(), MagicMock())
    data = {
        'ip': '',  # top-level empty — attribution only in JSON
        'raw_request': 'GET / HTTP/1.1',
        'timestamp': '2026-07-13 00:00:00.000000',
        'parsed_request': {
            'command': 'GET',
            'path': '/',
            'request_version': 'HTTP/1.1',
            'headers': {},
        },
        'is_detected': 1,
        'HIVELOGIN': 'honeypot',
        'ua': '',
        'dns_name': '',
        'country': '',
        'continent': '',
        'login': '',
        'listen_port': 0,
        'asn': '',
        'org': '',
        'bot_profile_data': {
            'bot_ip': '66.132.172.188',
            'metadata': {'host': '68.183.114.1:10110'},
            'asn': 'AS12345',
            'org': 'Attacker Networks',
        },
    }
    handler.save_data(data, _make_args())
    assert mock_insert.called
    bear = mock_insert.call_args[0][0]
    # The row is no longer anonymous: ip + port + asn promoted from JSON.
    assert bear.ip == '66.132.172.188'
    assert bear.listen_port == 10110
    assert bear.asn == 'AS12345'
    assert bear.org == 'Attacker Networks'


# ---------------------------------------------------------------------------
# HTTP-on-SSH-port protocol mismatch (issue #445)
# ---------------------------------------------------------------------------


def test_looks_like_http_probe_https_request():
    """A GET/POST/... request line is detected as an HTTP probe."""
    from manyfaced.common.protocol import detect_protocol

    assert detect_protocol(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n') == 'http'
    assert detect_protocol(b'POST /login HTTP/1.1\r\n\r\n') == 'http'
    assert detect_protocol(b'OPTIONS * HTTP/1.1\r\n\r\n') == 'http'
    assert detect_protocol(b'CONNECT host:22 HTTP/1.1\r\n\r\n') == 'http'
