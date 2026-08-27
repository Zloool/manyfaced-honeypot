"""Regression tests for manyfaced.client.client non-HTTP dispatch.

These pin the silent-capture behavior called out in issue #653: a server-first
connect that receives our greeting but sends no client frame must be recorded as
EMPTY_CONNECTION (auditable in analysis), not as a normal session with an empty
request_raw. The client-first equivalent is already covered by the #601 guard.
"""

from unittest.mock import MagicMock, patch

from manyfaced.client import client as mfh_client
from manyfaced.common.faces import FaceSpec
from manyfaced.common.status import EMPTY_CONNECTION, UNKNOWN_TELNET


def _make_args():
    args = MagicMock()
    args.verbose = False
    args.server = 8888
    return args


def _server_first_spec() -> FaceSpec:
    return FaceSpec(
        name='telnet',
        detected_id=UNKNOWN_TELNET,
        direction='server-first',
        greeting=b'Telnet login:\r\n',
        respond=lambda raw, ip: b'',  # reply unused when no frame is read
        capture_creds=False,
        extract_creds=None,
    )


def test_server_first_no_frame_stamped_empty_connection():
    """A server-first connect sending no client frame after the greeting must
    be stamped EMPTY_CONNECTION (issue #653), not a silent normal session."""
    sock = MagicMock()
    sock.recv.return_value = b''  # client sent nothing after our greeting
    captured: dict = {}

    def _capture_bs(bs, bot_ip):  # noqa: ANN001
        captured['bs'] = bs

    spec = _server_first_spec()
    with patch.object(mfh_client, '_enrich_and_send_bear', _capture_bs):
        mfh_client._handle_non_http_connection(
            sock, _make_args(), ('203.0.113.5', 5555), MagicMock(), 23, spec
        )

    assert 'bs' in captured, 'BearStorage was never recorded'
    assert captured['bs'].isDetected == EMPTY_CONNECTION


def test_server_first_with_frame_not_empty_connection():
    """A server-first connect that DOES send a client frame is a genuine probe
    and must keep its face detected_id (regression guard for the #653 fix)."""
    sock = MagicMock()
    # First recv delivers the auth frame, second returns b'' (EOF) so the
    # frame reader terminates instead of looping forever on the mock.
    sock.recv.side_effect = [b'USER admin\r\n', b'']
    captured: dict = {}

    def _capture_bs(bs, bot_ip):  # noqa: ANN001
        captured['bs'] = bs

    spec = _server_first_spec()
    with patch.object(mfh_client, '_enrich_and_send_bear', _capture_bs):
        mfh_client._handle_non_http_connection(
            sock, _make_args(), ('203.0.113.5', 5555), MagicMock(), 23, spec
        )

    assert 'bs' in captured, 'BearStorage was never recorded'
    assert captured['bs'].isDetected == UNKNOWN_TELNET
