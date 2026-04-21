"""
Comprehensive pytest tests for HTTPHandler and HTTPRequest modules.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip before any handler module is imported
_geoip_mock = MagicMock()
_geoip_mock.geolite2.geolite2 = _geoip_mock.geolite2
sys.modules["geoip"] = _geoip_mock
sys.modules["geoip.geolite2"] = _geoip_mock.geolite2
sys.modules["GeoIP"] = MagicMock()

from manyfaced.common.settings import HIVEPASS, HIVELOGIN  # noqa: E402
from manyfaced.common.httphandler import HTTPRequest  # noqa: E402
from manyfaced.handlers.http_handler import HTTPHandler  # noqa: E402


# ---------------------------------------------------------------------------
# HTTPHandler Tests
# ---------------------------------------------------------------------------


class TestHTTPHandlerGetKey:
    """Tests for HTTPHandler.get_key()."""

    @pytest.fixture
    def handler(self):
        """Create a minimal HTTPHandler instance."""
        args = MagicMock()
        args.verbose = False
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_get_key_returns_hivepass(self, handler):
        """get_key() should always return HIVEPASS regardless of identifier."""
        result = handler.get_key("some_bear_id")
        assert result == HIVEPASS

    def test_get_key_with_different_identifiers(self, handler):
        """get_key() should return HIVEPASS for various identifier types."""
        for identifier in ["bear1", "", "12345", "a" * 100]:
            assert handler.get_key(identifier) == HIVEPASS

    def test_get_key_returns_string(self, handler):
        """get_key() should return a string value."""
        result = handler.get_key("test")
        assert isinstance(result, str)
        assert len(result) > 0


class TestHTTPHandlerProcessRequest:
    """Tests for HTTPHandler.process_request()."""

    @pytest.fixture
    def handler(self):
        """Create a minimal HTTPHandler instance."""
        args = MagicMock()
        args.verbose = False
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    @pytest.fixture
    def sample_data(self):
        """Provide a sample request data dict."""
        raw = "GET /admin.php HTTP/1.1\r\nHost: example.com\r\n\r\n"
        return {
            "ip": "10.0.0.1",
            "raw_request": raw,
            "parsed_request": MagicMock(),
        }

    def _make_mocks(self):
        """Return a dict of mock context managers for the client module."""
        mock_ghh = patch("manyfaced.client.client.get_honey_http")
        mock_send = patch("manyfaced.client.client.send_report")
        return mock_ghh, mock_send

    def test_process_request_calls_get_honey_http(self, handler, sample_data):
        """process_request() should call get_honey_http with the right arguments."""
        mock_ghh, mock_send = self._make_mocks()
        with mock_ghh as ghh_mock, mock_send, \
             patch("manyfaced.handlers.http_handler.BearStorage"), \
             patch("manyfaced.handlers.http_handler.Process") as mock_proc:
            ghh_mock.return_value = ("HTTP/1.1 200 OK\r\n\r\n", True)
            mock_proc.return_value = MagicMock()

            handler.process_request(sample_data)

            # Verify get_honey_http was called
            assert ghh_mock.called
            call_args = ghh_mock.call_args
            # First arg should be an HTTPRequest instance
            assert isinstance(call_args[0][0], HTTPRequest)
            # Second arg should be the bot_ip
            assert call_args[0][1] == "10.0.0.1"
            # Third arg should be verbose
            assert call_args[0][2] is False

    def test_process_request_spawns_send_report_process(self, handler, sample_data):
        """process_request() should spawn a send_report Process."""
        mock_ghh, mock_send = self._make_mocks()
        with mock_ghh as ghh_mock, mock_send, \
             patch("manyfaced.handlers.http_handler.BearStorage"), \
             patch("manyfaced.handlers.http_handler.Process") as mock_proc:
            ghh_mock.return_value = ("HTTP/1.1 200 OK\r\n\r\n", True)
            mock_proc.return_value = MagicMock()

            handler.process_request(sample_data)

            # Verify Process was instantiated
            assert mock_proc.called
            process_kwargs = mock_proc.call_args
            # Should have been started
            assert mock_proc.return_value.start.called
            # Process name should be "send_report"
            assert process_kwargs.kwargs.get("name") == "send_report"
            # Target should be send_report (the mocked function)
            assert process_kwargs.kwargs.get("target") is not None

    def test_process_request_returns_output_data(self, handler, sample_data):
        """process_request() should return the output_data from get_honey_http."""
        mock_ghh, mock_send = self._make_mocks()
        with mock_ghh as ghh_mock, mock_send, \
             patch("manyfaced.handlers.http_handler.BearStorage"), \
             patch("manyfaced.handlers.http_handler.Process"):
            ghh_mock.return_value = ("HTTP/1.1 200 OK\r\n\r\n", True)

            result = handler.process_request(sample_data)
            assert result == "HTTP/1.1 200 OK\r\n\r\n"

    def test_process_request_with_verbose_true(self, handler):
        """process_request() should pass verbose flag to get_honey_http."""
        handler.args.verbose = True
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        mock_ghh = patch("manyfaced.client.client.get_honey_http")
        with mock_ghh as ghh_mock, \
             patch("manyfaced.handlers.http_handler.BearStorage"), \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            ghh_mock.return_value = ("", False)

            handler.process_request(sample_data)

            assert ghh_mock.call_args[0][2] is True


class TestHTTPHandlerProcessRequestDataFlow:
    """Tests verifying data flow through process_request()."""

    @pytest.fixture
    def handler(self):
        args = MagicMock()
        args.verbose = False
        update_event = MagicMock()
        return HTTPHandler(args, update_event)

    def test_bot_ip_passed_to_bearstorage(self, handler):
        """bot_ip from data['ip'] should be passed to BearStorage."""
        sample_data = {
            "ip": "192.168.99.99",
            "raw_request": "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)

            handler.process_request(sample_data)

            # Verify BearStorage was called with bot_ip as first arg
            bs_call = mock_bs.call_args
            assert bs_call[0][0] == "192.168.99.99"

    def test_raw_request_passed_to_bearstorage(self, handler):
        """raw_request from data should be passed to BearStorage."""
        raw = "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": raw,
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)

            handler.process_request(sample_data)

            bs_call = mock_bs.call_args
            assert bs_call[0][1] == raw

    def test_parsed_request_passed_to_bearstorage(self, handler):
        """parsed_request from data should be passed to BearStorage."""
        expected_parsed = MagicMock()
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "parsed_request": expected_parsed,
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)

            handler.process_request(sample_data)

            bs_call = mock_bs.call_args
            assert bs_call[0][3] == expected_parsed

    def test_detected_passed_to_bearstorage(self, handler):
        """detected value from get_honey_http should be passed to BearStorage."""
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", 1)

            handler.process_request(sample_data)

            bs_call = mock_bs.call_args
            assert bs_call[0][4] == 1

    def test_hivelogin_passed_to_bearstorage(self, handler):
        """HIVELOGIN should be passed to BearStorage as hostname."""
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)

            handler.process_request(sample_data)

            bs_call = mock_bs.call_args
            assert bs_call[0][5] == HIVELOGIN

    def test_send_report_receives_bearstorage(self, handler):
        """send_report Process should receive BearStorage as first argument."""
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process") as mock_proc, \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)
            mock_proc.return_value = MagicMock()

            handler.process_request(sample_data)

            process_kwargs = mock_proc.call_args
            # First arg in args tuple should be the BearStorage instance
            assert isinstance(process_kwargs.kwargs["args"][0], MagicMock)
            # HIVELOGIN should be second arg
            assert process_kwargs.kwargs["args"][1] == HIVELOGIN
            # HIVEPASS should be third arg
            assert process_kwargs.kwargs["args"][2] == HIVEPASS

    def test_request_time_format(self, handler):
        """request_time should be in expected datetime format."""
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage") as mock_bs, \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)

            handler.process_request(sample_data)

            bs_call = mock_bs.call_args
            timestamp = bs_call[0][2]
            # Should match pattern like "2026-04-20 07:49:00.000000"
            parts = timestamp.split(" ")
            assert len(parts) == 2
            date_parts = parts[0].split("-")
            assert len(date_parts) == 3
            time_parts = parts[1].split(":")
            assert len(time_parts) == 3
            assert "." in time_parts[2]  # microseconds present

    def test_heartbeat_request_passed_to_get_honey_http(self, handler):
        """HTTPRequest should be constructed from data['raw_request']."""
        raw = "GET /heartbeat HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": raw,
            "parsed_request": MagicMock(),
        }

        with patch("manyfaced.client.client.get_honey_http") as mock_ghh, \
             patch("manyfaced.handlers.http_handler.BearStorage"), \
             patch("manyfaced.handlers.http_handler.Process"), \
             patch("manyfaced.client.client.send_report"):
            mock_ghh.return_value = ("", False)

            handler.process_request(sample_data)

            http_req = mock_ghh.call_args[0][0]
            assert isinstance(http_req, HTTPRequest)
            assert http_req.command == "GET"
            assert http_req.path == "/heartbeat"


# ---------------------------------------------------------------------------
# HTTPRequest Tests
# ---------------------------------------------------------------------------


