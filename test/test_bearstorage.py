"""Tests for manyfaced.common.bearstorage.BearStorage."""

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock geoip / GeoIP modules so the import of bearstorage does not fail
# ---------------------------------------------------------------------------
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules["geoip"] = geoip_mock
sys.modules["geoip.geolite2"] = geoip_mock.geolite2
sys.modules["GeoIP"] = MagicMock()

from manyfaced.common.bearstorage import BearStorage  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockParsedRequest:
    """Minimal mock that mimics a parsed HTTP request object."""

    def __init__(self, path="/", command="GET", request_version="HTTP/1.1"):
        self.path = path
        self.command = command
        self.request_version = request_version
        self.headers = MagicMock()
        self.headers.__getitem__ = MagicMock(return_value="Mozilla/5.0")
        self.headers.__contains__ = MagicMock(return_value=True)
        self.headers.get = MagicMock(return_value="Mozilla/5.0")


class MockParsedRequestNoUa:
    """Parsed request with headers but no user-agent key."""

    def __init__(self, path="/admin", command="POST", request_version="HTTP/1.0"):
        self.path = path
        self.command = command
        self.request_version = request_version
        self.headers = MagicMock()
        self.headers.__getitem__ = MagicMock(return_value="SomeHeader")
        self.headers.__contains__ = MagicMock(return_value=False)
        self.headers.get = MagicMock(return_value=None)


class MockParsedRequestNoHeaders:
    """Parsed request that has no ``headers`` attribute at all."""

    def __init__(self):
        self.path = "/shell.php"
        self.command = "GET"
        self.request_version = "HTTP/1.1"


class MockParsedRequestMinimal:
    """Parsed request that has no path, no command, no headers."""

    command = None


# ---------------------------------------------------------------------------
# __init__ tests
# ---------------------------------------------------------------------------


class TestBearStorageInit:
    """Tests for BearStorage.__init__."""

    def test_basic_attributes_set(self):
        """Basic attributes (ip, raw_request, timestamp, hostname) are stored."""
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="GET / HTTP/1.1",
            timestamp="2024-01-01T00:00:00Z",
            parsed_request=MockParsedRequest(),
            is_detected=1,
            hostname="testhost",
        )
        assert bs.ip == "1.2.3.4"
        assert bs.raw_request == "GET / HTTP/1.1"
        assert bs.timestamp == "2024-01-01T00:00:00Z"
        assert bs.hostname == "testhost"
        assert bs.isDetected == 1

    def test_extract_path(self):
        """Path is extracted from parsed_request when available."""
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=MockParsedRequest(path="/foo/bar"),
            is_detected=0,
            hostname="h",
        )
        assert bs.path == "/foo/bar"

    def test_extract_command(self):
        """Command is extracted from parsed_request when not None."""
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=MockParsedRequest(command="POST"),
            is_detected=0,
            hostname="h",
        )
        assert bs.command == "POST"

    def test_extract_version(self):
        """Version is extracted from parsed_request.request_version."""
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=MockParsedRequest(request_version="HTTP/2.0"),
            is_detected=0,
            hostname="h",
        )
        assert bs.version == "HTTP/2.0"

    def test_extract_headers_and_ua(self):
        """Headers are stored and ua is extracted from user-agent header."""
        pr = MockParsedRequest()
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=pr,
            is_detected=0,
            hostname="h",
        )
        assert bs.headers is not None  # MagicMock returned
        assert "user-agent" in bs.headers  # __contains__ returns True

    def test_no_user_agent_header(self):
        """ua stays empty when user-agent is not in headers."""
        pr = MockParsedRequestNoUa()
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=pr,
            is_detected=0,
            hostname="h",
        )
        assert bs.ua == ""

    def test_no_headers_attribute(self):
        """ua and headers stay empty when parsed_request has no headers."""
        pr = MockParsedRequestNoHeaders()
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=pr,
            is_detected=0,
            hostname="h",
        )
        assert bs.ua == ""
        assert bs.headers == ""

    def test_no_path_command_version(self):
        """Attributes stay empty when parsed_request has no relevant attrs."""
        pr = MockParsedRequestMinimal()
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=pr,
            is_detected=0,
            hostname="h",
        )
        assert bs.path == ""
        assert bs.command == ""
        assert bs.version == ""
        assert bs.ua == ""
        assert bs.headers == ""

    @patch("manyfaced.common.bearstorage.socket.gethostbyaddr")
    def test_dns_lookup_success(self, mock_gethostbyaddr):
        """DNS lookup populates dns_name on success."""
        mock_gethostbyaddr.return_value = ("example.com", [], [])
        bs = BearStorage(
            ip="8.8.8.8",
            raw_request="",
            timestamp="",
            parsed_request=MockParsedRequest(),
            is_detected=0,
            hostname="h",
        )
        assert bs.dns_name == "example.com"

    @patch("manyfaced.common.bearstorage.socket.gethostbyaddr")
    def test_dns_lookup_failure(self, mock_gethostbyaddr):
        """dns_name stays empty on socket.herror."""
        import socket

        mock_gethostbyaddr.side_effect = socket.herror(1, "no reverse")
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="",
            timestamp="",
            parsed_request=MockParsedRequest(),
            is_detected=0,
            hostname="h",
        )
        assert bs.dns_name == ""


# ---------------------------------------------------------------------------
# __str__ tests
# ---------------------------------------------------------------------------


class TestBearStorageStr:
    """Tests for BearStorage.__str__."""

    def test_str_with_path(self):
        """__str__ includes path, command, version, UA, detected info when path is set."""
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="GET / HTTP/1.1",
            timestamp="2024-01-01T00:00:00Z",
            parsed_request=MockParsedRequest(path="/admin"),
            is_detected=1,
            hostname="testhost",
        )
        result = str(bs)
        assert "hostname: testhost" in result
        assert "IP: 1.2.3.4" in result
        assert "timestamp: 2024-01-01T00:00:00Z" in result
        assert "path: /admin" in result
        assert "Detected: Yes" in result

    def test_str_without_path(self):
        """__str__ shows raw_request when path is empty."""
        bs = BearStorage(
            ip="5.6.7.8",
            raw_request="POST /shell.php HTTP/1.1",
            timestamp="2024-06-15T12:00:00Z",
            parsed_request=MockParsedRequestMinimal(),
            is_detected=0,
            hostname="nohost",
        )
        result = str(bs)
        assert "hostname: nohost" in result
        assert "IP: 5.6.7.8" in result
        assert "timestamp: 2024-06-15T12:00:00Z" in result
        assert "raw_request: POST /shell.php HTTP/1.1" in result
        assert "country: " in result
        # The without-path branch does NOT include "Detected:" line
        assert "Detected:" not in result

    def test_str_detected_no(self):
        """When isDetected == 4294967295 - 3, shows Detected: No."""
        special = 4294967295 - 3
        bs = BearStorage(
            ip="1.1.1.1",
            raw_request="",
            timestamp="",
            parsed_request=MockParsedRequest(path="/x"),
            is_detected=special,
            hostname="h",
        )
        result = str(bs)
        assert "Detected: No" in result


# ---------------------------------------------------------------------------
# __repr__ tests
# ---------------------------------------------------------------------------


class TestBearStorageRepr:
    """Tests for BearStorage.__repr__."""

    def test_repr_same_as_str(self):
        """__repr__ returns the same string as __str__."""
        bs = BearStorage(
            ip="1.2.3.4",
            raw_request="GET / HTTP/1.1",
            timestamp="2024-01-01T00:00:00Z",
            parsed_request=MockParsedRequest(path="/test"),
            is_detected=1,
            hostname="h",
        )
        assert repr(bs) == str(bs)

    def test_repr_without_path(self):
        """__repr__ works correctly when path is empty."""
        bs = BearStorage(
            ip="2.2.2.2",
            raw_request="GET / HTTP/1.1",
            timestamp="",
            parsed_request=MockParsedRequestMinimal(),
            is_detected=0,
            hostname="h",
        )
        assert repr(bs) == str(bs)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestBearStorageEdgeCases:
    """Edge-case tests for BearStorage."""

    def test_empty_parsed_request_is_none(self):
        """Passing an object with no relevant attributes."""

        class EmptyRequest:
            command = None

        bs = BearStorage(
            ip="0.0.0.0",
            raw_request="",
            timestamp="",
            parsed_request=EmptyRequest(),
            is_detected=0,
            hostname="h",
        )
        assert bs.path == ""
        assert bs.command == ""
        assert bs.version == ""

    def test_all_attributes_present(self):
        """All expected attributes exist on the instance."""
        bs = BearStorage(
            ip="10.0.0.1",
            raw_request="full request",
            timestamp="now",
            parsed_request=MockParsedRequest(
                path="/p", command="GET", request_version="HTTP/1.1"
            ),
            is_detected=1,
            hostname="myhost",
        )
        for attr in (
            "ip",
            "raw_request",
            "timestamp",
            "path",
            "command",
            "version",
            "ua",
            "headers",
            "country",
            "continent",
            "timezone",
            "dns_name",
            "tracert",
            "isDetected",
            "hostname",
        ):
            assert hasattr(bs, attr), f"Missing attribute: {attr}"
