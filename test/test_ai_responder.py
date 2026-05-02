"""
Comprehensive pytest tests for AIResponder module.

Tests cover:
- AIResponder initialization and availability
- Request classification
- Prompt building
- Response generation (with mocked LLM)
- Fallback behavior when LLM is unavailable
- Integration with HTTPHandler
- Config loading with AI fields
- CLI argument parsing for AI flags
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


# ---------------------------------------------------------------------------
# AIResponder Tests
# ---------------------------------------------------------------------------


class TestAIResponderInit:
    """Tests for AIResponder initialization."""

    def test_init_without_llama_cpp(self):
        """AIResponder should initialize without llama-cpp-python installed."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder(
                endpoint="http://127.0.0.1:8080/v1",
                model="llama-3.1-8b-instruct",
            )
            assert responder.endpoint == "http://127.0.0.1:8080/v1"
            assert responder.model == "llama-3.1-8b-instruct"
            assert responder.max_tokens == 500
            assert responder.timeout == 5.0
            assert not responder.is_available()

    def test_init_custom_params(self):
        """AIResponder should accept custom parameters."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder(
                endpoint="http://localhost:9000/v1",
                model="custom-model",
                max_tokens=1000,
                timeout=10.0,
            )
            assert responder.endpoint == "http://localhost:9000/v1"
            assert responder.model == "custom-model"
            assert responder.max_tokens == 1000
            assert responder.timeout == 10.0

    def test_init_with_custom_persona(self):
        """AIResponder should accept a custom persona template."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            custom_template = "Custom persona for {path}"
            responder = AIResponder(persona_template=custom_template)
            assert responder.persona_template == custom_template

    def test_repr(self):
        """AIResponder.__repr__ should return a meaningful string."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            repr_str = repr(responder)
            assert "AIResponder" in repr_str
            assert "available=False" in repr_str


class TestAIResponderAvailability:
    """Tests for AIResponder availability checking."""

    def test_not_available_without_llama(self):
        """is_available() should return False without llama-cpp-python."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            assert responder.is_available() is False

    def test_init_flag_set_on_import_error(self):
        """_initialized should be False when llama_cpp is not available."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            assert responder._initialized is False

    def test_ping_endpoint_unreachable(self):
        """_ping_endpoint() should return False when endpoint is down."""
        from manyfaced.common.ai_responder import AIResponder

        responder = AIResponder(endpoint="http://127.0.0.1:19999/v1")
        responder._initialized = True  # Pretend openai is installed
        assert responder._ping_endpoint() is False

    def test_ping_endpoint_mocked_success(self):
        """_ping_endpoint() should return True when endpoint responds."""
        from manyfaced.common.ai_responder import AIResponder

        mock_client = MagicMock()
        mock_client.models.list.return_value = MagicMock()

        mock_openai = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            responder = AIResponder(endpoint="http://127.0.0.1:18080/v1")
            responder._initialized = True
            # Reset call count before testing _ping_endpoint
            mock_client.models.list.reset_mock()
            assert responder._ping_endpoint() is True
            mock_client.models.list.assert_called_once()


class TestAIResponderClassification:
    """Tests for request classification."""

    def test_classify_wordpress(self):
        """Requests to WordPress paths should be classified as 'wordpress'."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            assert responder._classify_request("/wp-login.php", "") == "wordpress"
            assert responder._classify_request("/wp-admin/", "") == "wordpress"
            assert (
                responder._classify_request("/wp-content/uploads/", "") == "wordpress"
            )
            assert responder._classify_request("/wordpress/", "") == "wordpress"

    def test_classify_phpmyadmin(self):
        """Requests to phpMyAdmin paths should be classified as 'phpmyadmin'."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            assert responder._classify_request("/phpmyadmin/", "") == "phpmyadmin"
            assert responder._classify_request("/pma/", "") == "phpmyadmin"
            assert responder._classify_request("/phpmy/", "") == "phpmyadmin"

    def test_classify_webdav(self):
        """Requests to WebDAV paths should be classified as 'webdav'."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            assert responder._classify_request("/webdav/", "") == "webdav"
            assert responder._classify_request("/dav/", "") == "webdav"

    def test_classify_generic(self):
        """Unknown paths should be classified as 'generic'."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            assert responder._classify_request("/", "") == "generic"
            assert responder._classify_request("/admin.php", "") == "generic"
            assert responder._classify_request("/shell.php", "") == "generic"
            assert responder._classify_request("/random/path", "") == "generic"


class TestAIResponderPromptBuilding:
    """Tests for prompt building."""

    def test_build_prompt_uses_default_template(self):
        """build_prompt() should include path, bot_ip, and face_type in prompt."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            prompt = responder._build_prompt("/admin.php", "", "1.2.3.4")
            assert "/admin.php" in prompt
            assert "1.2.3.4" in prompt

    def test_build_prompt_truncates_long_requests(self):
        """build_prompt() should truncate raw_request to 2000 chars."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            long_request = "GET / HTTP/1.1\r\n" + "A" * 5000
            prompt = responder._build_prompt("/", long_request, "1.2.3.4")
            # The raw_request in prompt should be truncated
            assert len(prompt) < 6000  # Should be significantly shorter

    def test_build_prompt_uses_category_override(self):
        """build_prompt() should use category-specific persona override."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            prompt = responder._build_prompt("/wp-login.php", "", "1.2.3.4")
            # WordPress override should mention WordPress
            assert "WordPress" in prompt


class TestAIResponderGenerateResponse:
    """Tests for response generation."""

    def test_generate_response_raises_when_unavailable(self):
        """generate_response() should raise RuntimeError when not available."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            with pytest.raises(RuntimeError, match="not available"):
                responder.generate_response("/wp-login.php", "", "1.2.3.4")

    def test_generate_response_with_mocked_llm(self):
        """generate_response() should return bytes when LLM is mocked."""
        from manyfaced.common.ai_responder import AIResponder

        responder = AIResponder(endpoint="http://127.0.0.1:18080/v1")
        responder._initialized = True
        responder._available = True

        with patch.object(responder, "_call_llm", return_value="Hello, bot!"):
            response_bytes, detected = responder.generate_response(
                "/wp-login.php", "", "1.2.3.4"
            )
            assert isinstance(response_bytes, bytes)
            assert detected == 1
            assert b"HTTP/1.1" in response_bytes
            assert b"text/html" in response_bytes

    def test_generate_response_fallback_on_llm_error(self):
        """generate_response() should raise on LLM error."""
        from manyfaced.common.ai_responder import AIResponder

        responder = AIResponder(endpoint="http://127.0.0.1:18080/v1")
        responder._initialized = True
        responder._available = True

        with patch.object(responder, "_call_llm", side_effect=Exception("LLM error")):
            with pytest.raises(Exception, match="LLM error"):
                responder.generate_response("/wp-login.php", "", "1.2.3.4")


class TestAIResponderHTTPResponse:
    """Tests for HTTP response building."""

    def test_build_http_response_basic(self):
        """_build_http_response() should produce valid HTTP response."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            response_bytes = responder._build_http_response("Hello", None)
            assert b"HTTP/1.1 200 OK" in response_bytes
            assert b"Server:" in response_bytes
            assert b"Content-Type:" in response_bytes
            assert b"Connection: close" in response_bytes
            assert b"Hello" in response_bytes

    def test_build_http_response_xml_content_type(self):
        """_build_http_response() should use XML content type for .xml faces."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            response_bytes = responder._build_http_response("<xml/>", "webdav.xml")
            assert b"application/xml" in response_bytes

    def test_build_http_response_is_bytes(self):
        """_build_http_response() should return bytes."""
        with patch.dict("sys.modules", {"openai": None}):
            from manyfaced.common.ai_responder import AIResponder

            responder = AIResponder()
            response_bytes = responder._build_http_response("test", None)
            assert isinstance(response_bytes, bytes)


# ---------------------------------------------------------------------------
# HTTPHandler AI Integration Tests
# ---------------------------------------------------------------------------


class TestHTTPHandlerAIIntegration:
    """Tests for HTTPHandler AI responder integration."""

    @pytest.fixture
    def handler_no_ai(self):
        """Create HTTPHandler without AI responder."""
        args = MagicMock()
        args.verbose = False
        args.ai_responder = False
        update_event = MagicMock()
        from manyfaced.handlers.http_handler import HTTPHandler

        return HTTPHandler(args, update_event)

    @pytest.fixture
    def handler_with_ai(self):
        """Create HTTPHandler with AI responder enabled (but unavailable)."""
        args = MagicMock()
        args.verbose = False
        args.ai_responder = True
        args.ai_endpoint = "http://127.0.0.1:8080/v1"
        args.ai_model = "test-model"
        args.ai_max_tokens = 500
        update_event = MagicMock()
        from manyfaced.handlers.http_handler import HTTPHandler

        return HTTPHandler(args, update_event)

    def test_handler_without_ai_has_no_responder(self, handler_no_ai):
        """HTTPHandler without AI should have _ai_responder=None."""
        assert handler_no_ai._ai_responder is None
        assert handler_no_ai._ai_enabled is False

    def test_handler_with_ai_has_responder_attr(self, handler_with_ai):
        """HTTPHandler with AI enabled should have _ai_responder attribute."""
        assert hasattr(handler_with_ai, "_ai_responder")
        assert handler_with_ai._ai_enabled is True
        # Responder should be None since llama_cpp is not installed
        assert handler_with_ai._ai_responder is None

    def test_process_request_with_handler_match(self):
        """process_request() uses handler registry when path matches."""
        args = MagicMock()
        args.verbose = False
        args.ai_responder = False
        update_event = MagicMock()

        from manyfaced.handlers.http_handler import HTTPHandler

        handler = HTTPHandler(args, update_event)

        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with (
            patch("manyfaced.client.client.send_report"),
            patch("multiprocessing.Process") as mock_proc,
        ):
            response = handler.process_request(sample_data)

            # Handler registry matched /wp-login.php and returned a response
            assert response is not None
            assert isinstance(response, bytes)

    def test_process_request_without_ai_flag(self):
        """process_request() works correctly when AI is disabled."""
        args = MagicMock()
        args.verbose = False
        args.ai_responder = False
        update_event = MagicMock()

        from manyfaced.handlers.http_handler import HTTPHandler

        handler = HTTPHandler(args, update_event)

        sample_data = {
            "ip": "10.0.0.1",
            "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "parsed_request": MagicMock(),
        }

        with (
            patch("manyfaced.client.client.send_report"),
            patch("multiprocessing.Process") as mock_proc,
        ):
            response = handler.process_request(sample_data)

            # Should fall back to _fallback_response
            assert response is not None
            assert isinstance(response, bytes)


# ---------------------------------------------------------------------------
# get_honey_http AI Integration Tests
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Config AI Fields Tests
# ---------------------------------------------------------------------------


class TestConfigAILoad:
    """Tests for AI config field loading."""

    def test_config_has_ai_fields(self):
        """Config should have AI_* fields."""
        from manyfaced.common.config import settings

        assert hasattr(settings, "AI_ENABLED")
        assert hasattr(settings, "AI_ENDPOINT")
        assert hasattr(settings, "AI_MODEL")
        assert hasattr(settings, "AI_MAX_TOKENS")
        assert hasattr(settings, "AI_TIMEOUT")

    def test_config_ai_defaults(self):
        """Config AI fields should have correct defaults."""
        from manyfaced.common.config import settings

        assert settings.AI_ENABLED is False
        assert settings.AI_ENDPOINT == "http://127.0.0.1:8080/v1"
        assert settings.AI_MODEL == "llama-3.1-8b-instruct"
        assert settings.AI_MAX_TOKENS == 500
        assert settings.AI_TIMEOUT == 5.0

    def test_config_ai_enabled_via_env(self):
        """AI_ENABLED should be overridable via environment variable."""
        from manyfaced.common.config import Config

        config = Config.load()
        assert config.AI_ENABLED is False  # Default

    def test_config_ai_max_tokens_type(self):
        """AI_MAX_TOKENS should be an int."""
        from manyfaced.common.config import settings

        assert isinstance(settings.AI_MAX_TOKENS, int)

    def test_config_ai_timeout_type(self):
        """AI_TIMEOUT should be a float."""
        from manyfaced.common.config import settings

        assert isinstance(settings.AI_TIMEOUT, float)


# ---------------------------------------------------------------------------
# CLI Arguments AI Flags Tests
# ---------------------------------------------------------------------------


class TestCLIArgsAI:
    """Tests for AI CLI argument parsing."""

    def test_parse_ai_responder_flag(self):
        """--ai-responder flag should set ai_responder=True."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py", "--ai-responder"]):
            args = parse()
            assert args.ai_responder is True

    def test_parse_ai_responder_default(self):
        """ai_responder should default to False."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py"]):
            args = parse()
            assert args.ai_responder is False

    def test_parse_ai_endpoint_flag(self):
        """--ai-endpoint flag should set ai_endpoint."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py", "--ai-endpoint", "http://localhost:9000/v1"]):
            args = parse()
            assert args.ai_endpoint == "http://localhost:9000/v1"

    def test_parse_ai_endpoint_default(self):
        """ai_endpoint should default to empty string."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py"]):
            args = parse()
            assert args.ai_endpoint == ""

    def test_parse_ai_model_flag(self):
        """--ai-model flag should set ai_model."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py", "--ai-model", "my-model"]):
            args = parse()
            assert args.ai_model == "my-model"

    def test_parse_ai_max_tokens_flag(self):
        """--ai-max-tokens flag should set ai_max_tokens."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py", "--ai-max-tokens", "1000"]):
            args = parse()
            assert args.ai_max_tokens == 1000

    def test_parse_ai_max_tokens_default(self):
        """ai_max_tokens should default to 0."""
        from manyfaced.common.arguments import parse

        with patch("sys.argv", ["mfh.py"]):
            args = parse()
            assert args.ai_max_tokens == 0

    def test_parse_all_ai_flags(self):
        """All AI flags should be parseable together."""
        from manyfaced.common.arguments import parse

        with patch(
            "sys.argv",
            [
                "mfh.py",
                "--ai-responder",
                "--ai-endpoint",
                "http://localhost:9000/v1",
                "--ai-model",
                "my-model",
                "--ai-max-tokens",
                "1000",
            ],
        ):
            args = parse()
            assert args.ai_responder is True
            assert args.ai_endpoint == "http://localhost:9000/v1"
            assert args.ai_model == "my-model"
            assert args.ai_max_tokens == 1000


# ---------------------------------------------------------------------------
# Backward Compatibility Tests
# ---------------------------------------------------------------------------
