import datetime
import os
import socket
from multiprocessing import Process

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.settings import HIVELOGIN, HIVEPASS
from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.httphandler import HTTPRequest
from .base_handler import BaseHandler

logger = get_logger(__name__)


class HTTPHandler(BaseHandler):
    """HTTP honeypot handler with optional AI-powered response generation.

    When AI responder is enabled, the handler uses an LLM to generate
    realistic, interactive responses that encourage deeper exploitation
    attempts from probing bots.
    """

    def __init__(self, args, update_event):
        super().__init__(args, update_event)
        self._ai_responder = None
        self._ai_enabled = getattr(args, "ai_responder", False)
        if self._ai_enabled:
            self._init_ai_responder(args)

    def _init_ai_responder(self, args):
        """Initialize the AI responder and ResponderRegistry."""
        try:
            from manyfaced.common.ai_responder import AIResponder
            from manyfaced.common.responder import (
                PhpMyAdminResponder,
                ResponderRegistry,
                WordPressResponder,
                WebDAVResponder,
            )

            # Build AI config: CLI args override config file settings
            ai_endpoint = getattr(args, "ai_endpoint", "")
            ai_model = getattr(args, "ai_model", "")
            ai_max_tokens = getattr(args, "ai_max_tokens", 0)

            # Fall back to config file settings if CLI args not provided
            if not ai_endpoint:
                ai_endpoint = os.environ.get(
                    "HONEY_AI_ENDPOINT", "http://127.0.0.1:8080/v1"
                )
            if not ai_model:
                ai_model = os.environ.get(
                    "HONEY_AI_MODEL", "llama-3.1-8b-instruct"
                )
            if ai_max_tokens == 0:
                ai_max_tokens = int(os.environ.get("HONEY_AI_MAX_TOKENS", "500"))

            # Create ResponderRegistry with modular responders
            self._registry = ResponderRegistry()
            self._registry.register(PhpMyAdminResponder())
            self._registry.register(WordPressResponder())
            self._registry.register(WebDAVResponder())

            # Create AIResponder with registry
            self._ai_responder = AIResponder(
                endpoint=ai_endpoint,
                model=ai_model,
                max_tokens=ai_max_tokens,
                registry=self._registry,
            )

            if self._ai_responder.is_available():
                logger.info(
                    "AI responder enabled for interactive bot engagement "
                    "(model=%s, endpoint=%s, registry=%s)",
                    ai_model,
                    ai_endpoint,
                    self._registry,
                )
            else:
                logger.warning(
                    "AI responder enabled but unavailable – "
                    "llama-cpp-python not installed or endpoint unreachable"
                )
                self._ai_responder = None
        except Exception as e:
            logger.warning("Failed to initialize AI responder: %s", e)
            self._ai_responder = None

    def handle_request(self, message: str, bot_ip: str = "127.0.0.1"):
        """Handle a raw HTTP request from a bot.

        Unlike the server-side handler, this does NOT decrypt or parse JSON.
        It receives raw HTTP data, generates a honeypot response, and
        spawns a process to send the report to the server.

        Args:
            message: Raw HTTP request string from the bot.
            bot_ip: IP address of the connecting bot.

        Returns:
            The honeypot response data (HTTP response string or bytes).
        """
        # Parse the raw HTTP request
        try:
            parsed = HTTPRequest(message)
            # If parsing failed (path is None), create a minimal valid request
            if parsed.path is None:
                logger.warning("HTTPRequest failed to parse path, using fallback for %s", bot_ip)
                parsed = HTTPRequest("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n")
        except Exception as e:
            logger.warning("Failed to parse HTTP request: %s, using fallback for %s", e, bot_ip)
            parsed = HTTPRequest("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n")

        # Build the data dict that process_request expects
        data = {
            "ip": bot_ip,
            "raw_request": message,
            "parsed_request": parsed,
        }

        return self.process_request(data)

    def get_key(self, identifier):
        return HIVEPASS

    def process_request(self, data):
        """Import here to avoid circular dependency."""
        from manyfaced.client.client import get_honey_http, send_report

        bot_ip = data["ip"]
        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))

        logger.info("Incoming request from %s at %s", bot_ip, request_time)

        # Pass AI responder to get_honey_http for optional AI-powered response
        logger.debug("Calling get_honey_http for %s", bot_ip)
        output_data, detected = get_honey_http(
            data["parsed_request"],
            bot_ip,
            self.args.verbose,
            ai_responder=self._ai_responder,
        )
        logger.debug("get_honey_http returned for %s, detected=%s", bot_ip, detected)

        logger.debug("Creating BearStorage for %s", bot_ip)
        bs = BearStorage(
            bot_ip,
            data["raw_request"],
            request_time,
            data["parsed_request"],
            detected,
            HIVELOGIN,
        )
        logger.debug("BearStorage created for %s", bot_ip)

        # Determine server connection info for sending reports
        server_host = getattr(self.args, "server_host", "127.0.0.1")
        server_port = getattr(self.args, "server", None)

        if server_port is not None:
            logger.debug("Spawning send_report process for %s (server:%d)", bot_ip, server_port)
            Process(
                args=(bs, bot_ip, HIVEPASS, server_host, server_port),
                name="send_report",
                target=send_report,
            ).start()
            logger.debug("Spawned send_report process for %s", bot_ip)
        else:
            logger.debug("No server port configured, skipping report for %s", bot_ip)

        return output_data
