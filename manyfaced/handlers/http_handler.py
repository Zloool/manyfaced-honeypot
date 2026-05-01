"""HTTPHandler – handles raw HTTP requests from bots.

This handler receives raw HTTP data from connecting bots, routes requests
to the appropriate service handler via the HandlerRegistry, generates
realistic honeypot responses, and spawns processes to send reports to
the server.

The handler system replaces the old "faces" dict approach with specialized
handlers for each service (WordPress, phpMyAdmin, Jenkins, Tomcat, etc.).
"""

from __future__ import annotations

import datetime
import os
import random
import threading
from concurrent.futures import ThreadPoolExecutor

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.config import settings
from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.httphandler import HTTPRequest
from manyfaced.common.protocol import detect_protocol, get_protocol_info
from manyfaced.common.status import SSH_CLIENT, UNKNOWN_NON_HTTP
from .registry import HandlerRegistry
from .wordpress_handler import WordPressHandler
from .phpmyadmin_handler import PhpMyAdminHandler
from .jenkins_handler import JenkinsHandler
from .tomcat_handler import TomcatHandler
from .drupal_handler import DrupalHandler
from .cpanel_handler import CPanelHandler
from .generic_handler import GenericHandler

logger = get_logger(__name__)


# Singleton registry – initialized on first use
_registry: HandlerRegistry | None = None

# Thread pool for sending reports (replaces per-request subprocess spawning)
# Using a thread pool instead of multiprocessing.Process per request prevents
# process explosion (was spawning 1 process per bot request → 200+ processes)
_report_executor: ThreadPoolExecutor | None = None
_report_executor_lock = threading.Lock()

MAX_REPORT_THREADS = 10


def _get_report_executor() -> ThreadPoolExecutor:
    """Get or create the module-level report thread pool (singleton)."""
    global _report_executor
    if _report_executor is None or _report_executor._shutdown:
        with _report_executor_lock:
            # Double-check after acquiring lock
            if _report_executor is None or _report_executor._shutdown:
                _report_executor = ThreadPoolExecutor(
                    max_workers=MAX_REPORT_THREADS,
                    thread_name_prefix="report_send",
                )
    return _report_executor


def shutdown_report_executor():
    """Gracefully shut down the report thread pool."""
    global _report_executor
    if _report_executor is not None and not _report_executor._shutdown:
        _report_executor.shutdown(wait=True, cancel_futures=True)
        _report_executor = None


def _get_registry() -> HandlerRegistry:
    """Get or create the handler registry (singleton)."""
    global _registry
    if _registry is None:
        _registry = HandlerRegistry()
        # Register all handlers in order of priority (most specific first)
        # Handlers are checked in registration order; first match wins.
        _registry.register(WordPressHandler())
        _registry.register(PhpMyAdminHandler())
        _registry.register(JenkinsHandler())
        _registry.register(TomcatHandler())
        _registry.register(DrupalHandler())
        _registry.register(CPanelHandler())
        # Generic handler is last – catches everything else
        _registry.register(GenericHandler())
        logger.info(
            "HandlerRegistry initialized with %d handlers",
            len(_registry.get_all_handlers()),
        )
    return _registry


class HTTPHandler:
    """HTTP honeypot handler that routes requests to service-specific handlers.

    Unlike the server-side BaseHandler, this does NOT decrypt or parse JSON.
    It receives raw HTTP data, routes to the appropriate handler, generates
    a honeypot response, and spawns a process to send the report to the server.
    """

    def __init__(self, args, update_event):
        """Initialize the HTTP handler.

        Args:
            args: CLI arguments namespace
            update_event: Event to signal shutdown
        """
        self.args = args
        self.update_event = update_event
        # Initialize AI responder if enabled
        self._ai_enabled = getattr(args, "ai_responder", False)
        self._ai_responder = None
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

            ai_endpoint = getattr(args, "ai_endpoint", "")
            ai_model = getattr(args, "ai_model", "")
            ai_max_tokens = getattr(args, "ai_max_tokens", 0)

            if not ai_endpoint:
                ai_endpoint = os.environ.get(
                    "HONEY_AI_ENDPOINT", "http://127.0.0.1:8080/v1"
                )
            if not ai_model:
                ai_model = os.environ.get("HONEY_AI_MODEL", "llama-3.1-8b-instruct")
            if ai_max_tokens == 0:
                ai_max_tokens = int(os.environ.get("HONEY_AI_MAX_TOKENS", "500"))

            self._registry = ResponderRegistry()
            self._registry.register(PhpMyAdminResponder())
            self._registry.register(WordPressResponder())
            self._registry.register(WebDAVResponder())

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

        Detects protocol before parsing and handles non-HTTP probes
        (SSH, FTP, etc.) with appropriate responses and reports.

        Args:
            message: Raw HTTP request string from the bot.
            bot_ip: IP address of the connecting bot.

        Returns:
            The honeypot response data (HTTP response string or bytes).
        """
        # Detect protocol before attempting HTTP parsing
        raw_bytes = message.encode("utf-8") if isinstance(message, str) else message
        protocol = detect_protocol(raw_bytes)
        protocol_info = get_protocol_info(raw_bytes) if protocol else {}

        if protocol == "ssh":
            logger.info(
                "SSH probe detected from %s: %s",
                bot_ip,
                protocol_info.get("client", "unknown"),
            )
            return self._handle_ssh_probe(bot_ip, protocol_info)

        if protocol is not None and protocol != "http":
            logger.info("Non-HTTP protocol detected from %s: %s", bot_ip, protocol)
            return self._handle_non_http_probe(bot_ip, protocol, protocol_info)

        # Parse the raw HTTP request
        try:
            parsed = HTTPRequest(message)
            # If parsing failed (path is None), create a minimal valid request
            path_val = getattr(parsed, "path", None)
            if path_val is None:
                logger.debug(
                    "HTTPRequest failed to parse path, using fallback for %s", bot_ip
                )
                fallback = (
                    "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n"
                )
                parsed = HTTPRequest(fallback)
        except Exception as e:
            logger.debug(
                "Failed to parse HTTP request: %s, using fallback for %s", e, bot_ip
            )
            fallback = (
                "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Unknown\r\n\r\n"
            )
            parsed = HTTPRequest(fallback)

        # Build the data dict that process_request expects
        data = {
            "ip": bot_ip,
            "raw_request": message,
            "parsed_request": parsed,
        }

        return self.process_request(data)

    def _send_report(
        self, bot_ip: str, raw_request: str, parsed, detected: int, protocol: str = None
    ):
        """Send a report to the server for a bot interaction.

        Args:
            bot_ip: Bot IP address.
            raw_request: Raw request data.
            parsed: Parsed request object.
            detected: Detection ID.
            protocol: Detected protocol name (for non-HTTP).
        """
        from manyfaced.client.client import send_report

        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))
        server_host = getattr(self.args, "server_host", "127.0.0.1")
        server_port = getattr(self.args, "server", None)

        if server_port is None:
            return

        bs = BearStorage(
            bot_ip,
            raw_request,
            request_time,
            parsed,
            detected,
            settings.HIVELOGIN,
        )

        executor = _get_report_executor()
        executor.submit(
            send_report, bs, bot_ip, settings.HIVEPASS, server_host, server_port
        )

    def _handle_ssh_probe(self, bot_ip: str, protocol_info: dict) -> bytes:
        """Handle an SSH probe by responding with a fake SSH banner.

        Args:
            bot_ip: IP address of the connecting bot.
            protocol_info: Dict with SSH protocol details.

        Returns:
            Fake SSH banner response bytes.
        """
        # Extract client version if available
        client = protocol_info.get("client", "")
        version = protocol_info.get("version", "")

        # Generate a realistic-looking SSH banner with varying OpenSSH versions
        banner_versions = [
            "SSH-2.0-OpenSSH_9.6",
            "SSH-2.0-OpenSSH_8.9",
            "SSH-2.0-OpenSSH_7.9",
            "SSH-2.0-libssh2_1.10.0",
        ]
        banner = random.choice(banner_versions) + "\r\n"

        logger.debug("Sent SSH banner to %s (client=%s)", bot_ip, client)

        # Send report for SSH probe
        # Create a minimal parsed object for reporting
        class _ParsedSSH:
            command = "SSH"
            path = "/"
            headers = {}
            user_agent = client or "unknown"

        ssh_version = version or "SSH-2.0"
        _ParsedSSH.version = ssh_version

        self._send_report(
            bot_ip, banner_versions[0], _ParsedSSH(), SSH_CLIENT, protocol="ssh"
        )
        return banner.encode("utf-8")

    def _handle_non_http_probe(
        self, bot_ip: str, protocol: str, protocol_info: dict
    ) -> bytes:
        """Handle non-HTTP protocol probes.

        Args:
            bot_ip: IP address of the connecting bot.
            protocol: Detected protocol name.
            protocol_info: Dict with protocol details.

        Returns:
            Appropriate response bytes for the protocol.
        """
        detected_id = UNKNOWN_NON_HTTP
        response = None

        # FTP: respond with a fake FTP banner
        if protocol == "ftp":
            banners = [
                "220 (vsFTPd 3.0.3)\r\n",
                "220 Welcome to FTP service.\r\n",
                "220 ProFTPD 1.3.5 Server\r\n",
            ]
            response = random.choice(banners).encode("utf-8")
            detected_id = UNKNOWN_NON_HTTP

        # Telnet: send null bytes (common telnet probe response)
        elif protocol == "telnet":
            response = b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f"
            detected_id = UNKNOWN_NON_HTTP

        # RDP: send a negative response
        elif protocol == "rdp":
            response = b"\x03\x00\x00\x1f\x0e\xe0\x00\x00\x18\x00\x01\xc1\x00\x00\x00"
            detected_id = UNKNOWN_NON_HTTP

        # VNC: respond with version string
        elif protocol == "vnc":
            response = b"RFB 003.003\r\n"
            detected_id = UNKNOWN_NON_HTTP

        # SMTP/POP3/IMAP: send a fake greeting
        elif protocol in ("smtp", "pop3", "imap"):
            greetings = {
                "smtp": "220 manyfaced-honeypot ESMTP\r\n",
                "pop3": "+OK manyfaced-honeypot POP3 ready\r\n",
                "imap": "* OK manyfaced-honeypot IMAP4 ready\r\n",
            }
            response = greetings[protocol].encode("utf-8")
            detected_id = UNKNOWN_NON_HTTP

        else:
            # Unknown protocol: just close (empty response)
            response = b""

        if response:
            # Send report for non-HTTP probe
            class _ParsedNonHTTP:
                command = protocol.upper()
                path = "/"
                version = protocol_info.get("version", protocol)
                headers = {}
                user_agent = protocol_info.get("client", protocol)

            self._send_report(
                bot_ip,
                protocol_info.get("raw", ""),
                _ParsedNonHTTP(),
                detected_id,
                protocol=protocol,
            )

        return response

    def process_request(self, data):
        """Process an incoming HTTP request.

        Routes to the appropriate handler, generates response, and
        spawns a process to send the report to the server.

        Args:
            data: Dict with 'ip', 'raw_request', 'parsed_request'

        Returns:
            The honeypot response bytes.
        """
        from manyfaced.client.client import send_report

        bot_ip = data["ip"]
        raw_request = data["raw_request"]
        parsed = data["parsed_request"]
        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))

        logger.info("Incoming request from %s at %s", bot_ip, request_time)

        # Extract headers from parsed request
        headers = {}
        if hasattr(parsed, "headers") and parsed.headers:
            try:
                headers = dict(parsed.headers)
            except Exception:
                pass

        # Route through the handler registry
        handler = _get_registry()
        path = getattr(parsed, "path", "/")

        # Try handler registry first
        result = handler.generate_response(
            path=path,
            raw_request=raw_request,
            bot_ip=bot_ip,
            headers=headers,
        )

        if result is not None:
            output_data, detected = result
            logger.debug(
                "Handler registry returned response for %s (detected=%s)",
                bot_ip,
                detected,
            )

            # Record the full interaction in the dialogue for all matching handlers
            request_data = {
                "path": path,
                "method": self._extract_method(raw_request),
                "raw": raw_request,
                "headers": headers,
            }
            matching_handlers = handler.get_all_matching_handlers(path)
            for h in matching_handlers:
                profile = h.get_or_create_profile(bot_ip)
                profile.record_interaction(request_data, output_data, detected)
        else:
            # Fallback to AI responder if enabled
            if self._ai_responder and self._ai_responder.is_available():
                try:
                    response_bytes, detected = self._ai_responder.generate_response(
                        request_path=path,
                        raw_request=raw_request,
                        bot_ip=bot_ip,
                    )
                    output_data = response_bytes
                except Exception as e:
                    logger.warning("AI response failed for %s %s: %s", bot_ip, path, e)
                    output_data, detected = self._fallback_response(path), 1
            else:
                output_data, detected = self._fallback_response(path), 1

        logger.debug(
            "Generated response for %s, detected=%s, size=%d",
            bot_ip,
            detected,
            len(output_data),
        )

        # Create BearStorage for reporting
        logger.debug("Creating BearStorage for %s", bot_ip)
        bs = BearStorage(
            bot_ip,
            raw_request,
            request_time,
            parsed,
            detected,
            settings.HIVELOGIN,
        )
        logger.debug("BearStorage created for %s", bot_ip)

        # Determine server connection info for sending reports
        server_host = getattr(self.args, "server_host", "127.0.0.1")
        server_port = getattr(self.args, "server", None)

        if server_port is not None:
            # Use thread pool instead of spawning a subprocess per request.
            # This prevents process explosion: the old code spawned 1 Process
            # per bot request (200+ processes logged), causing file descriptor
            # exhaustion and crashes. ThreadPoolExecutor reuses threads.
            executor = _get_report_executor()
            executor.submit(
                send_report, bs, bot_ip, settings.HIVEPASS, server_host, server_port
            )
        else:
            logger.debug("No server port configured, skipping report for %s", bot_ip)

        return output_data

    @staticmethod
    def _extract_method(raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _fallback_response(self, path: str) -> bytes:
        """Fallback response for unmatched paths."""
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        body = f"""<!DOCTYPE html>
<html><head><title>Server</title></head>
<body><h1>Welcome to zlol's manyface!</h1>
<p>Server: Apache/2.4.57 (Ubuntu)</p>
<p>Path: {path}</p>
</body></html>"""
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: Apache/2.4.57 (Ubuntu)\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        return response.encode("iso-8859-1")
