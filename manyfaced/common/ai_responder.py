"""
AI-powered responder for manyfaced honeypot.

Generates plausible, interactive HTTP responses to bot probes using a local LLM.
Designed to provoke deeper exploitation attempts by providing realistic,
vulnerable-looking responses that encourage further probing.

Usage:
    from manyfaced.common.ai_responder import AIResponder
    
    responder = AIResponder(
        endpoint="http://127.0.0.1:8080/v1",
        model="llama-3.1-8b-instruct",
    )
    
    if responder.is_available():
        response_bytes, detected = responder.generate_response(
            request_path="/wp-login.php",
            raw_request="GET /wp-login.php HTTP/1.1...",
            bot_ip="1.2.3.4",
        )
    else:
        # Fall back to static responses
        response_bytes, detected = get_honey_http(...)

Dependencies:
    llama-cpp-python (optional) – AI responder silently disables itself if not installed.
"""

from __future__ import annotations

import datetime
import json
import threading
from typing import Optional

from manyfaced.common.logging_setup import get_logger

logger = get_logger(__name__)

# ── Default persona template ──────────────────────────────────────────────────

DEFAULT_PERSONA_TEMPLATE = """\
You are a vulnerable web server running an outdated CMS or web application.
A bot has just made an HTTP request to your server.

Your goal is to generate a realistic HTTP response that:
1. Matches the service type implied by the request path
2. Contains subtle vulnerability indicators (debug info, error traces, outdated software banners)
3. Encourages further probing by leaving hints of additional attack surfaces
4. Is technically accurate for HTTP/1.1 with proper headers

Keep responses concise (under {max_tokens} tokens). Do NOT include any meta-commentary,
explanations, or markdown formatting. Return ONLY the raw HTTP response body.

Request path: {path}
Raw request: {raw_request}
Bot IP: {bot_ip}
Known face type: {face_type}
"""

# ── Response templates for common probe categories ────────────────────────────

RESPONSE_TEMPLATES = {
    "wordpress": {
        "description": "WordPress login/configuration probe",
        "persona_override": "You are running WordPress 4.2.0 with debug mode enabled. A bot from {bot_ip} requested {path}. Return a realistic WordPress error or login page with subtle vulnerability hints.",
    },
    "phpmyadmin": {
        "description": "phpMyAdmin probe",
        "persona_override": "You are running phpMyAdmin 4.0.10.2 with a known vulnerability. A bot from {bot_ip} requested {path}. Return a realistic phpMyAdmin error page with database connection hints.",
    },
    "webdav": {
        "description": "WebDAV probe",
        "persona_override": "You are running Apache with WebDAV enabled. A bot from {bot_ip} requested {path}. Return a realistic WebDAV directory listing with sensitive file hints.",
    },
    "generic": {
        "description": "Generic vulnerability scanner probe",
        "persona_override": "You are running an outdated web server with multiple vulnerabilities. A bot from {bot_ip} requested {path}. Return a realistic error page with server version hints and debug information.",
    },
}


class AIResponder:
    """AI-powered HTTP response generator for honeypot bot interaction.

    Connects to a local LLM instance (via llama-cpp-python) to generate
    realistic, interactive responses that encourage deeper exploitation.

    Integrates with the modular ResponderRegistry to delegate to domain-specific
    responders when available, falling back to direct LLM calls.

    Attributes:
        endpoint: LLM API endpoint URL
        model: LLM model name
        persona_template: Template string for the AI persona
        max_tokens: Maximum tokens in generated response
        timeout: Request timeout in seconds
        registry: Optional ResponderRegistry for modular response generation
        _llama: llama-cpp-python LLM instance (None if not available)
        _lock: Thread lock for thread safety
    """

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8080/v1",
        model: str = "llama-3.1-8b-instruct",
        persona_template: str | None = None,
        max_tokens: int = 500,
        timeout: float = 5.0,
        registry=None,
    ):
        """Initialize the AI responder.

        Args:
            endpoint: LLM API endpoint (OpenAI-compatible API)
            model: LLM model name
            persona_template: Custom persona template string
            max_tokens: Maximum tokens in generated response
            timeout: Request timeout in seconds
            registry: Optional ResponderRegistry for modular response generation
        """
        self.endpoint = endpoint
        self.model = model
        self.persona_template = persona_template or DEFAULT_PERSONA_TEMPLATE
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.registry = registry
        self._llama = None
        self._lock = threading.Lock()
        self._initialized = False
        self._available = False

        # Try to initialize llama-cpp-python
        self._try_init()

    def _try_init(self) -> None:
        """Try to initialize llama-cpp-python. Silently fails if not available."""
        try:
            from llama_cpp import Llama

            logger.info(
                "Initializing AI responder with model %s at %s", self.model, self.endpoint
            )
            # Note: We use the OpenAI-compatible endpoint, not local GGUF loading
            # This allows flexibility – the endpoint could be llama.cpp server,
            # Ollama, vLLM, or any OpenAI-compatible API
            self._initialized = True
            self._available = True
            logger.info("AI responder initialized successfully")
        except ImportError:
            logger.warning(
                "llama-cpp-python not installed – AI responder disabled. "
                "Install with: pip install llama-cpp-python"
            )
            self._initialized = False
            self._available = False
        except Exception as e:
            logger.warning("AI responder initialization failed: %s", e)
            self._initialized = False
            self._available = False

    def is_available(self) -> bool:
        """Check if the AI responder is available and connected.

        Returns:
            True if the LLM is reachable and ready to generate responses.
        """
        if not self._initialized:
            return False
        return self._available

    def _classify_request(self, request_path: str, raw_request: str) -> str:
        """Classify the request into a response category.

        Args:
            request_path: The URL path from the request
            raw_request: The full raw HTTP request

        Returns:
            Category string (wordpress, phpmyadmin, webdav, generic)
        """
        path_lower = request_path.lower()

        if any(kw in path_lower for kw in ["wp-login", "wp-admin", "wp-content", "wordpress"]):
            return "wordpress"
        if any(kw in path_lower for kw in ["phpmyadmin", "pma", "phpmy"]):
            return "phpmyadmin"
        if any(kw in path_lower for kw in ["webdav", "dav"]):
            return "webdav"
        return "generic"

    def _build_prompt(
        self,
        request_path: str,
        raw_request: str,
        bot_ip: str,
        face_type: str | None = None,
    ) -> str:
        """Build the AI prompt for response generation.

        Args:
            request_path: The URL path from the request
            raw_request: The full raw HTTP request
            bot_ip: The bot's IP address
            face_type: Known face type from static faces dict (or None)

        Returns:
            Formatted prompt string
        """
        category = self._classify_request(request_path, raw_request)
        template = self.persona_template

        # Use category-specific override if available
        if category in RESPONSE_TEMPLATES:
            template = RESPONSE_TEMPLATES[category]["persona_override"]

        return template.format(
            max_tokens=self.max_tokens,
            path=request_path,
            raw_request=raw_request[:2000],  # Truncate to avoid overly long prompts
            bot_ip=bot_ip,
            face_type=face_type or category,
        )

    def generate_response(
        self,
        request_path: str,
        raw_request: str,
        bot_ip: str,
        known_face: str | None = None,
        headers: dict | None = None,
    ) -> tuple[bytes, int]:
        """Generate an AI-powered HTTP response for a bot request.

        Delegates to the ResponderRegistry if available, falling back to
        direct LLM calls.

        Args:
            request_path: The URL path from the request
            raw_request: The full raw HTTP request string
            bot_ip: The bot's IP address
            known_face: Known face type from static faces dict (or None)
            headers: Request headers (or None)

        Returns:
            Tuple of (response_bytes, detected_flag)
            detected_flag: 1 if detected as known probe, UNKNOWN_HTTP if not

        Raises:
            RuntimeError: If AI responder is not available
        """
        if not self.is_available():
            raise RuntimeError("AI responder is not available")

        # Try registry first (modular responders)
        if self.registry:
            result = self.registry.generate_response(
                path=request_path,
                raw_request=raw_request,
                bot_ip=bot_ip,
                headers=headers,
            )
            if result is not None:
                return result

        # Fall back to direct LLM call
        prompt = self._build_prompt(request_path, raw_request, bot_ip, known_face)

        try:
            response_text = self._call_llm(prompt)
            # Build HTTP response from AI-generated text
            return self._build_http_response(response_text, known_face), 1
        except Exception as e:
            logger.error("AI response generation failed: %s", e)
            raise

    def _call_llm(self, prompt: str) -> str:
        """Call the LLM to generate a response.

        Args:
            prompt: The formatted prompt string

        Returns:
            Generated response text

        Raises:
            Exception: If the LLM call fails
        """
        # Use llama-cpp-python's OpenAI-compatible client
        try:
            from openai import OpenAI

            client = OpenAI(
                api_key="not-needed",  # Many local LLMs don't require auth
                base_url=self.endpoint,
                timeout=self.timeout,
            )

            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a vulnerable web server. Generate realistic HTTP responses.",
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=0.7,
                top_p=0.9,
            )

            return response.choices[0].message.content.strip()

        except ImportError:
            # openai package not installed, try llama_cpp directly
            return self._call_llama_cpp(prompt)
        except Exception as e:
            logger.error("LLM API call failed: %s", e)
            raise

    def _call_llama_cpp(self, prompt: str) -> str:
        """Fallback: call llama-cpp-python directly if openai package not available.

        Args:
            prompt: The formatted prompt string

        Returns:
            Generated response text

        Raises:
            RuntimeError: If llama-cpp-python is also unavailable
        """
        try:
            from llama_cpp import Llama

            llm = Llama(
                model_path=self.model,
                n_ctx=2048,
                n_threads=4,
                verbose=False,
            )

            output = llm.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a vulnerable web server. Generate realistic HTTP responses.",
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=0.7,
            )

            return output["choices"][0]["message"]["content"].strip()

        except Exception as e:
            logger.error("llama-cpp-python direct call failed: %s", e)
            raise

    def _build_http_response(self, response_text: str, known_face: str | None) -> bytes:
        """Build a complete HTTP response from AI-generated text.

        Args:
            response_text: AI-generated response body text
            known_face: Known face type (used to determine content type)

        Returns:
            Complete HTTP response as bytes
        """
        import datetime

        # Determine content type based on face type
        if known_face and known_face.endswith(".xml"):
            content_type = "application/xml; charset=utf-8"
        elif known_face and known_face in ("wpconfig.php",):
            content_type = "application/x-php"
        else:
            content_type = "text/html; charset=UTF-8"

        # Build HTTP response
        now = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        server_version = "Apache/2.4.41 (Ubuntu) PHP/7.4.3"

        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {server_version}\r\n"
            f"Date: {now}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Connection: close\r\n"
            f"X-Powered-By: PHP/7.4.3\r\n"
            f"\r\n"
            f"{response_text}"
        )

        return response.encode("iso-8859-1")

    def __repr__(self) -> str:
        return (
            f"AIResponder(endpoint={self.endpoint!r}, model={self.model!r}, "
            f"available={self._available})"
        )
