# AI Responder for Many-faced Honeypot

## Overview
Add an AI-powered responder that generates plausible, interactive HTTP responses to bot probes, designed to provoke deeper exploitation attempts. The AI connects to a local LLM instance (llama-cpp-python) and falls back to static responses if unavailable.

## Architecture

```
Bot Request
    ↓
HTTPHandler.process_request()
    ↓
get_honey_http() ────→ AI Responder (optional) ────→ Plausible response
    ↓ (or fallback)
Static faces dict lookup ────→ Pre-built response
```

## Tasks

### Task 1: Create AI Responder Module
- Create `manyfaced/common/ai_responder.py`
- Implement `AIResponder` class with:
  - `__init__(self, endpoint, model, persona_template, max_tokens=500, timeout=5)`
  - `generate_response(self, request_path, raw_request, bot_ip, known_face=None)` → returns (response_bytes, detected)
  - `is_available()` → bool (checks LLM connection)
  - Uses `llama-cpp-python` for local LLM inference
  - Graceful fallback to static responses on failure
- Define default persona template (vulnerable web server)
- Define response templates for common probe types

### Task 2: Add Config Fields for AI Responder
- Add to `Config` dataclass:
  - `AI_ENABLED: bool` (default False)
  - `AI_ENDPOINT: str` (default "http://127.0.0.1:8080/v1")
  - `AI_MODEL: str` (default "llama-3.1-8b-instruct")
  - `AI_MAX_TOKENS: int` (default 500)
  - `AI_TIMEOUT: float` (default 5.0)
- Add to `generate_config_file()`: AI section in TOML
- Add backward-compat aliases in module-level exports
- Add to settings.py re-exports

### Task 3: Add CLI Flags
- Add to `arguments.py`:
  - `--ai-responder` flag (enables AI responder)
  - `--ai-endpoint` flag (LLM endpoint URL)
  - `--ai-model` flag (LLM model name)
  - `--ai-max-tokens` flag (max response tokens)

### Task 4: Integrate AI Responder into HTTPHandler
- Modify `HTTPHandler.process_request()`:
  - Check if AI responder is enabled
  - If enabled, try AI responder first
  - On AI failure, fall back to static faces dict lookup
  - Log AI vs static response usage
- Modify `get_honey_http()` in client.py to accept optional AI responder

### Task 5: Write Tests
- Test `AIResponder` class initialization
- Test `is_available()` method
- Test fallback behavior when LLM is unavailable
- Test config loading with AI fields
- Test CLI argument parsing for AI flags
- Test integration with HTTPHandler

## Design Decisions

1. **Fallback-first approach**: AI is optional. If LLM is unavailable or times out, fall back to static responses.
2. **Thread-safe**: AI responder should be thread-safe for multi-port mode.
3. **Persona-driven**: The LLM is prompted to act as a vulnerable web server, generating realistic responses that encourage deeper probing.
4. **Rate-limited**: Configurable timeout to prevent hanging on slow LLM responses.
5. **No external dependencies unless installed**: llama-cpp-python is optional. If not installed, AI responder silently disables itself.

## Response Strategy

The AI responder will:
1. Analyze the bot's request path and content
2. Determine what kind of service the bot thinks it's talking to
3. Generate a plausible response that:
   - Matches the expected service type (WordPress, phpMyAdmin, etc.)
   - Contains subtle hints of vulnerability (debug info, error messages)
   - Encourages the bot to try deeper exploitation
   - Includes realistic server headers and status codes

Example persona prompt:
```
You are a vulnerable web server running an outdated CMS. A bot has just made an HTTP request.
Generate a realistic HTTP response that:
1. Matches the service type implied by the request path
2. Contains subtle vulnerability indicators (debug info, error traces, outdated software banners)
3. Encourages further probing
4. Is technically accurate for HTTP/1.1

Request path: {path}
Raw request: {raw_request}
```
