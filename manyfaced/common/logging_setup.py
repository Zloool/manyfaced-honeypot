"""System-wide logging configuration for manyfaced.

Initialises a structured logging pipeline with:
  - A ``StreamHandler`` (stderr) at the configured log level.
  - A ``FileHandler`` (rotating, configurable path) for persistent logs.
  - A JSON-style formatter for file output, plain-text for stderr.

Call ``setup_logging()`` early in the application lifecycle (e.g. in
``manyfaced.mfh.run()``) to install the root logger.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FILE = os.environ.get(
    "HONEY_LOG_FILE",
    os.path.join(
        os.path.expanduser("~"), ".local", "share", "manyfaced", "honeypot.log"
    ),
)
DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_LOG_BACKUP_COUNT = 5
DEFAULT_LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(processName)s | %(message)s"
)
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------------------------
# Formatter classes
# ---------------------------------------------------------------------------


class ColouredFormatter(logging.Formatter):
    """Stderr formatter with ANSI colour codes for readability."""

    _COLOURS = {
        "DEBUG": "\033[36m",  # cyan
        "INFO": "\033[32m",  # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",  # red
        "CRITICAL": "\033[1;31m",  # bold red
    }
    _RESET = "\033[0m"

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt or DEFAULT_LOG_FORMAT, datefmt or DEFAULT_DATE_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        colour = self._COLOURS.get(record.levelname, "")
        if colour:
            return f"{colour}{msg}{self._RESET}"
        return msg


class JsonFormatter(logging.Formatter):
    """File formatter that emits one JSON object per log line."""

    def __init__(self) -> None:
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        extra: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "process": record.process,
            "processName": record.processName,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            extra["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(extra, default=str)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_logging(
    level: str = DEFAULT_LOG_LEVEL,
    log_file: str | None = None,
    enable_file: bool = True,
) -> None:
    """Configure the root logger for the application.

    Parameters
    ----------
    level : str
        Logging level string (e.g. ``"DEBUG"``, ``"INFO"``).
    log_file : str or None
        Path to the log file. Falls back to ``DEFAULT_LOG_FILE``.
    enable_file : bool
        If ``False``, only the stderr handler is added.
    """
    log_file = log_file or DEFAULT_LOG_FILE

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # -- stderr handler (coloured, human-readable) --------------------------
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(root.level)
    stream.setFormatter(ColouredFormatter())
    root.addHandler(stream)

    # -- file handler (JSON, rotating) --------------------------------------
    if enable_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=DEFAULT_LOG_MAX_BYTES,
            backupCount=DEFAULT_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(root.level)
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger.

    Convenience wrapper that mirrors ``logging.getLogger`` but ensures
    the caller's module name is used.
    """
    return logging.getLogger(name)


__all__ = ["setup_logging", "get_logger"]
