"""Tests for manyfaced.common.logging_setup."""

import json
import logging
import logging.handlers
import os
import sys

from manyfaced.common.logging_setup import (
    ColouredFormatter,
    JsonFormatter,
    get_logger,
    setup_logging,
)


# ---------------------------------------------------------------------------
# ColouredFormatter tests
# ---------------------------------------------------------------------------


class TestColouredFormatter:
    """Tests for ColouredFormatter."""

    def _make_record(self, levelname: str, message: str = "test message") -> logging.LogRecord:
        """Create a LogRecord at the given level."""
        return logging.LogRecord(
            name="test",
            level=getattr(logging, levelname),
            pathname="test.py",
            lineno=1,
            msg=message,
            args=(),
            exc_info=None,
        )

    def test_debug_is_coloured(self):
        """DEBUG messages get cyan colour code."""
        formatter = ColouredFormatter()
        record = self._make_record("DEBUG")
        result = formatter.format(record)
        assert "\033[36m" in result  # cyan
        assert "\033[0m" in result  # reset
        assert "test message" in result

    def test_info_is_coloured(self):
        """INFO messages get green colour code."""
        formatter = ColouredFormatter()
        record = self._make_record("INFO")
        result = formatter.format(record)
        assert "\033[32m" in result  # green
        assert "\033[0m" in result

    def test_warning_is_coloured(self):
        """WARNING messages get yellow colour code."""
        formatter = ColouredFormatter()
        record = self._make_record("WARNING")
        result = formatter.format(record)
        assert "\033[33m" in result  # yellow
        assert "\033[0m" in result

    def test_error_is_coloured(self):
        """ERROR messages get red colour code."""
        formatter = ColouredFormatter()
        record = self._make_record("ERROR")
        result = formatter.format(record)
        assert "\033[31m" in result  # red
        assert "\033[0m" in result

    def test_critical_is_coloured(self):
        """CRITICAL messages get bold red colour code."""
        formatter = ColouredFormatter()
        record = self._make_record("CRITICAL")
        result = formatter.format(record)
        assert "\033[1;31m" in result  # bold red
        assert "\033[0m" in result

    def test_unknown_level_has_no_colour(self):
        """Levels not in _COLOURS get no colour codes."""
        formatter = ColouredFormatter()
        record = self._make_record("NOTSET")
        result = formatter.format(record)
        assert "\033[" not in result
        assert "test message" in result

    def test_format_method_includes_default_fields(self):
        """The format output contains the default log fields."""
        formatter = ColouredFormatter()
        record = self._make_record("INFO", "hello")
        result = formatter.format(record)
        # The default format includes levelname, name, processName, message
        assert "INFO" in result
        assert "hello" in result

    def test_format_with_custom_fmt(self):
        """Custom format string is respected."""
        fmt = "%(levelname)s: %(message)s"
        formatter = ColouredFormatter(fmt=fmt)
        record = self._make_record("WARNING", "warn msg")
        result = formatter.format(record)
        assert "WARNING" in result
        assert "warn msg" in result


# ---------------------------------------------------------------------------
# JsonFormatter tests
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    """Tests for JsonFormatter."""

    def _make_record(self, levelname: str, message: str = "test message") -> logging.LogRecord:
        return logging.LogRecord(
            name="my.logger",
            level=getattr(logging, levelname),
            pathname="test.py",
            lineno=1,
            msg=message,
            args=(),
            exc_info=None,
        )

    def test_json_output_contains_expected_keys(self):
        """Each JSON line contains the expected keys."""
        formatter = JsonFormatter()
        record = self._make_record("INFO", "hello world")
        result = formatter.format(record)
        data = json.loads(result)
        expected_keys = {"timestamp", "level", "logger", "process", "processName", "message"}
        assert expected_keys.issubset(data.keys())

    def test_json_level_correct(self):
        """The level field matches the record's levelname."""
        formatter = JsonFormatter()
        record = self._make_record("ERROR", "err")
        result = formatter.format(record)
        data = json.loads(result)
        assert data["level"] == "ERROR"

    def test_json_logger_name(self):
        """The logger field matches the record's name."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="custom.logger.name",
            level=logging.DEBUG,
            pathname="x.py",
            lineno=1,
            msg="msg",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        data = json.loads(result)
        assert data["logger"] == "custom.logger.name"

    def test_json_message(self):
        """The message field contains the formatted message."""
        formatter = JsonFormatter()
        record = self._make_record("DEBUG", "my message")
        result = formatter.format(record)
        data = json.loads(result)
        assert data["message"] == "my message"

    def test_json_with_exc_info(self):
        """exc_info is included in output when present."""
        formatter = JsonFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="x.py",
                lineno=1,
                msg="oops",
                args=(),
                exc_info=sys.exc_info(),
            )
        result = formatter.format(record)
        data = json.loads(result)
        assert "exc_info" in data
        assert "ValueError" in data["exc_info"]

    def test_json_without_exc_info(self):
        """exc_info is not present when there is no exception."""
        formatter = JsonFormatter()
        record = self._make_record("INFO", "no error")
        result = formatter.format(record)
        data = json.loads(result)
        assert "exc_info" not in data


# ---------------------------------------------------------------------------
# setup_logging tests
# ---------------------------------------------------------------------------


class TestSetupLogging:
    """Tests for setup_logging."""

    def _cleanup_root_logger(self):
        """Remove all handlers from the root logger."""
        root = logging.getLogger()
        root.handlers.clear()

    def test_creates_stream_handler(self, tmp_path):
        """setup_logging adds a StreamHandler to the root logger."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "test.log")
        setup_logging(level="DEBUG", log_file=log_file, enable_file=False)
        root = logging.getLogger()
        stream_handlers = [
            h for h in root.handlers if isinstance(h, logging.StreamHandler)
        ]
        assert len(stream_handlers) >= 1

    def test_creates_file_handler_when_enabled(self, tmp_path):
        """setup_logging adds a RotatingFileHandler when enable_file=True."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "sub" / "app.log")
        setup_logging(level="DEBUG", log_file=log_file, enable_file=True)
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert len(file_handlers) >= 1

    def test_sets_log_level(self, tmp_path):
        """The root logger level is set to the requested level."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "test.log")
        setup_logging(level="WARNING", log_file=log_file, enable_file=False)
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_file_is_created(self, tmp_path):
        """The log file is created on disk when enable_file=True."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "sub" / "app.log")
        setup_logging(level="INFO", log_file=log_file, enable_file=True)
        assert os.path.isfile(log_file)

    def test_disable_file_mode_no_file_handler(self, tmp_path):
        """When enable_file=False, no RotatingFileHandler is added."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "test.log")
        setup_logging(level="INFO", log_file=log_file, enable_file=False)
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert len(file_handlers) == 0

    def test_stream_handler_has_coloured_formatter(self, tmp_path):
        """The StreamHandler uses a ColouredFormatter."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "test.log")
        setup_logging(level="INFO", log_file=log_file, enable_file=False)
        root = logging.getLogger()
        stream_handlers = [
            h for h in root.handlers if isinstance(h, logging.StreamHandler)
        ]
        assert len(stream_handlers) >= 1
        formatter = stream_handlers[0].formatter
        assert isinstance(formatter, ColouredFormatter)

    def test_file_handler_has_json_formatter(self, tmp_path):
        """The RotatingFileHandler uses a JsonFormatter."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "sub" / "app.log")
        setup_logging(level="INFO", log_file=log_file, enable_file=True)
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert len(file_handlers) >= 1
        formatter = file_handlers[0].formatter
        assert isinstance(formatter, JsonFormatter)

    def test_log_directory_created(self, tmp_path):
        """Log directory is created if it does not exist."""
        self._cleanup_root_logger()
        log_file = str(tmp_path / "a" / "b" / "c" / "deep.log")
        setup_logging(level="INFO", log_file=log_file, enable_file=True)
        assert os.path.isdir(str(tmp_path / "a" / "b" / "c"))


# ---------------------------------------------------------------------------
# get_logger tests
# ---------------------------------------------------------------------------


class TestGetLogger:
    """Tests for get_logger."""

    def test_returns_logger_instance(self):
        """get_logger returns a logging.Logger instance."""
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)

    def test_logger_has_name(self):
        """The returned logger has the correct name."""
        logger = get_logger("my.custom.logger")
        assert logger.name == "my.custom.logger"

    def test_same_name_returns_same_logger(self):
        """Calling get_logger with the same name returns the same logger."""
        l1 = get_logger("shared.logger")
        l2 = get_logger("shared.logger")
        assert l1 is l2
