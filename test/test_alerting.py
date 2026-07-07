"""Tests for manyfaced.common.alerting — credential capture notifications."""

import logging
from unittest.mock import MagicMock, patch


class TestNotifyCredentialCapture:
    """Test credential capture notification functionality."""

    def test_notify_credential_capture_logs_error(self, caplog):
        """Verify that notify_credential_capture logs at ERROR level."""
        from manyfaced.common.alerting import notify_credential_capture

        with caplog.at_level(logging.ERROR):
            notify_credential_capture(
                ip='1.2.3.4',
                credentials='admin:password123',
                path='/login',
                hostname='test-honeypot',
            )

        assert 'CREDENTIAL CAPTURE DETECTED' in caplog.text
        assert '1.2.3.4' in caplog.text
        assert 'admin:password123' in caplog.text

    def test_send_alert_logs_error(self, caplog):
        """Verify that send_alert logs at ERROR level."""
        from manyfaced.common.alerting import send_alert

        with caplog.at_level(logging.ERROR):
            send_alert('Test Alert', 'This is a test message')

        assert 'Test Alert' in caplog.text
        assert 'This is a test message' in caplog.text


class TestAlertConfig:
    """Test alert configuration loading."""

    def test_default_config_values(self):
        """Verify default configuration values are sensible."""
        from manyfaced.common.alerting import AlertConfig, _load_alert_config

        config = _load_alert_config()

        # Default values should be safe (no external notifications by default)
        assert config.LOG_ONLY is True
        assert config.ENABLED is False
        assert config.TELEGRAM_BOT_TOKEN == ''
        assert config.SMTP_HOST == 'localhost'
        assert config.SMTP_PORT == 587

    def test_config_handles_missing_values(self):
        """Verify configuration handles missing/empty values gracefully."""
        from manyfaced.common.alerting import AlertConfig, _load_alert_config

        # This should not raise any exceptions even with no config
        config = _load_alert_config()

        assert isinstance(config, AlertConfig)
        assert hasattr(config, 'TELEGRAM_BOT_TOKEN')
        assert hasattr(config, 'SMTP_HOST')
        assert hasattr(config, 'WEBHOOK_URL')


class TestSendFunctions:
    """Test individual notification send functions."""

    def test_send_telegram_message_failure(self):
        """Verify send_telegram_message returns False on failure."""
        from manyfaced.common.alerting import send_telegram_message

        result = send_telegram_message('invalid_token', '123456', 'Test message')
        assert result is False

    def test_send_email_alert_failure(self):
        """Verify send_email_alert returns False on failure."""
        from manyfaced.common.alerting import send_email_alert

        result = send_email_alert(
            smtp_host='invalid.host',
            smtp_port=587,
            smtp_user='',
            smtp_password='',
            from_email='',
            to_emails=(),
            subject='Test',
            body='Test message',
        )
        assert result is False

    def test_send_webhook_alert_failure(self):
        """Verify send_webhook_alert returns False on failure."""
        from manyfaced.common.alerting import send_webhook_alert

        result = send_webhook_alert('http://invalid.host/webhook', {'test': 'data'})
        assert result is False


class TestAlertConfigDataclass:
    """Test AlertConfig dataclass structure."""

    def test_dataclass_fields(self):
        """Verify AlertConfig has all expected fields."""
        from manyfaced.common.alerting import AlertConfig

        config = AlertConfig()

        # Check all required fields exist
        assert hasattr(config, 'TELEGRAM_BOT_TOKEN')
        assert hasattr(config, 'TELEGRAM_CHAT_ID')
        assert hasattr(config, 'SMTP_HOST')
        assert hasattr(config, 'SMTP_PORT')
        assert hasattr(config, 'SMTP_USER')
        assert hasattr(config, 'SMTP_PASSWORD')
        assert hasattr(config, 'FROM_EMAIL')
        assert hasattr(config, 'TO_EMAILS')
        assert hasattr(config, 'WEBHOOK_URL')
        assert hasattr(config, 'ENABLED')
        assert hasattr(config, 'LOG_ONLY')

    def test_dataclass_defaults(self):
        """Verify AlertConfig default values."""
        from manyfaced.common.alerting import AlertConfig

        config = AlertConfig()

        # String fields should be empty by default
        assert config.TELEGRAM_BOT_TOKEN == ''
        assert config.SMTP_HOST == 'localhost'
        assert config.FROM_EMAIL == ''
        assert config.WEBHOOK_URL == ''

        # Integer field should have sensible default
        assert config.SMTP_PORT == 587

        # Tuple field should be empty by default
        assert config.TO_EMAILS == ()

        # Boolean fields should default to safe values
        assert config.ENABLED is False
        assert config.LOG_ONLY is True


class TestAlertingFixes:
    """Regression tests for issues #172, #173, #174."""

    def test_env_vars_are_read(self, monkeypatch):
        """#172: HONEY_ALERT_* environment variables must be picked up."""
        import os

        monkeypatch.setenv('HONEY_ALERT_WEBHOOK_URL', 'https://example.test/hook')
        monkeypatch.setenv('HONEY_ALERT_TELEGRAM_BOT_TOKEN', 'tok123')
        monkeypatch.setenv('HONEY_ALERT_SMTP_HOST', 'smtp.example.test')
        # Ensure no TOML overrides it.
        monkeypatch.delenv('HONEY_ALERT_CONFIG', raising=False)

        from manyfaced.common.alerting import _load_alert_config

        cfg = _load_alert_config()
        assert cfg.WEBHOOK_URL == 'https://example.test/hook'
        assert cfg.TELEGRAM_BOT_TOKEN == 'tok123'
        assert cfg.SMTP_HOST == 'smtp.example.test'

    def test_alerting_section_read_from_config_toml(self, tmp_path, monkeypatch):
        """#215: the [alerting] section of the operator's config.toml is read
        end-to-end via Config.load() -> settings.ALERTING, not a phantom
        ALERT_CONFIG attribute. log_only=false and enabled=true must take effect.
        """
        from manyfaced.common import config

        cfg_path = tmp_path / 'config.toml'
        cfg_path.write_text(
            '[alerting]\n'
            'enabled = true\n'
            'log_only = false\n'
            'webhook_url = "https://example.test/hook"\n',
            encoding='utf-8',
        )
        # Build a REAL Config from this file (no secrets needed for alerting).
        real_cfg = config.Config.load(config_path=cfg_path, validate_secrets=False)
        assert real_cfg.ALERTING == {
            'enabled': True,
            'log_only': False,
            'webhook_url': 'https://example.test/hook',
        }
        # _load_alert_config must pick the section up from settings.ALERTING.
        monkeypatch.setattr(config, 'settings', real_cfg)
        monkeypatch.delenv('HONEY_ALERT_CONFIG', raising=False)

        from manyfaced.common.alerting import _load_alert_config

        cfg = _load_alert_config()
        assert cfg.LOG_ONLY is False
        assert cfg.ENABLED is True
        assert cfg.WEBHOOK_URL == 'https://example.test/hook'

    def test_log_only_false_from_toml(self, tmp_path, monkeypatch):
        """#173: log_only = false in config.toml must take effect (not coerce to true)."""
        from manyfaced.common import config

        cfg_path = tmp_path / 'config.toml'
        cfg_path.write_text('[alerting]\nenabled = true\nlog_only = false\n', encoding='utf-8')
        real_cfg = config.Config.load(config_path=cfg_path, validate_secrets=False)
        monkeypatch.setattr(config, 'settings', real_cfg)
        monkeypatch.delenv('HONEY_ALERT_CONFIG', raising=False)

        from manyfaced.common.alerting import _load_alert_config

        cfg = _load_alert_config()
        assert cfg.LOG_ONLY is False
        assert cfg.ENABLED is True

    def test_as_bool_coerces_toml_false(self):
        """#173: _as_bool must treat a TOML-parsed False as False (not fall back to default)."""
        from manyfaced.common.alerting import _as_bool

        assert _as_bool(False, True) is False
        assert _as_bool(True, False) is True
        assert _as_bool('false', True) is False
        assert _as_bool('true', False) is True
        assert _as_bool(None, True) is True

    def test_notify_dispatches_background_thread(self, caplog):
        """#174: notify_credential_capture must not block the caller; it dispatches to the pool."""
        import logging
        import threading
        import time

        from manyfaced.common import alerting
        from manyfaced.common.alerting import notify_credential_capture

        # Force external delivery path (not LOG_ONLY).
        with patch.object(
            alerting, 'alert_config', alerting.AlertConfig(LOG_ONLY=False, WEBHOOK_URL='https://x')
        ):
            with caplog.at_level(logging.ERROR):
                notify_credential_capture(ip='9.9.9.9', credentials='u:p', path='/x')
            # The caller returns immediately; delivery runs on a pool worker
            # (the executor may start the worker lazily, so allow a tick).
            import time

            for _ in range(50):
                threads = [t for t in threading.enumerate() if 'alert-delivery' in t.name]
                if threads:
                    break
                time.sleep(0.02)
            assert threads, 'expected an alert-delivery pool worker to be running'

    def test_alert_executor_is_bounded_and_drains_on_shutdown(self):
        """#216: submissions go to a bounded pool and shutdown drains in-flight tasks."""
        import threading

        from manyfaced.common import alerting

        alerting.shutdown_alert_executor()  # ensure a fresh pool
        try:
            started = threading.Event()
            finished = threading.Event()

            def _task():
                started.wait(5)
                finished.set()

            alerting.submit_alert(_task)
            # A worker thread exists (bounded pool, not unbounded per-alert threads).
            assert any('alert-delivery' in t.name for t in threading.enumerate())
            # Drain: shutdown(wait=True) must let the in-flight task finish.
            started.set()
            alerting.shutdown_alert_executor(wait=True)
            assert finished.wait(5), 'shutdown did not drain the in-flight alert task'
        finally:
            alerting.shutdown_alert_executor()


__all__ = [
    'TestNotifyCredentialCapture',
    'TestAlertConfig',
    'TestSendFunctions',
    'TestAlertConfigDataclass',
    'TestAlertingFixes',
]
