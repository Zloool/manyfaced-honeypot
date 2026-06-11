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


class TestIntegration:
    """Integration tests for alerting system."""

    def test_notify_credential_capture_integration(self):
        """Test full integration of credential capture notification."""
        from manyfaced.common.alerting import notify_credential_capture, alert_config

        # This should not raise any exceptions even with default config
        notify_credential_capture(
            ip='192.168.1.100',
            credentials='admin:secret123',
            path='/login',
            hostname='production-honeypot',
        )

        # Verify it completed without errors (logging is the only action with default config)


__all__ = [
    'TestNotifyCredentialCapture',
    'TestAlertConfig',
    'TestSendFunctions',
    'TestAlertConfigDataclass',
    'TestIntegration',
]
