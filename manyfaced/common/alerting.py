"""Alerting/notification system for credential captures and other events.

Supports multiple notification channels:
- Telegram bot messages (via Bot API)
- Email (SMTP)
- Webhook (HTTP POST to arbitrary URL)

Configuration is loaded from config.toml [alerting] section or environment variables
with HONEY_ALERT_ prefix.

Usage:
    from manyfaced.common.alerting import notify_credential_capture, send_alert

    # Send credential capture alert
    notify_credential_capture(ip='1.2.3.4', credentials='admin:password123', path='/login')

    # Generic alert (for future use)
    send_alert('System warning', 'Disk space low on /dev/sda1')
"""

from __future__ import annotations

import json
import logging
import smtplib
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AlertConfig:
    """Alerting configuration loaded from config.toml or environment variables."""

    # Telegram settings
    TELEGRAM_BOT_TOKEN: str = ''
    TELEGRAM_CHAT_ID: str = ''

    # Email settings
    SMTP_HOST: str = 'localhost'
    SMTP_PORT: int = 587
    SMTP_USER: str = ''
    SMTP_PASSWORD: str = ''
    FROM_EMAIL: str = ''
    TO_EMAILS: tuple[str, ...] = ()

    # Webhook settings
    WEBHOOK_URL: str = ''

    # General
    ENABLED: bool = False
    LOG_ONLY: bool = True  # If True, only log alerts (no external notifications)


def _load_alert_config() -> AlertConfig:
    """Load alerting configuration from config.toml or environment variables."""
    try:
        from manyfaced.common.config import settings  # noqa: PLC0415

        toml_path = getattr(settings, 'ALERT_CONFIG', None)
        if toml_path:
            import tomllib  # noqa: PLC0415

            with open(toml_path, 'rb') as f:
                raw = tomllib.load(f)
            alerting = raw.get('alerting', {})
        else:
            alerting = {}
    except Exception:
        alerting = {}

    prefix = 'HONEY_ALERT_'

    def env(key: str, default: Any = '') -> str:
        return (
            settings.__dict__.get(f'{prefix}{key}', default)
            if hasattr(settings, f'{prefix}{key}')
            else ''
        )

    # Load from TOML first, then override with environment variables
    telegram_token = alerting.get('telegram_bot_token', env('TELEGRAM_BOT_TOKEN', '')) or ''
    telegram_chat_id = alerting.get('telegram_chat_id', env('TELEGRAM_CHAT_ID', '')) or ''
    smtp_host = alerting.get('smtp_host', env('SMTP_HOST', 'localhost')) or 'localhost'
    smtp_port_str = alerting.get('smtp_port', env('SMTP_PORT', '587')) or '587'
    try:
        smtp_port = int(smtp_port_str)
    except (ValueError, TypeError):
        smtp_port = 587
    smtp_user = alerting.get('smtp_user', env('SMTP_USER', '')) or ''
    smtp_password = alerting.get('smtp_password', env('SMTP_PASSWORD', '')) or ''
    from_email = alerting.get('from_email', env('FROM_EMAIL', '')) or ''
    to_emails_str = alerting.get('to_emails', env('TO_EMAILS', '')) or ''
    webhook_url = alerting.get('webhook_url', env('WEBHOOK_URL', '')) or ''

    enabled_str = alerting.get('enabled', env('ENABLED', 'false')) or 'false'
    log_only_str = alerting.get('log_only', env('LOG_ONLY', 'true')) or 'true'
    enabled = str(enabled_str).lower() in ('true', '1', 'yes')
    log_only = str(log_only_str).lower() in ('true', '1', 'yes')

    to_emails = (
        tuple(e.strip() for e in to_emails_str.split(',') if e.strip()) if to_emails_str else ()
    )

    return AlertConfig(
        TELEGRAM_BOT_TOKEN=telegram_token,
        TELEGRAM_CHAT_ID=telegram_chat_id,
        SMTP_HOST=smtp_host,
        SMTP_PORT=smtp_port,
        SMTP_USER=smtp_user,
        SMTP_PASSWORD=smtp_password,
        FROM_EMAIL=from_email,
        TO_EMAILS=to_emails,
        WEBHOOK_URL=webhook_url,
        ENABLED=enabled or not log_only,
        LOG_ONLY=log_only,
    )


# Global alert config instance (loaded once at module import)
alert_config: AlertConfig = _load_alert_config()


def send_telegram_message(token: str, chat_id: str, message: str) -> bool:
    """Send a message to Telegram via Bot API.

    Args:
        token: Telegram bot token.
        chat_id: Target chat/channel ID.
        message: Message text to send.

    Returns:
        True if message was sent successfully, False otherwise.
    """
    try:
        import urllib.request  # noqa: PLC0415

        url = f'https://api.telegram.org/bot{token}/sendMessage'
        payload = json.dumps(
            {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML',
            }
        ).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            return result.get('ok', False)

    except Exception as e:
        logger.error('Failed to send Telegram message: %s', e)
        return False


def send_email_alert(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_email: str,
    to_emails: tuple[str, ...],
    subject: str,
    body: str,
) -> bool:
    """Send an email alert via SMTP.

    Args:
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port.
        smtp_user: SMTP username.
        smtp_password: SMTP password.
        from_email: Sender email address.
        to_emails: Tuple of recipient email addresses.
        subject: Email subject line.
        body: Email body text.

    Returns:
        True if email was sent successfully, False otherwise.
    """
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = ', '.join(to_emails)

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_emails, msg.as_string())

        return True

    except Exception as e:
        logger.error('Failed to send email alert: %s', e)
        return False


def send_webhook_alert(url: str, payload: dict[str, Any]) -> bool:
    """Send an alert via HTTP POST webhook.

    Args:
        url: Webhook URL to POST to.
        payload: Dictionary of data to send as JSON.

    Returns:
        True if request was successful (2xx status), False otherwise.
    """
    try:
        import urllib.request  # noqa: PLC0415

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300

    except Exception as e:
        logger.error('Failed to send webhook alert: %s', e)
        return False


def notify_credential_capture(
    ip: str,
    credentials: str,
    path: str = '/',
    hostname: str = '',
) -> None:
    """Send notification when credentials are captured from a honeypot connection.

    This is the primary entry point for credential capture alerts. It logs at ERROR level
    and optionally sends notifications via configured channels (Telegram, email, webhook).

    Args:
        ip: IP address of the bot that submitted credentials.
        credentials: Captured credentials string (e.g., 'admin:password123').
        path: Request path where credentials were captured.
        hostname: Honeypot hostname/identifier that received the credentials.
    """
    # Always log at ERROR level for visibility in logs
    alert_message = (
        f'⚠️ CREDENTIAL CAPTURE DETECTED\n'
        f'IP: {ip}\n'
        f'Credentials: {credentials}\n'
        f'Path: {path}\n'
        f'Honeypot: {hostname or "unknown"}\n'
        f'Timestamp: {__import__("datetime").datetime.now().isoformat()}'
    )

    logger.error(alert_message)

    # If only logging, don't send external notifications
    if alert_config.LOG_ONLY:
        return

    # Send Telegram notification if configured
    if alert_config.TELEGRAM_BOT_TOKEN and alert_config.TELEGRAM_CHAT_ID:
        telegram_msg = (
            f'<b>⚠️ CREDENTIAL CAPTURE</b>\n'
            f'<b>IP:</b> <code>{ip}</code>\n'
            f'<b>Credentials:</b> <code>{credentials}</code>\n'
            f'<b>Path:</b> {path}\n'
            f'<b>Honeypot:</b> {hostname or "unknown"}\n'
            f'<b>Time:</b> {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        )
        send_telegram_message(
            alert_config.TELEGRAM_BOT_TOKEN,
            alert_config.TELEGRAM_CHAT_ID,
            telegram_msg,
        )

    # Send email notification if configured
    if alert_config.FROM_EMAIL and alert_config.TO_EMAILS:
        subject = f'[Honeypot Alert] Credential capture from {ip}'
        body = (
            f'CREDENTIAL CAPTURE DETECTED\n'
            f'=========================\n\n'
            f'IP Address: {ip}\n'
            f'Credentials: {credentials}\n'
            f'Request Path: {path}\n'
            f'Honeypot Hostname: {hostname or "unknown"}\n'
            f'Timestamp: {__import__("datetime").datetime.now().isoformat()}'
        )
        send_email_alert(
            alert_config.SMTP_HOST,
            alert_config.SMTP_PORT,
            alert_config.SMTP_USER,
            alert_config.SMTP_PASSWORD,
            alert_config.FROM_EMAIL,
            alert_config.TO_EMAILS,
            subject,
            body,
        )

    # Send webhook notification if configured
    if alert_config.WEBHOOK_URL:
        payload = {
            'event': 'credential_capture',
            'ip': ip,
            'credentials': credentials,
            'path': path,
            'hostname': hostname or '',
            'timestamp': __import__('datetime').datetime.now().isoformat(),
        }
        send_webhook_alert(alert_config.WEBHOOK_URL, payload)


def send_alert(title: str, message: str) -> None:
    """Send a generic alert via configured channels.

    This is a general-purpose alert function for future use (e.g., system warnings,
    database errors, etc.). Currently only logs at ERROR level unless external
    notification channels are configured.

    Args:
        title: Alert title/summary.
        message: Detailed alert message.
    """
    alert_text = f'⚠️ {title}\n{message}'
    logger.error(alert_text)

    if alert_config.LOG_ONLY:
        return

    # Send via all configured channels
    if alert_config.TELEGRAM_BOT_TOKEN and alert_config.TELEGRAM_CHAT_ID:
        send_telegram_message(
            alert_config.TELEGRAM_BOT_TOKEN,
            alert_config.TELEGRAM_CHAT_ID,
            f'<b>{title}</b>\n{message}',
        )

    if alert_config.FROM_EMAIL and alert_config.TO_EMAILS:
        send_email_alert(
            alert_config.SMTP_HOST,
            alert_config.SMTP_PORT,
            alert_config.SMTP_USER,
            alert_config.SMTP_PASSWORD,
            alert_config.FROM_EMAIL,
            alert_config.TO_EMAILS,
            f'[Honeypot] {title}',
            message,
        )

    if alert_config.WEBHOOK_URL:
        send_webhook_alert(
            alert_config.WEBHOOK_URL,
            {'event': 'alert', 'title': title, 'message': message},
        )


__all__ = [
    'AlertConfig',
    'alert_config',
    'notify_credential_capture',
    'send_alert',
]
