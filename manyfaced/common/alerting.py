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
import os
import smtplib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Any, Callable

from manyfaced.common.metrics import incr

logger = logging.getLogger(__name__)

# Bounded executor for off-request-thread alert delivery (#216). Caps concurrent
# delivery threads so a burst of credential captures can't spawn unbounded OS
# threads; excess alerts queue and are drained by the fixed worker pool.
_ALERT_MAX_WORKERS = 8
_alert_executor: ThreadPoolExecutor | None = None


def _get_alert_executor() -> ThreadPoolExecutor:
    """Lazily create the shared alert-delivery executor (module-level singleton)."""
    global _alert_executor
    if _alert_executor is None or _alert_executor._shutdown:  # noqa: SLF001
        _alert_executor = ThreadPoolExecutor(
            max_workers=_ALERT_MAX_WORKERS, thread_name_prefix='alert-delivery'
        )
    return _alert_executor


def submit_alert(task: Callable[[], None]) -> None:
    """Submit an alert-delivery task to the bounded pool.

    Falls back to running inline (best-effort) if the pool is shut down, so a
    late delivery during shutdown is still attempted rather than silently
    dropped.
    """
    try:
        _get_alert_executor().submit(task)
    except Exception:  # pragma: no cover - defensive; never block the caller
        logger.warning('Alert executor unavailable; delivering inline')
        try:
            task()
        except Exception:  # noqa: BLE001
            # Inline delivery also failed — give up on this alert; do not block
            # the calling code path (alerting must never raise into producers).
            pass


def shutdown_alert_executor(wait: bool = True) -> None:
    """Drain and shut down the alert-delivery executor (call on shutdown).

    With ``wait=True`` (default) any in-flight alert deliveries are allowed to
    finish before returning, so a credential capture that happened just before
    a restart isn't silently killed mid-send (#216). Safe to call multiple times.
    """
    global _alert_executor
    exc = _alert_executor
    _alert_executor = None
    if exc is not None and not exc._shutdown:  # noqa: SLF001
        exc.shutdown(wait=wait, cancel_futures=False)


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


def _as_bool(value: Any, default: bool) -> bool:
    """Coerce a TOML bool or env-string value to a bool.

    Handles the case where TOML parses ``log_only = false`` to the Python value
    ``False`` (which a naive ``value or 'true'`` would wrongly treat as
    "falsy -> default true").
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ('true', '1', 'yes', 'on')


def _load_alert_config() -> AlertConfig:
    """Load alerting configuration from config.toml or environment variables.

    TOML precedence (both are merged, env vars still override individual keys
    below): first the ``[alerting]`` section of the main config.toml (now
    exposed as ``settings.ALERTING`` — issue #215), then an explicit
    ``ALERT_CONFIG`` file path / ``HONEY_ALERT_CONFIG`` env var if set.
    """
    alerting: dict[str, Any] = {}
    try:
        from manyfaced.common.config import settings  # noqa: PLC0415

        # Primary: the [alerting] section of the operator's config.toml.
        alerting = dict(getattr(settings, 'ALERTING', {}) or {})
        # Backward-compat: a standalone ALERT_CONFIG TOML file (file path or
        # HONEY_ALERT_CONFIG env var) overrides/extends the section above.
        alert_config_path = os.environ.get('HONEY_ALERT_CONFIG') or getattr(
            settings, 'ALERT_CONFIG', None
        )
        if alert_config_path:
            import tomllib  # noqa: PLC0415

            with open(alert_config_path, 'rb') as f:
                raw = tomllib.load(f)
            alerting.update(raw.get('alerting', {}))
    except Exception:
        alerting = {}

    prefix = 'HONEY_ALERT_'

    def env(key: str, default: str = '') -> str:
        # Read real process environment variables (the documented HONEY_ALERT_*
        # config path). Previously this consulted settings.__dict__, which never
        # carries these keys, so every lookup fell through to '' and silently
        # discarded the caller's default too.
        return os.environ.get(f'{prefix}{key}', default)

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

    enabled = _as_bool(alerting.get('enabled', env('ENABLED', 'false')), False)
    log_only = _as_bool(alerting.get('log_only', env('LOG_ONLY', 'true')), True)

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


def _deliver_credential_capture(
    ip: str,
    credentials: str,
    path: str,
    hostname: str,
) -> None:
    """Deliver credential-capture alerts via configured external channels.

    Runs on a daemon background thread so the request-handling path that calls
    ``notify_credential_capture`` is never blocked by a slow/unreachable
    Telegram/SMTP/webhook endpoint (each has a 10s timeout; sequential delivery
    could otherwise stall the request thread for ~30s — see issue #174).
    """
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


def notify_credential_capture(
    ip: str,
    credentials: str,
    path: str = '/',
    hostname: str = '',
) -> None:
    """Send notification when credentials are captured from a honeypot connection.

    This is the primary entry point for credential capture alerts. It logs at ERROR level
    and optionally sends notifications via configured channels (Telegram, email, webhook).

    The ERROR-level log is written synchronously (cheap); external delivery is dispatched
    to a daemon background thread so a slow/unreachable channel cannot stall the request
    thread that reported the capture (issue #174).

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

    # Observability: count every credential capture (issue #166). This is the
    # signal source the #125 alerting can fire on.
    incr('credential_captures')

    # If only logging, don't send external notifications
    if alert_config.LOG_ONLY:
        return

    # Dispatch external notifications off the request thread via the bounded
    # pool (issue #174 off-thread; #216 bounded + drainable on shutdown).
    submit_alert(lambda: _deliver_credential_capture(ip, credentials, path, hostname))


def _deliver_alert(title: str, message: str) -> None:
    """Deliver a generic alert via configured channels (background worker)."""
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


def send_alert(title: str, message: str) -> None:
    """Send a generic alert via configured channels.

    This is a general-purpose alert function for future use (e.g., system warnings,
    database errors, etc.). Currently only logs at ERROR level unless external
    notification channels are configured.

    External delivery is dispatched to a daemon background thread so it cannot
    block the caller (issue #174).

    Args:
        title: Alert title/summary.
        message: Detailed alert message.
    """
    alert_text = f'⚠️ {title}\n{message}'
    logger.error(alert_text)

    if alert_config.LOG_ONLY:
        return

    # Dispatch off the request thread via the bounded pool (issue #174 off-thread;
    # #216 bounded + drainable on shutdown).
    submit_alert(lambda: _deliver_alert(title, message))


__all__ = [
    'AlertConfig',
    'alert_config',
    'notify_credential_capture',
    'send_alert',
]
