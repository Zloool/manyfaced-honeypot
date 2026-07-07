"""Report sender – encrypts and transmits bot reports to the honeypot server.

Extracted from client.py to reduce module size and cyclomatic complexity.
"""

import json
import time
from socket import AF_INET, SOCK_STREAM, error as socket_error, socket

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.metrics import incr
from manyfaced.common.myenc import AESCipher
from manyfaced.common.utils import dump_file

logger = get_logger(__name__)

REPORT_SEND_MAX_RETRIES = 5
REPORT_SEND_RETRY_DELAY = 2  # seconds
REPORT_SEND_BACKOFF_FACTOR = 2  # exponential backoff


def send_report(data, client, password, server_host, server_port, sensor_id=None):
    """Send a bot report to the server as an encrypted TCP message.

    Args:
        data: BearStorage instance with bot data.
        client: Bot IP address (used for logging and data dict).
        password: AES encryption password (HIVEPASS).
        server_host: Server hostname.
        server_port: Server port number.
        sensor_id: Sensor identifier sent as message prefix to the server.
                   If None, falls back to client IP (legacy behavior).
    """
    cypher = AESCipher(password)
    parsed = data.parsed_request if hasattr(data, 'parsed_request') else None

    # Extract user-agent from headers (case-insensitive lookup on HTTPMessage)
    ua = ''
    if hasattr(data, 'ua'):
        ua = data.ua or ''
    elif parsed is not None and hasattr(parsed, 'headers') and parsed.headers:
        ua = (
            getattr(parsed, 'user_agent', '')
            or parsed.headers.get('User-Agent', '')
            or parsed.headers.get('user-agent', '')
        )

    data_dict = {
        'ip': data.ip,
        'raw_request': data.raw_request,
        'timestamp': data.timestamp,
        'parsed_request': {
            'command': getattr(data, 'command', ''),
            'path': getattr(data, 'path', ''),
            'request_version': getattr(data, 'version', ''),
            'headers': dict(data.headers)
            if hasattr(data, 'headers') and isinstance(data.headers, dict)
            else {},
        },
        'is_detected': data.isDetected if hasattr(data, 'isDetected') else data.is_detected,
        'HIVELOGIN': data.hostname,
        # Additional fields for better data quality
        'ua': ua,
        'dns_name': getattr(data, 'dns_name', '') or '',
        'country': getattr(data, 'country', '') or '',
        'continent': getattr(data, 'continent', '') or '',
        'login': getattr(data, 'login', '') or '',  # Captured credentials (user:pass or user only)
    }

    # Bot profile data — accumulated state (escalation, dialogue, history) for this IP
    if hasattr(data, 'bot_profile_data') and data.bot_profile_data:
        data_dict['bot_profile_data'] = data.bot_profile_data
    identifier = sensor_id if sensor_id else client
    message = (identifier + ':').encode()
    message += cypher.encrypt(json.dumps(data_dict).encode()).encode()

    # Retry with exponential backoff to handle server restarts
    delay = REPORT_SEND_RETRY_DELAY
    for attempt in range(1, REPORT_SEND_MAX_RETRIES + 1):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(10)  # don't hang forever on connect
        try:
            s.connect((server_host, server_port))
            s.sendall(message)
            response = s.recv(1024)
            if not response.decode().startswith('200'):
                logger.warning(
                    'Failed to send report: Non-200 response from server (attempt %d/%d)',
                    attempt,
                    REPORT_SEND_MAX_RETRIES,
                )
                print(response)
            s.close()
            logger.info('Report sent for %s', client)
            incr('report_send_success')
            return  # success – stop retrying
        except socket_error:
            s.close()
            if attempt < REPORT_SEND_MAX_RETRIES:
                logger.debug(
                    'Report send failed for %s (attempt %d/%d), retrying in %ds',
                    client,
                    attempt,
                    REPORT_SEND_MAX_RETRIES,
                    delay,
                )
                time.sleep(delay)
                delay *= REPORT_SEND_BACKOFF_FACTOR
            else:
                logger.error(
                    'Socket error sending report for %s after %d attempts – dumping to file',
                    client,
                    REPORT_SEND_MAX_RETRIES,
                )
                incr('report_send_failure')
                dump_file(data)
        except KeyboardInterrupt:
            s.close()
            raise
