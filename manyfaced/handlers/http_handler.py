import datetime
from multiprocessing import Process

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.settings import HIVELOGIN, HIVEPASS
from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.httphandler import HTTPRequest
from .base_handler import BaseHandler

logger = get_logger(__name__)


class HTTPHandler(BaseHandler):
    def __init__(self, args, update_event):
        super().__init__(args, update_event)

    def get_key(self, identifier):
        return HIVEPASS

    def process_request(self, data):
        """Import here to avoid circular dependency."""
        from manyfaced.client.client import get_honey_http, send_report

        bot_ip = data["ip"]
        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))

        logger.info("Incoming request from %s at %s", bot_ip, request_time)

        output_data, detected = get_honey_http(
            HTTPRequest(data["raw_request"]), bot_ip, self.args.verbose
        )

        bs = BearStorage(
            bot_ip,
            data["raw_request"],
            request_time,
            data["parsed_request"],
            detected,
            HIVELOGIN,
        )
        Process(
            args=(bs, HIVELOGIN, HIVEPASS),
            name="send_report",
            target=send_report,
        ).start()

        logger.debug("Spawned send_report process for %s", bot_ip)

        return output_data
