import datetime
import signal
from abc import ABC, abstractmethod
from multiprocessing import Process, Lock
from socket import error as socket_error

from manyfaced.common.myenc import AESCipher
from manyfaced.common.settings import HIVELOGIN, HIVEPASS
from manyfaced.common.status import BOT_TIMEOUT, UNKNOWN_HTTP
from manyfaced.common.utils import dump_file, receive_timeout
from manyfaced.common.handler import RequestHandler
from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.httphandler import HTTPRequest
from .base_handler import BaseHandler

class HTTPHandler(BaseHandler):
    def __init__(self, args, update_event):
        super().__init__(args, update_event)

    def get_key(self, identifier):
        return HIVEPASS
    
    def process_request(self, data):
        """Import here to avoid circular dependency."""
        from manyfaced.client.client import get_honey_http, send_report, honey_webdav, honey_robots, honey_generic
        bot_ip = data['ip']
        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))
        
        output_data, detected = get_honey_http(HTTPRequest(data['raw_request']), bot_ip, self.args.verbose)
        
        bs = BearStorage(bot_ip, data['raw_request'], request_time, data['parsed_request'], detected, HIVELOGIN)
        Process(
            args=(bs, HIVELOGIN, HIVEPASS, Lock()),
            name="send_report",
            target=send_report).start()
        
        return output_data
