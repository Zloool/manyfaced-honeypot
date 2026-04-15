from common.myenc import AESCipher
from common.settings import HIVELOGIN, HIVEPASS
from common.status import BOT_TIMEOUT, UNKNOWN_HTTP
from common.utils import dump_file, receive_timeout
from manyfaced.common.handler import RequestHandler
from .base_handler import BaseHandler

class HTTPHandler(BaseHandler):
    def __init__(self, args, update_event):
        super().__init__(args, update_event)

    def get_key(self, identifier):
        return HIVEPASS  # Assuming we're using Hive login for key
    
    def process_request(self, data):
        bot_ip = data['ip']
        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))
        
        output_data, detected = get_honey_http(HTTPRequest(data['raw_request']), bot_ip, self.args.verbose)
        
        bs = BearStorage(bot_ip, data['raw_request'], request_time, data['parsed_request'], detected, HIVELOGIN)
        Process(
            args=(bs, HIVELOGIN, HIVEPASS, Lock()),
            name="send_report",
            target=send_report).start()
        
        return output_data
