import json
import signal
from multiprocessing import Process, Lock
from requests.exceptions import ConnectionError
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as socket_error)

from common.myenc import AESCipher
from common.settings import AUTHORISEDBEARS
from common.utils import dump_file, receive_timeout
from db.dbconnect import Insert, BearRequests
from manyfaced.common.handler import RequestHandler

class ServerHandler(RequestHandler):
    def __init__(self, args, update_event):
        super().__init__(args, update_event)

    def parse_message(self, message):
        request = message.split(":", 1)
        if len(request) != 2:
            raise ValueError("Invalid message format")
        return request

    def get_key(self, identifier):
        # Assuming identifier is the key for server
        return AUTHORISEDBEARS.get(identifier)

    def process_request(self, data):
        db_lock = Lock()
        Process(
            args=(data, self.args, db_lock),
            name="data_saving",
            target=self.save_data).start()
        
        return True  # Success

    def save_data(self, data):
        with db_lock:
            try:
                bear = BearRequests(
                    ip=data['ip'],
                    raw_request=data['raw_request'],
                    timestamp=data['timestamp'],
                    parsed_request=data['parsed_request'],
                    is_detected=data['is_detected'],
                    HIVELOGIN=data['HIVELOGIN']
                )
                Insert(bear)
            except ConnectionError as e:
                dump_file(json.dumps(data))
                if self.args.verbose:
                    print(f"Error writing data to database: {e}, writing to file")
        return


def main(args, update_event):
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('', args.server))
    server_socket.listen(1)
    if args.verbose:
        print("Awaiting for bears on port %s" % args.server)
    while True:
        if update_event.is_set():
            break
        try:
            connection_socket, addr = server_socket.accept()
        except KeyboardInterrupt:
            if 'connection_socket' in locals():
                connection_socket.close()
            break
        try:
            message = receive_timeout(connection_socket)
            response = ServerHandler(args, update_event).handle_request(message)
            connection_socket.send(response.encode())
        except socket_error as e:
            print(type(e))
            print(e.args)
            print(e)
            continue
        except (ValueError, TypeError, KeyError, ImportError) as e:
            print(f"Unexpected error: {e}")
            connection_socket.send(f"CODE 300 ERROR: {e}")
        finally:
            connection_socket.close()

    server_socket.close()
