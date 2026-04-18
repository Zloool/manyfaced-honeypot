import json
import signal
from multiprocessing import Process, Lock
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    error as socket_error,
)

from manyfaced.common.settings import AUTHORISEDBEARS
from manyfaced.common.utils import dump_file, receive_timeout
from manyfaced.db.dbconnect import Insert, BearRequests
from manyfaced.handlers.base_handler import BaseHandler


class ServerHandler(BaseHandler):
    def __init__(self, args, update_event):
        super().__init__(args, update_event)

    def get_key(self, identifier):
        return AUTHORISEDBEARS.get(identifier)  # Use authorized bears for key

    def process_request(self, data):
        db_lock = Lock()
        Process(
            args=(data, self.args, db_lock), name="data_saving", target=self.save_data
        ).start()

        return True

    def save_data(self, data, args, db_lock):
        with db_lock:
            try:
                bear = BearRequests(
                    ip=data["ip"],
                    raw_request=data["raw_request"],
                    timestamp=data["timestamp"],
                    parsed_request=data["parsed_request"],
                    is_detected=data["is_detected"],
                    HIVELOGIN=data["HIVELOGIN"],
                )
                Insert(bear)
                if args.verbose:
                    print(f"Data saved for {data['ip']}")
            except (ConnectionError, TypeError) as e:
                dump_file(json.dumps(data))
                if self.args.verbose:
                    print(f"Error writing data to database: {e}, writing to file")
        return


def main(args, update_event):
    if getattr(signal, "SIGCHLD", None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(("", args.server))
    server_socket.listen(1)
    if args.verbose:
        print("Awaiting for bears on port %s" % args.server)
    while True:
        if update_event.is_set():
            break
        connection_socket: socket | None = None
        try:
            connection_socket, addr = server_socket.accept()
        except KeyboardInterrupt:
            break
        try:
            message = receive_timeout(connection_socket)
            handler = ServerHandler(args, update_event)
            response = handler.handle_request(message)
            if isinstance(response, bool):
                response = "200 OK"
            elif not isinstance(response, str):
                response = str(response)
            connection_socket.send(response.encode())
        except socket_error as e:
            if args.verbose:
                print(f"Socket error: {e}")
            continue
        except (ValueError, TypeError, KeyError, ImportError) as e:
            if connection_socket:
                connection_socket.send(f"CODE 300 ERROR: {e}".encode())
            if args.verbose:
                print(f"Unexpected error: {e}")
        finally:
            if connection_socket:
                connection_socket.close()

    server_socket.close()
