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


def data_saving(data, args, lock):
    with lock:
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
            if args.verbose:
                print(f"Error writing data to database: {e}, writing to file")
    return


def main(args, update_event):
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    db_lock = Lock()
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
            response = handle_client(args, db_lock, message)
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


def handle_client(args, db_lock, message):
    try:
        request = parse_message(message)
        decrypted = decrypt_message(request, args.verbose)
        data = parse_json(decrypted)
        
        response = process_request(data, args, db_lock)
        return "200" if response else ""
    except UnicodeDecodeError as e:
        print("Error decrypting data from client, check login data.")
        return "CODE 301 INCORRECT PASSWORD"
    except ValueError as e:
        print(f"Invalid message format: {e}")
        return f"CODE 304 WRONG MESSAGE FORMAT"


def parse_message(message):
    request = message.split(":", 1)
    if len(request) != 2:
        raise ValueError("Invalid message format")
    return request


def decrypt_message(request, verbose=False):
    key = AUTHORISEDBEARS[request[0]]
    decipher = AESCipher(key)
    return decipher.decrypt(request[1])


def parse_json(decrypted_data):
    try:
        data = json.loads(decrypted_data.decode('utf-8'))
        return data
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid JSON format: {e}")


def process_request(data, args, db_lock):
    # Store the request in database in separate process
    Process(
        args=(data, args, db_lock),
        name="data_saving",
        target=data_saving
    ).start()
    
    return True  # Success
