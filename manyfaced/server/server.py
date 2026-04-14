import pickle
import json
import os
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
                parsed_request=json.dumps(data['parsed_request']),
                is_detected=data['is_detected'],
                HIVELOGIN=data['HIVELOGIN']
            )
            Insert(bear)
        except ConnectionError as e:
            dump_file(data)
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
            connection_socket.send(response)
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
        request = message.split(":", 1)
        if len(request) != 2:
            return "CODE 304 WRONG MESSAGE FORMAT"
        key = AUTHORISEDBEARS[request[0]]
        decipher = AESCipher(key)
        decrypted_message = decipher.decrypt(request[1])
        try:
            data = json.loads(decrypted_message.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"Invalid JSON format: {e}")
            return f"CODE 305 INVALID JSON: {e}"
        if args.verbose:
            print(json.dumps(data, indent=2))
        Process(
                args=(data, args, db_lock),
                name="data_saving",
                target=data_saving
        ).start()
        response = "200"
    except UnicodeDecodeError as e:
        print("Error decrypting data from client, check login data.")
        response = "CODE 301 INCORRECT PASSWORD"
    except TypeError as e:
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 302 INVALID DATA TYPE"
    except KeyError as e:
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 303 INCORRECT LOGIN"
    except ValueError as e:
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 300 INVALID DATA"
    except ImportError as e:  # In case of wrong pickle class
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 300 FUCK YOU"
    return response
