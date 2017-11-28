import os
import pickle
import signal
from base64 import b64encode
from multiprocessing import Lock, Process
from threading import Thread, Lock as TLock
from socket import error as socket_error
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket

from cryptography.fernet import Fernet
from requests.exceptions import ConnectionError

from manyfaced.common.settings import AUTHORISEDBEARS
from manyfaced.common.utils import dump_file, receive_timeout
from manyfaced.db.dbconnect import Insert


def data_saving(data, args, lock):
    with lock:
        try:
            Insert(data)
        except ConnectionError:
            dump_file(data)
            if args.verbose:
                print("Error writing data to clickhouse, writing to file")
        except KeyboardInterrupt:
            pass


def main(args, update_event):
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    if args.debug is not None:
        db_lock = TLock()
    else:
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
        except Exception as e:
            print(type(e))
            print(e.args)
            print(e)
            connection_socket.send("CODE 300 FUCK YOU".encode())
        finally:
            connection_socket.close()

    server_socket.close()


def handle_client(args, db_lock, message):
    try:
        request = message.split(":")
        if len(request) is not 2:
            return "CODE 304 WRONG MESSAGE FORMAT"
        key = AUTHORISEDBEARS[request[0]]
        decipher = Fernet(key)
        decrypted_message = decipher.decrypt(request[1].encode())
        data = pickle.loads(decrypted_message)
        if args.verbose:
            print(data)
        if args.debug is not None:
            run_style = Thread
        else:
            run_style = Process
        run_style(
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
        response = "CODE 302 TYPEERROR"
    except KeyError as e:
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 303 INCORRECT LOGIN"
    except ValueError as e:
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 300 FUCK YOU"
    except ImportError as e:  # In case of wrong pickle class
        print(type(e))
        print(e.args)
        print(e)
        response = "CODE 300 FUCK YOU"
    return response
