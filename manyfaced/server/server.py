import pickle
import os
import signal
from multiprocessing import Process, Lock
from requests.exceptions import ConnectionError
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as socket_error)

from common.myenc import AESCipher
from common.settings import AUTHORISEDBEARS
from common.utils import dump_file, receive_timeout
from db.dbconnect import Insert


def data_saving(data, args, lock):
    with lock:
        try:
            Insert(data)
        except ConnectionError:
            dump_file(data)
            if args.verbose:
                print "Error writing data to clickhouse, writing to file"
        except KeyboardInterrupt:
            pass
    os._exit(0)


def main(args, update_event):
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    db_lock = Lock()
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('', args.server))
    server_socket.listen(1)
    if args.verbose:
        print "Awaiting for bears on port %s" % args.server
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
            request = message.split(":")
            if len(request) is not 2:
                connection_socket.send("CODE 300 FUCK YOU")
                connection_socket.close()
                continue
            key = AUTHORISEDBEARS[request[0]]
            decipher = AESCipher(key)
            decrypted_message = decipher.decrypt(request[1])
            data = pickle.loads(decrypted_message)
            if args.verbose:
                print unicode(data).encode('utf-8')
            Process(
                args=(data, args, db_lock),
                name="data_saving",
                target=data_saving
            ).start()
            connection_socket.send("200")
        except socket_error, e:
            print e
            continue
        except TypeError, e:
            print e
            connection_socket.send("CODE 300 FUCK YOU")
        except KeyError, e:
            print e
            connection_socket.send("CODE 300 FUCK YOU")
        except ValueError, e:
            print e
            connection_socket.send("CODE 300 FUCK YOU")
        except ImportError, e:  # In case of wrong pickle class
            print e
            connection_socket.send("CODE 300 FUCK YOU")
        except e:
            print e
            connection_socket.send("CODE 300 FUCK YOU")
        finally:
            connection_socket.close()

    server_socket.close()
