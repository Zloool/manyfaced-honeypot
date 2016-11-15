import pickle
import time
import os
import signal
from multiprocessing import Process, Lock
from requests.exceptions import ConnectionError
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as sockerror)

from common.status import CLIENT_TIMEOUT
from common.myenc import AESCipher
from common.settings import AUTHORISEDBEARS
from db.dbconnect import Insert


def dump_file(data):
    try:
        with file('temp.db') as f:
            string_file = f.read()
        db = pickle.loads(string_file)
    except:
        db = list()
    db.append(data)
    with open('temp.db', "w") as f:
        f.write(str(pickle.dumps(db)))


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


def recv_timeout(the_socket, timeout=CLIENT_TIMEOUT):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = []

    # beginning time
    begin = time.time()
    while True:
        # if you got some data, then break after timeout
        if total_data and time.time() - begin > timeout:
            break

        # if you got no data at all, wait a little longer, twice the timeout
        elif time.time() - begin > timeout * 2:
            break

        # recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                # change the beginning time for measurement
                begin = time.time()
            else:
                # sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass

    # join all parts to make final string
    return ''.join(total_data)


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
            message = recv_timeout(connection_socket)
            request = message.split(":")
            if len(request) is not 2:
                connection_socket.send("CODE 300 FUCK YOU")
                connection_socket.close()
                continue
            key = AUTHORISEDBEARS[request[0]]
            decipher = AESCipher(key)
            data = pickle.loads(decipher.decrypt(request[1]))
            if args.verbose:
                print unicode(data).encode('utf-8')
            Process(
                args=(data, args, db_lock),
                name="data_saving",
                target=data_saving
            ).start()
            connection_socket.send("200")
        except sockerror, e:
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
        finally:
            connection_socket.close()

    server_socket.close()
