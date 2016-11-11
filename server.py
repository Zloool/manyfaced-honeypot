import pickle
import time
import os
from multiprocessing import Process, Lock
from requests.exceptions import ConnectionError
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as sockerror)

from settings import AUTHORISEDBEARS
from myenc import AESCipher
from dbconnect import Insert


def DumpToFile(data):
    try:
        with file('temp.db') as f:
            stringfile = f.read()
        db = pickle.loads(stringfile)
    except:
        db = list()
    db.append(data)
    with open('temp.db', "w") as f:
        f.write(str(pickle.dumps(db)))


def DataSaving(data, args, lock):
    with lock:
        try:
            Insert(data)
        except ConnectionError:
            DumpToFile(data)
            if args.verbose:
                print "Error writing data to clickhouse, writing to file"
        except KeyboardInterrupt:
            pass
    os._exit(0)


def recv_timeout(the_socket, timeout=2):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = []
    data = ''

    # beginning time
    begin = time.time()
    while 1:
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
    db_lock = Lock()
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('', args.server))
    serverSocket.listen(1)
    if args.verbose:
        print "Awaiting for bears on port %s" % args.server
    while True:
        if update_event.is_set():
            break
        try:
            connectionSocket, addr = serverSocket.accept()
        except KeyboardInterrupt:
            if 'connectionSocket' in locals():
                connectionSocket.close()
            break
        try:
            message = recv_timeout(connectionSocket)
            request = message.split(":")
            if len(request) is not 2:
                connectionSocket.send("CODE 300 FUCK YOU")
                connectionSocket.close()
                continue
            key = AUTHORISEDBEARS[request[0]]
            deciper = AESCipher(key)
            data = pickle.loads(deciper.decrypt(request[1]))
            if args.verbose:
                print unicode(data).encode('utf-8')
            ds = Process(
                args=(data, args, db_lock),
                name="DataSaving",
                target=DataSaving
            )
            ds.start()
            connectionSocket.send("200")
        except sockerror, e:
            print e
            continue
        except TypeError, e:
            print e
            connectionSocket.send("CODE 300 FUCK YOU")
        except KeyError, e:
            print e
            connectionSocket.send("CODE 300 FUCK YOU")
        except ValueError, e:
            print e
            connectionSocket.send("CODE 300 FUCK YOU")
        finally:
            connectionSocket.close()

    serverSocket.close()
