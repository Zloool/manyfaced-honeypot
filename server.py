import pickle
from threading import Thread
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


def DataSaving(data, args):
    try:
        Insert(data)
    except ConnectionError:
        DumpToFile(data)
        if args.verbose:
            print "Error writing data to clickhouse, writing to file"


def main(args, update_event):
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
            message = connectionSocket.recv(100000)
            request = message.split(":")
            if len(request) is not 2:
                connectionSocket.send("CODE 300 FUCK YOU")
                continue
            key = AUTHORISEDBEARS[request[0]]
            deciper = AESCipher(key)
            data = pickle.loads(deciper.decrypt(request[1]))
            if args.verbose:
                print data.encode('utf-8')
            Thread(
                args=(data, args),
                name="DataSaving",
                target=DataSaving
            ).start()
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
