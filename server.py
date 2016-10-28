import pickle
import os
from shutil import copyfile
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

if not os.path.isfile("settings.py"):
    copyfile("settings.py.example", "settings.py")
from settings import HIVEPORT, AUTHORISEDBEARS
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


def main(args, update_event):
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('', HIVEPORT))
    serverSocket.listen(1)
    if args.verbose:
        print "Awaiting for bears on port %s" % HIVEPORT
    while True:
        if update_event.is_set():
            break
        connectionSocket, addr = serverSocket.accept()
        try:
            message = connectionSocket.recv(30000)
            request = message.split(":")
            key = AUTHORISEDBEARS[request[0]]
            deciper = AESCipher(key)
            data = pickle.loads(deciper.decrypt(request[1]))
            if args.verbose:
                print data
            try:
                Insert(data)
            except:
                DumpToFile(data)
                if args.verbose:
                    print "Error writing data to clickhouse, writing to file"
            connectionSocket.send("200")
            connectionSocket.close()
        except:
            try:
                connectionSocket.send("CODE 300 FUCK YOU")
            finally:
                connectionSocket.close()
    serverSocket.close()
