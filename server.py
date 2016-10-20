import pickle
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

from arguments import parse
from myenc import AESCipher
from settings import HIVEPORT


authorised_probes = {'CHORDCOLLISION': 'test', 'WINTERKAREN': ''}


def main():
    global authorised_probes
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('', HIVEPORT))
    serverSocket.listen(1)
    print "Awaiting for bears on port %s" % HIVEPORT
    while True:
        connectionSocket, addr = serverSocket.accept()
        # try:
        if True:
            message = connectionSocket.recv(30000)
            request = message.split(":")
            key = authorised_probes[request[0]]
            print key
            deciper = AESCipher(key)
            data = pickle.loads(deciper.decrypt(request[1]))
            print data
            connectionSocket.send("200")
            connectionSocket.close()
        except:
            connectionSocket.send("300")
            connectionSocket.close()
    serverSocket.close()

if __name__ == '__main__':
    args = parse()
    main()
