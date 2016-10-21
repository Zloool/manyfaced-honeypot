import pickle
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

from arguments import parse
from myenc import AESCipher
from settings import HIVEPORT, AUTHORISEDBEARS


def main():
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('', HIVEPORT))
    serverSocket.listen(1)
    print "Awaiting for bears on port %s" % HIVEPORT
    while True:
        connectionSocket, addr = serverSocket.accept()
        try:
            message = connectionSocket.recv(30000)
            print message
            request = message.split(":")
            key = AUTHORISEDBEARS[request[0]]
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
