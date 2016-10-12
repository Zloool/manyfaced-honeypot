import os
import datetime
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from cases import cases
from httphandler import HTTPRequest
from settings import HONEYPORT, HONEYFOLDER
# TODO unittests


# import signal
# exit -- something to do on SIGINT
# signal.signal(signal.SIGINT, exit)
# TODO implement SIGINT handler

def create_file(message, directory):
    if not os.path.exists(HONEYFOLDER+directory):
        os.makedirs(HONEYFOLDER+directory)
    currtime = str(datetime.datetime.now()).replace(':', ';')
    filename = HONEYFOLDER+directory+"/"+currtime
    f = open(filename, 'w')
    f.write(str(message))
    f.close()


def get_honey(path):
    try:
        respfilename = cases[path]
        # TODO check, if cases[path] exists, instead of throwing an exc
        # TODO implement if system for complex requests respfilename == ""
        f = open('responses/'+respfilename)
        print ip_addr + " " + path + " gotcha!"
        # TODO turn off verbose by args
    except:
        respfilename = cases["zero"]
        f = open('responses/'+respfilename)
        print ip_addr + " " + path + " not detected..."
        # TODO add to souces, if not detected
    outputdata = f.read()
    f.close()
    return outputdata

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', HONEYPORT))
# TODO args
serverSocket.listen(1)
print "Serving honey on port %s" % HONEYPORT
while True:
    connectionSocket, addr = serverSocket.accept()
    try:
        message = connectionSocket.recv(30*1024)
        ip_addr = connectionSocket.getpeername()[0]
        create_file(message, ip_addr)
        path = ""
        try:
            request = HTTPRequest(message)
            path = request.path
            # TODO check error_code, instead of exc
        except:
            path = str(request.error_code)
        outputdata = get_honey(path)

        connectionSocket.send('HTTP/1.0 200 OK\r\n\r\n')
        # TODO add server banner

        connectionSocket.send(outputdata)
        connectionSocket.close()
    except IOError:
        # TODO test and remove this branch
        print "Caught exception IOError"
        # connectionSocket.send('HTTP/1.0 200 OK\r\n\r\n')
        connectionSocket.close()
    except socket.error, exc:
        print "Caught exception socket.error : %s" % exc
        connectionSocket.close()
serverSocket.close()  # This line is never achieved, implement in SIGINT?
