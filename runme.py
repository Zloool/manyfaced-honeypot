import os
import sys
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
    outputdata = ""
    stringfile = ""
    msgsize = 0
    try:
        respfilename = cases[path]
        # TODO check, if cases[path] exists, instead of throwing an exc
        # TODO implement if system for complex requests respfilename == ""
        f = open('responses/'+respfilename)
        stringfile = f.read()
        f.close()
        msgsize = sys.getsizeof(stringfile)
        print ip_addr + " " + path + " gotcha!"
        # TODO turn off verbose by args
    except:
        respfilename = cases["zero"]
        f = open('responses/'+respfilename)
        stringfile = f.read()
        f.close()
        msgsize = sys.getsizeof(stringfile)
        print ip_addr + " " + path + " not detected..."
        # TODO add to souces, if not detected
    outputdata += 'HTTP/1.1 200 OK\r\n'
    outputdata += 'Server: Apache/1.3.42 (Unix)  (Red Hat/Linux)\r\n'
    outputdata += 'Content-Type: text/html\r\n'
    outputdata += 'Connection: close\r\n'
    outputdata += 'Date: ' + str(datetime.datetime.now())
    outputdata += 'Content-Length: ' + str(msgsize)
    outputdata += '\r\n'
    outputdata += stringfile
    return outputdata

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
port = HONEYPORT
if len(sys.argv) == 2:
    try:
        port = int(sys.argv[1])
    except ValueError:
        pass
serverSocket.bind(('', port))
# TODO args
serverSocket.listen(1)
print "Serving honey on port %s" % port
while True:
    connectionSocket, addr = serverSocket.accept()
    try:
        message = connectionSocket.recv(30*1024)
        ip_addr = connectionSocket.getpeername()[0]
        create_file(message, ip_addr)
        path = ""
        request = HTTPRequest(message)
        if request.error_code is None:
            path = request.path
            outputdata = get_honey(path)
        else:
            path = str(request.error_code)  # use non-http parser here
            outputdata = get_honey(path)
        connectionSocket.send(outputdata)
        connectionSocket.close()
    except:  # rewrite this
        # print "Caught exception socket.error : %s" % e
        connectionSocket.close()
serverSocket.close()  # This line is never achieved, implement in SIGINT?
