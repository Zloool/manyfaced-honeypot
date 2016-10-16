import datetime
import os
import sys
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
    global unknown_cases
    outputdata = ""
    stringfile = ""
    msgsize = 0
    if path in cases:
        respfilename = cases[path]
        f = open('responses/'+respfilename)
        stringfile = f.read()
        f.close()
        if respfilename == "webdav.xml":
            msgsize = sys.getsizeof(stringfile)
            outputdata += 'HTTP/1.1 207 Multi-Status\r\n'
            outputdata += 'Content-Type: application/xml; charset="utf-8\r\n'
            outputdata += '\r\n'
            outputdata += stringfile
        else:
            msgsize = sys.getsizeof(stringfile)
            outputdata += 'HTTP/1.1 200 OK\r\n'
            outputdata += 'Server: Apache/1.3.42 (Unix)  (Red Hat/Linux)\r\n'
            outputdata += 'Content-Type: text/html\r\n'
            outputdata += 'Connection: close\r\n'
            outputdata += 'Date: ' + str(datetime.datetime.now())
            outputdata += 'Content-Length: ' + str(msgsize)
            outputdata += '\r\n'
            outputdata += stringfile
        print ip_addr + " " + path + " gotcha!"
        # TODO turn off verbose by args
    else:
        print ip_addr + " " + path + " not detected..."
        if path not in unknown_cases:
            unknown_cases.append(path)
            with open("cases.txt", "a") as myfile:
                myfile.write(path + "\n")
            print path + " added to list"
        # TODO add to souces, if not
        respfilename = cases["zero"]
        f = open('responses/'+respfilename)
        stringfile = f.read()
        f.close()
        msgsize = sys.getsizeof(stringfile)
        outputdata += 'HTTP/1.1 200 OK\r\n'
        outputdata += 'Server: Apache/1.3.42 (Unix)  (Red Hat/Linux)\r\n'
        outputdata += 'Content-Type: text/html\r\n'
        outputdata += 'Connection: close\r\n'
        outputdata += 'Date: ' + str(datetime.datetime.now())
        outputdata += 'Content-Length: ' + str(msgsize)
        outputdata += '\r\n'
        outputdata += stringfile
    return outputdata

unknown_cases = [line.rstrip('\n') for line in open('cases.txt')]
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
port = HONEYPORT
if len(sys.argv) == 2:
    try:
        port = int(sys.argv[1])
    except ValueError:
        pass
serverSocket.bind(('', port))
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
