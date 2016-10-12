import os
import datetime
from socket import socket, AF_INET, SOCK_STREAM
from cases import cases
from httphandler import HTTPRequest
# import signal
# TODO unittests


def create_file(message, directory):
    if not os.path.exists("bots/"+directory):
        os.makedirs("bots/"+directory)
    filename = "bots/"+directory+"/"+str(datetime.datetime.now()).replace(':', ';')
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

# exit -- something to do on SIGINT
# signal.signal(signal.SIGINT, exit)
# TODO implement SIGINT handler
serverSocket = socket(AF_INET, SOCK_STREAM)
# serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) FIX ME
# TODO add socketopt to resolve socket.error: [Errno 98] Address already in use
serverSocket.bind(('', 80))
# TODO args or settins
serverSocket.listen(1)
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
        except:
            path = str(request.error_code)
        # print request.error_code       # None  (check this first)
        # print request.command          # "GET"
        # print request.path             # "/who/ken/trust.html"
        # print request.request_version  # "HTTP/1.1"
        # print len(request.headers)     # 3
        # print request.headers.keys()   # ['accept-charset', 'host', 'accept']
        # print request.headers['host']  # "cm.bell-labs.com"
        # filename = message.split()[1]
        # print filename[1:]

        outputdata = get_honey(path)
        connectionSocket.send('HTTP/1.0 200 OK\r\n\r\n')
        connectionSocket.send(outputdata)

        # Send the content of the requested file to the client
        # for i in range(0, len(outputdata)):
        #    connectionSocket.send(outputdata[i])
        connectionSocket.close()
    except IOError:
        print "Caught exception IOError"
        # connectionSocket.send('HTTP/1.0 200 OK\r\n\r\n')
        connectionSocket.close()
    except socket.error, exc:
        print "Caught exception socket.error : %s" % exc
        connectionSocket.close()

serverSocket.close()
