import os
import datetime
from socket import socket, AF_INET, SOCK_STREAM
from cases import cases
from httphandler import HTTPRequest


def create_file(message, directory):
    if not os.path.exists("bots/"+directory):
        os.makedirs("bots/"+directory)
    filename = "bots/"+directory+"/"+str(datetime.datetime.now()).replace(':', ';')
    print filename
    f = open(filename, 'w')
    f.write(str(message))
    f.close()

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', 80))
serverSocket.listen(1)
while True:
    connectionSocket, addr = serverSocket.accept()
    try:
        message = connectionSocket.recv(30*1024)
        ip_addr = connectionSocket.getpeername()[0]
        create_file(message, ip_addr)
        request = HTTPRequest(message)
        # print request.error_code       # None  (check this first)
        # print request.command          # "GET"
        # print request.path             # "/who/ken/trust.html"
        # print request.request_version  # "HTTP/1.1"
        # print len(request.headers)     # 3
        # print request.headers.keys()   # ['accept-charset', 'host', 'accept']
        # print request.headers['host']  # "cm.bell-labs.com"
        # filename = message.split()[1]
        # print filename[1:]
        try:
            respfilename = cases[request.path]
            # TODO make parser for path traverse, etc
        except:
            respfilename = cases["zero"]
        f = open('responses\\'+respfilename)
        outputdata = f.read()
        f.close()
        # Send one HTTP header line into socket
        connectionSocket.send('HTTP/1.0 200 OK\r\n\r\n')
        # Send the content of the requested file to the client
        for i in range(0, len(outputdata)):
            connectionSocket.send(outputdata[i])
        connectionSocket.close()
    except IOError:
        # Send response message for file not found
        connectionSocket.send('HTTP/1.0 200 OK\r\n\r\n')
        # Close client socket
        connectionSocket.close()
serverSocket.close()
