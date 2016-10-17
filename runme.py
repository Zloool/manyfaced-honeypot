import datetime
import os
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

from arguments import parse
from cases import cases
from httphandler import HTTPRequest
from settings import HONEYFOLDER


def create_file(message, directory):
    if not os.path.exists(HONEYFOLDER+directory):
        os.makedirs(HONEYFOLDER+directory)
    currtime = str(datetime.datetime.now()).replace(':', ';')
    filename = HONEYFOLDER+directory+"/"+currtime
    f = open(filename, 'w')
    f.write(str(message))
    f.close()


def compile_banner(msgsize=0,
                   code="HTTP/1.1 200 OK",
                   serverver="Apache/1.3.42 (Unix)  (Red Hat/Linux)",
                   contenttype='text/html; charset=UTF-8',
                   connection="close",
                   date=str(datetime.datetime.now()),
                   nlcount=2):
    banner = ""
    if code != 0:
        banner += code + '\r\n'
    if serverver != 0:
        banner += 'Server: ' + serverver + '\r\n'
    if contenttype != 0:
        banner += 'Content-Type: ' + contenttype + '\r\n'
    if connection != 0:
        banner += 'Connection: ' + connection + '\r\n'
    if date != 0:
        banner += 'Date: ' + date + '\r\n'
    if msgsize != 0:
        banner += 'Content-Length: ' + str(msgsize)
    for i in range(nlcount):
        banner += '\r\n'
    return banner


def get_honey_http(request):
    # request.path
    global unknown_cases
    outputdata = ""
    stringfile = ""
    if request.path in cases:  # if we know what to do
        respfilename = cases[request.path]
        if respfilename == "webdav.xml":
            with file('responses/'+cases[request.path]) as f:
                stringfile = f.read()
            outputdata += compile_banner(code='HTTP/1.1 207 Multi-Status',
                                         contenttype='application/xml; '
                                         'charset=utf-8',
                                         connection=0, date=0, serverver=0,
                                         nlcount=1)
            outputdata += stringfile
        elif respfilename == "robots":
            stringfile = 'User-Agent: *\r\nAllow: /\r\n'
            for url in known_cases:
                stringfile += 'Disallow: ' + url + "\r\n"
            outputdata += compile_banner(msgsize=len(stringfile),
                                         contenttype="Content-Type: text/plain"
                                         "; charset=UTF-8")
            outputdata += stringfile
        else:
            with file('responses/'+cases[request.path]) as f:
                stringfile = f.read()
            outputdata += compile_banner(msgsize=len(stringfile))
            outputdata += stringfile
        print ip_addr + " " + request.path + " gotcha!"
        # TODO turn off verbose by args
    else:  # if we dont know what to do
        print ip_addr + " " + request.path + " not detected..."
        if request.path not in unknown_cases:
            unknown_cases.append(request.path)
            with open("cases.txt", "a") as f:
                f.write(request.path + "\n")
        with file('responses/'+cases["zero"]) as f:
            stringfile = f.read()
        outputdata += compile_banner(msgsize=len(stringfile),
                                     contenttype="Content-Type: text/plain;"
                                     " charset=UTF-8")
        outputdata += stringfile
    return outputdata

unknown_cases = [line.rstrip('\n') for line in open('cases.txt')]
known_cases = set()
for url in cases:
    known_cases.add(url)
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
args = parse()
serverSocket.bind(('', args.port))
serverSocket.listen(1)
print "Serving honey on port %s" % args.port
while True:
    connectionSocket, addr = serverSocket.accept()
    try:
        message = connectionSocket.recv(30*1024)
        ip_addr = connectionSocket.getpeername()[0]
        create_file(message, ip_addr)
        path = ""
        request = HTTPRequest(message)
        if request.error_code is None:
            outputdata = get_honey_http(request)
        else:
            path = str(request.error_code)  # use non-http parser here
            # outputdata = get_honey(path)
        connectionSocket.send(outputdata)
        connectionSocket.close()
    except:  # rewrite this
        # print "Caught exception socket.error : %s" % e
        connectionSocket.close()
serverSocket.close()  # This line is never achieved, implement in SIGINT?
