import datetime
import os
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

from arguments import parse
from cases import cases
from httphandler import HTTPRequest
from settings import HONEYFOLDER


def create_file(message, directory):
    """
    Temporary function, being used for storing honeypot data, before i
    add ClickHouse as the storage. I am using it to save each packet to a
    separate file, using timestamp as a filename, and SRC_IP as a foldername.
    HONEYFOLDER is the name of a root directory to save all data into.
    """
    if not os.path.exists(HONEYFOLDER+directory):
        os.makedirs(HONEYFOLDER+directory)
    currtime = str(datetime.datetime.now()).replace(':', ';')
    filename = HONEYFOLDER+directory+"/"+currtime
    with open(filename, "w") as f:
        f.write(str(message))


def compile_banner(msgsize=0,
                   code="HTTP/1.1 200 OK",
                   serverver="Apache/1.3.42 (Unix)  (Red Hat/Linux)  "
                             "OpenSSL/1.0.1e PHP/5.5.9 ",
                   contenttype='text/html; charset=UTF-8',
                   connection="close",
                   date=str(datetime.datetime.now()),
                   nlcount=2):
    """
    This function creates an HTTP banner and returns it as string. Works well
    with default arguments in most cases, any of them can be overridden.
    `msgsize` needs to be equal to len() of the content string (will work with
    incorrect values in some browsers, but not in YaBrowser, so maybe in all
    of the chrome based browsers).
    `nlcount` is the number of blank lines in the end of server banner. Number
    of the lines depends on Content-Type of the response. Should be:
    2 - `text/html`; 1 - `application/xml`
    """
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
    """
    This is the place where magic happens. Function recieves parsed HTTP
    request as an argument and returns an output as a string. If it
    is kind of static content, its being read from responses/. In some kind of
    harder case i use if-else to determine which code should i use. As an
    example, WEBDAV protocol uses different server banner and Content-Type of
    robots.txt should be text/plain(they are also dynamically generated).
    """
    global unknown_cases
    outputdata = ""
    stringfile = ""
    if request.path in cases:  # If we know what to do with request
        respfilename = cases[request.path]
        if respfilename == "webdav.xml":  # Compile response for WEBDAV listing
            with file('responses/'+cases[request.path]) as f:
                stringfile = f.read()
            outputdata += compile_banner(code='HTTP/1.1 207 Multi-Status',
                                         contenttype='application/xml; '
                                         'charset=utf-8',
                                         connection=0, date=0, serverver=0,
                                         nlcount=1)
            outputdata += stringfile
        elif respfilename == "robots":  # Generate robots.txt from cases dict
            stringfile = 'User-Agent: *\r\nAllow: /\r\n'
            for url in known_cases:
                stringfile += 'Disallow: ' + url + "\r\n"
            outputdata += compile_banner(msgsize=len(stringfile),
                                         contenttype="Content-Type: text/plain"
                                         "; charset=UTF-8")
            outputdata += stringfile
        else:  # If our request dont require special treatment, it goes here
            with file('responses/'+cases[request.path]) as f:
                stringfile = f.read()
            outputdata += compile_banner(msgsize=len(stringfile))
            outputdata += stringfile
        if args.verbose:
            print ip_addr + " " + request.path + " gotcha!"
    else:  # If we dont know what to do whith that request
        if args.verbose:
            print ip_addr + " " + request.path + " not detected..."
        if request.path not in unknown_cases:
            # Lets add him to our todo list ;) (if we dont already have it)
            unknown_cases.append(request.path)
            with open("cases.txt", "a") as f:
                f.write(request.path + "\n")
        # Send default response
        with file('responses/'+cases["zero"]) as f:
            stringfile = f.read()
        outputdata += compile_banner(msgsize=len(stringfile))
        outputdata += stringfile
    return outputdata

# Get our unimplemented requests list, so we cann add something to it
unknown_cases = [line.rstrip('\n') for line in open('cases.txt')]
# Create a known_cases set, so we can generate robots.txt
known_cases = set()
for url in cases:
    known_cases.add(url)
# Parse arguments
args = parse()
# Create socket
serverSocket = socket(AF_INET, SOCK_STREAM)
# Need to set setsockopt to resolve "port already in use" issue
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
# Bind our socket to a port. Will use one from settings, if not given in args
serverSocket.bind(('', args.port))
serverSocket.listen(1)
print "Serving honey on port %s" % args.port
# Endless loop for handling requests
while True:
    connectionSocket, addr = serverSocket.accept()
    # Need to use try, because socket will generate a lot of exc
    try:
        # Argument is the number of bytes to recieve from client. Why 30000?idk
        message = connectionSocket.recv(30000)
        ip_addr = connectionSocket.getpeername()[0]
        create_file(message, ip_addr)
        # Try to parse request parameters from message
        request = HTTPRequest(message)
        if request.error_code is None:
            outputdata = get_honey_http(request)
        # If its not an HTTP request, it goes here
        else:
            path = str(request.error_code)  # use non-http parser here
            outputdata = ""
        connectionSocket.send(outputdata)
        connectionSocket.close()
    except:  # rewrite this
        # print "Caught exception socket.error : %s" % e
        connectionSocket.close()
serverSocket.close()  # This line is never achieved, implement in SIGINT?
