import datetime
import os
import pickle
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as sockerror)
from multiprocessing import Process, Lock


from settings import HIVEHOST, HIVEPORT, HIVELOGIN, HIVEPASS
from faces import faces
from httphandler import HTTPRequest
from myenc import AESCipher
from bearstorage import BearStorage
from server import DumpToFile, recv_timeout


def send_report(data, client, password, lock):
    with lock:
        ciper = AESCipher(password)
        message = client + ":"
        message += ciper.encrypt(pickle.dumps(data))
        s = socket(AF_INET, SOCK_STREAM)
        try:
            s.connect((HIVEHOST, HIVEPORT))
            s.sendall(message)
            response = s.recv(1024)
            if response != '200':
                raise sockerror
            s.close()
        except sockerror:
            DumpToFile(data)
            # response = "Hive server is not responding :("
        except KeyboardInterrupt:
            pass
    os._exit(0)


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
    with default arguments in most faces, any of them can be overridden.
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


def get_honey_http(args, request, ip_addr):
    """
    This is the place where magic happens. Function receives parsed HTTP
    request as an argument and returns an output as a string. If it
    is kind of static content, its being read from responses/. In some kind of
    harder case i use if-else to determine which code should i use. As an
    example, WEBDAV protocol uses different server banner and Content-Type of
    robots.txt should be text/plain(they are also dynamically generated).
    """
    outputdata = ""
    stringfile = ""
    if request.path in faces:  # If we know what to do with request
        respfilename = faces[request.path]
        if respfilename == "webdav.xml":  # Compile response for WEBDAV listing
            with file('responses/' + faces[request.path]) as f:
                stringfile = f.read()
            outputdata += compile_banner(code='HTTP/1.1 207 Multi-Status',
                                         contenttype='application/xml; '
                                         'charset=utf-8',
                                         connection=0, date=0, serverver=0,
                                         nlcount=1)
            outputdata += stringfile
        elif respfilename == "robots":  # Generate robots.txt from faces dict
            stringfile = 'User-Agent: *\r\nAllow: /\r\n'
            for url in known_faces:
                stringfile += 'Disallow: ' + url + "\r\n"
            outputdata += compile_banner(msgsize=len(stringfile),
                                         contenttype="text/plain"
                                         "; charset=UTF-8")
            outputdata += stringfile
        else:  # If our request doesnt require special treatment, it goes here
            with file('responses/' + faces[request.path]) as f:
                stringfile = f.read()
            outputdata += compile_banner(msgsize=len(stringfile))
            outputdata += stringfile
        if args.verbose:
            print ip_addr + " " + request.path + " gotcha!"
    else:  # If we dont know what to do with that request
        if args.verbose:
            print ip_addr + " " + request.path[:50] + " not detected..."
        if request.path not in unknown_faces:
            # Lets add him to our todo list ;) (if we dont already have it)
            unknown_faces.append(request.path)
            with open("local_faces.txt", "a") as f:
                f.write(request.path + "\n")
        # Send default response
        with file('responses/' + faces["zero"]) as f:
            stringfile = f.read()
        outputdata += compile_banner(msgsize=len(stringfile))
        outputdata += stringfile
    return outputdata, request.path in faces


def main(args, update_event):
    report_lock = Lock()
    # Get our unimplemented requests list, so we can add something to it
    global unknown_faces
    if not os.path.isfile("local_faces.txt"):
        f = file("local_faces.txt", "w")
        f.close()
    unknown_faces = [line.rstrip('\n') for line in open('faces.txt')]
    unknown_faces += [line.rstrip('\n') for line in open('local_faces.txt')]
    # Create a known_faces set, so we can generate robots.txt
    global known_faces
    known_faces = set()
    for url in faces:
        known_faces.add(url)
    # Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # Need to set setsockopt to resolve "port already in use" issue
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # Bind our socket to a port
    # Will use one from settings, if not given in args
    serverSocket.bind(('', args.client))
    serverSocket.listen(1)
    if args.verbose:
        print "Serving honey on port %s" % args.client
    # Endless loop for handling requests
    while True:

        if update_event.is_set():
            break
        try:
            connectionSocket, addr = serverSocket.accept()
        except KeyboardInterrupt:
            if 'connectionSocket' in locals():
                connectionSocket.close()
            break
        # Need to use try, because socket will generate a lot of exceptions
        try:
            # Argument is the number of bytes to recieve from client
            message = recv_timeout(connectionSocket)
        except sockerror:
            if args.verbose:
                print "Failed to recieve data from bot"
            continue
        ip_addr = connectionSocket.getpeername()[0]
        dt = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))
        # Try to parse request parameters from message
        request = HTTPRequest(message)
        if request.error_code is None:
            if hasattr(request, 'path'):
                outputdata, detected = get_honey_http(
                    args, request, ip_addr)
            else:
                outputdata = message
                detected = 4294967295 - 1
        # If it's not an HTTP request, it goes here
        else:
            if args.verbose:
                print "Got non-http request"
            detected = 4294967295 - 2
            outputdata = message
        bs = BearStorage(ip_addr, unicode(message, errors='replace'),
                         dt, request, detected, HIVELOGIN)
        response = Process(
            args=(bs, HIVELOGIN, HIVEPASS, report_lock),
            name="send_report",
            target=send_report,)
        response.start()
        try:
            connectionSocket.send(outputdata)
            connectionSocket.close()
        except sockerror:
            if args.verbose:
                print "Failed to send response to bot"
            continue
    serverSocket.close()
