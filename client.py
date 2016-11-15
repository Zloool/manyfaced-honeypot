import datetime
import os
import pickle
import signal
from multiprocessing import Process, Lock
from operator import itemgetter
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as sockerror)

import status
from bearstorage import BearStorage
from faces import faces
from httphandler import HTTPRequest
from myenc import AESCipher
from server import dump_file, recv_timeout
from settings import HIVEHOST, HIVEPORT, HIVELOGIN, HIVEPASS


def send_report(data, client, password, lock):
    with lock:
        cypher = AESCipher(password)
        message = client + ":"
        message += cypher.encrypt(pickle.dumps(data))
        s = socket(AF_INET, SOCK_STREAM)
        try:
            s.connect((HIVEHOST, HIVEPORT))
            s.sendall(message)
            response = s.recv(1024)
            if response != '200':
                raise sockerror
            s.close()
        except sockerror:
            dump_file(data)
        except KeyboardInterrupt:
            pass
    os._exit(0)


def compile_banner(msg_size=0,
                   code="HTTP/1.1 200 OK",
                   server_version="Apache/1.3.42 (Unix)  (Red Hat/Linux)  "
                        "OpenSSL/1.0.1e PHP/5.5.9 ",
                   content_type='text/html; charset=UTF-8',
                   connection="close",
                   date=str(datetime.datetime.now()),
                   nl_count=2):
    """
    This function creates an HTTP banner and returns it as string. Works well
    with default arguments in most faces, any of them can be overridden.
    `msg_size` needs to be equal to len() of the content string (will work with
    incorrect values in some browsers, but not in YaBrowser, so maybe in all
    of the chrome based browsers).
    `nl_count` is the number of blank lines in the end of server banner. Number
    of the lines depends on Content-Type of the response. Should be:
    2 - `text/html`; 1 - `application/xml`
    """
    banner = ""
    if code != 0:
        banner += code + '\r\n'
    if server_version != '':
        banner += 'Server: ' + server_version + '\r\n'
    if content_type != '':
        banner += 'Content-Type: ' + content_type + '\r\n'
    if connection != '':
        banner += 'Connection: ' + connection + '\r\n'
    if date != '':
        banner += 'Date: ' + date + '\r\n'
    if msg_size != '':
        banner += 'Content-Length: ' + str(msg_size)
    for i in range(nl_count):
        banner += '\r\n'
    return banner


def get_honey_http(request, ip_addr, verbose):
    """
    This is the place where magic happens. Function receives parsed HTTP
    request as an argument and returns an output as a string. If it
    is kind of static content, its being read from responses/. In some kind of
    harder case i use if-else to determine which code should i use. As an
    example, WEBDAV protocol uses different server banner and Content-Type of
    robots.txt should be text/plain(they are also dynamically generated).
    """
    if request.path in faces:  # If we know what to do with request
        face = faces[request.path]
        if face == "webdav.xml":  # Compile response for WEBDAV listing
            output_data = honey_webdav(ip_addr)
        elif face == "robots":  # Generate robots.txt from faces dict
            output_data = honey_robots()
        else:  # If our request doesnt require special treatment, it goes here
            output_data = honey_generic(face)
        if verbose:
            print ip_addr + " " + request.path + " gotcha!"
    else:  # If we dont know what to do with that request
        if verbose:
            print ip_addr + " " + request.path[:50] + " not detected..."
        output_data = honey_unknown(request)
    try:
        detected = map(itemgetter(0), faces).index(request.path)
    except ValueError:
        detected = status.UNKNOWN_HTTP
    return output_data, detected


def honey_unknown(request):
    if request.path not in unknown_faces:
        unknown_faces.append(request.path)
        with open("local_faces.txt", "a") as f:
            f.write(request.path + "\n")
    output_data = honey_generic(faces["zero"])
    return output_data


def honey_generic(face):
    with file('responses/' + face) as f:
        body = f.read()
    output_data = compile_banner(msg_size=len(body))
    output_data += body
    return output_data


def honey_robots():
    body = 'User-Agent: *\r\nAllow: /\r\n'
    for url in known_faces:
        body += 'Disallow: ' + url + "\r\n"
    output_data = compile_banner(msg_size=len(body),
                                 content_type="text/plain"
                                              "; charset=UTF-8")
    output_data += body
    return output_data


def honey_webdav(ip_addr):
    with file('responses/webdav.xml') as f:
        body = f.read()
    output_data = compile_banner(code='HTTP/1.1 207 Multi-Status',
                                 content_type='application/xml; '
                                              'charset=utf-8', connection='',
                                 date='', server_version='', nl_count=1)
    output_data += body
    return output_data


def handle_request(message, request_time, bot_ip, verbose, report_lock):
    request = HTTPRequest(message)
    if request.error_code is None:
        if hasattr(request, 'path'):
            output_data, detected = get_honey_http(request, bot_ip, verbose)
        else:
            output_data = message
            detected = status.UNKNOWN_HTTP
    else:
        if verbose:
            print "Got non-http request"
        detected = status.UNKNOWN_NON_HTTP
        output_data = message
    bs = BearStorage(bot_ip, unicode(message, errors='replace'),
                     request_time, request, detected, HIVELOGIN)
    Process(
        args=(bs, HIVELOGIN, HIVEPASS, report_lock),
        name="send_report",
        target=send_report,).start()
    return output_data


def create_server(port, report_lock, verbose, update_event):
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(1)
    if verbose:
        print "Serving honey on port %s" % port
    while True:
        if update_event.is_set():
            break
        try:
            connection_socket, addr = server_socket.accept()
        except KeyboardInterrupt:
            if 'connection_socket' in locals():
                connection_socket.close()
            break
        try:
            message = recv_timeout(connection_socket, status.BOT_TIMEOUT)
        except sockerror:
            if verbose:
                print "Failed to receive data from bot"
            continue
        bot_ip = addr[0]
        request_time = str(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"))
        outputdata = handle_request(message, request_time, bot_ip,
                                    verbose, report_lock)
        try:
            connection_socket.send(outputdata)
            connection_socket.close()
        except sockerror:
            if verbose:
                print "Failed to send response to bot"
            continue
    server_socket.close()


def main(args, update_event):
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    report_lock = Lock()
    global unknown_faces
    if not os.path.isfile("local_faces.txt"):
        f = file("local_faces.txt", "w")
        f.close()
    unknown_faces = [line.rstrip('\n') for line in open('faces.txt')]
    unknown_faces += [line.rstrip('\n') for line in open('local_faces.txt')]
    global known_faces
    known_faces = set()
    for url in faces:
        known_faces.add(url)
    create_server(args.client, report_lock, args.verbose, update_event)
