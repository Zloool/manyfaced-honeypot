import datetime
import os
import json
import signal
from multiprocessing import Process, Lock
from socket import (socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
                    error as socket_error, inet_aton)

# List of popular pages requested by incoming hostile bots, with appropriate face to show them
faces = {
    '/3001': 'webdav.xml',
    '/../../../../../../etc/passwd': 'webdav.xml',
    '/?author=1': 'webdav.xml',
    '/admin.php': 'webdav.xml',
    '/admin/': 'webdav.xml',
    '/bitrix/admin/': 'webdav.xml',
    '/blog/CHANGELOG.txt': 'webdav.xml',
    '/cgi-bin/php-cgi.bin?-d allow_url_include=on -d safe_mode=off -d suhosin.simulation=on -d disable_functions="" -d open_basedir=none -d auto_prepend_file=php://input -d cgi.force_redirect=0 -d cgi.redirect_status_env="yes" -d cgi.fix_pathinfo=1 -d auto_prepend_file=php://input -n': 'webdav.xml',
    '/cgi/common.cgi': 'webdav.xml',
    '/CHANGELOG.txt': 'webdav.xml',
    '/command.php': 'webdav.xml',
    '/dbadmin/': 'webdav.xml',
    '/drupal/': 'webdav.xml',
    '/drupal/CHANGELOG.txt': 'webdav.xml',
    '/feed2js/magpie_debug.php': 'webdav.xml',
    '/forum/CHANGELOG.txt': 'webdav.xml',
    '/Http/DataLayCfg.xml': 'webdav.xml',
    '/index.php/admin/': 'webdav.xml',
    '/invoker/JMXInvokerServlet': 'webdav.xml',
    '/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo': 'webdav.xml',
    '/joom/': 'webdav.xml',
    '/joomla/': 'webdav.xml',
    '/language/Swedish${IFS}&&echo${IFS}610cker>qt&&tar${IFS}/string.js': 'webdav.xml',
    '/m/': 'webdav.xml',
    '/manager/': 'webdav.xml',
    '/manager/html': 'webdav.xml',
    '/mss': 'webdav.xml',
    '/mss-value/': 'webdav.xml',
    '/mss/': 'webdav.xml',
    '/mss/?preview_id=219&preview_nonce=6d5cf35da4&_thumbnail_id=-1&preview=true': 'webdav.xml',
    '/muieblackcat': 'webdav.xml',
    '/netcat/admin/': 'webdav.xml',
    '/new/': 'webdav.xml',
    '/OA_HTML/OA.jsp': 'webdav.xml',
    '/old/': 'webdav.xml',
    '/pma/scripts/setup.php': 'webdav.xml',
    '/program/': 'webdav.xml',
    '/RemoteControl.html': 'webdav.xml',
    '/robots.txt': 'webdav.xml',
    '/searchreplacedb2.php': 'webdav.xml',
    '/shell?id': 'webdav.xml',
    '/shop/CHANGELOG.txt': 'webdav.xml',
    '/shopdb/': 'webdav.xml',
    '/site/CHANGELOG.txt': 'webdav.xml',
    '/sitemap.xml': 'webdav.xml',
    '/store/CHANGELOG.txt': 'webdav.xml',
    '/stssys.htm': 'webdav.xml',
    '/test': 'webdav.xml',
    '/test/': 'webdav.xml',
    '/test/CHANGELOG.txt': 'webdav.xml',
    '/uoytamiw.html': 'webdav.xml',
    '/uplink_info.xml': 'webdav.xml',
    '/user': 'webdav.xml',
    '/user/': 'webdav.xml',
    '/w00tw00t.at.blackhats.romanian.anti-sec:': 'webdav.xml',
    '/web-console/ServerInfo.jsp': 'webdav.xml',
    '/webdav/info.php': 'webdav.xml',
    '/wp-content': 'webdav.xml',
    '/wp-content/debug.log': 'webdav.xml',
    '/www/start.html': 'webdav.xml',
    '/x': 'webdav.xml',
    '/xmlrpc.php': 'webdav.xml',
    'http://www.baidu.com/favicon.ico': 'webdav.xml',
    'http://www.qq.com/404/search_children.js': 'webdav.xml',
    '/CHANGELOG.txt': 'webdav.xml',
    '/drupal/CHANGELOG.txt': 'webdav.xml',
    '/site/CHANGELOG.txt': 'webdav.xml',
    '/store/CHANGELOG.txt': 'webdav.xml',
    '/test/CHANGELOG.txt': 'webdav.xml',
    '/shop/CHANGELOG.txt': 'webdav.xml',
    '/forum/CHANGELOG.txt': 'webdav.xml',
    '/blog/CHANGELOG.txt': 'webdav.xml',
    '/OA_HTML/OA.jsp': 'webdav.xml',
    '/Http/DataLayCfg.xml': 'webdav.xml',
    '/www/start.html': 'webdav.xml',
    '/RemoteControl.html': 'webdav.xml'
}
from manyfaced.common.bearstorage import BearStorage
from manyfaced.common.httphandler import HTTPRequest
from manyfaced.handlers.http_handler import HTTPHandler

def send_report(data, client, password, lock):
    with lock:
        cypher = AESCipher(password)
        message = (client + ":").encode()
        data_dict = {
            'ip': data.ip,
            'raw_request': data.raw_request,
            'timestamp': data.timestamp,
            'parsed_request': {
                'command': data.parsed_request.command,
                'path': data.parsed_request.path,
                'request_version': data.parsed_request.request_version,
                'headers': dict(data.parsed_request.headers)
            },
            'is_detected': data.is_detected,
            'HIVELOGIN': data.HIVELOGIN
        }
        message += cypher.encrypt(json.dumps(data_dict).encode())
        s = socket(AF_INET, SOCK_STREAM)
        try:
            s.connect((HIVEHOST, HIVEPORT))
            s.sendall(message)
            response = s.recv(1024)
            if response.decode() != '200':
                print(response)
                print("Failed to send report: Non-200 response")
            s.close()
        except socket_error:
            dump_file(data)
        except KeyboardInterrupt:
            pass
    return


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


def get_honey_http(request, bot_ip, verbose):
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
        detected = 1
        if face == "webdav.xml":  # Compile response for WEBDAV listing
            output_data = honey_webdav(bot_ip)
        elif face == "robots":  # Generate robots.txt from faces dict
            output_data = honey_robots()
        else:  # If our request doesnt require special treatment, it goes here
            output_data = honey_generic(face)
        if verbose:
            print(bot_ip + " " + request.path + " gotcha!")
    else:  # If we dont know what to do with that request
        if verbose:
            print(bot_ip + " " + request.path[:50] + " not detected...")
        output_data = honey_generic(faces['zero'])
        detected = UNKNOWN_HTTP
    return output_data, detected


def honey_generic(face):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(root_dir, 'responses', face)
    with open(path, 'r') as f:
        body = f.read()
    output_data = compile_banner(msg_size=len(body))
    output_data += body
    return output_data


def honey_robots():
    body = 'User-Agent: *\r\nAllow: /\r\n'
    for url in set(faces.keys()):
        body += 'Disallow: ' + url + "\r\n"
    output_data = compile_banner(msg_size=len(body),
                                 content_type="text/plain"
                                              "; charset=UTF-8")
    output_data += body
    return output_data


def honey_webdav(bot_ip):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(root_dir, 'responses', 'webdav.xml')
    with open(path, 'r') as f:
        body = f.read()
    output_data = compile_banner(code='HTTP/1.1 207 Multi-Status',
                                 content_type='application/xml; '
                                              'charset=utf-8', connection='',
                                 date='', server_version='', nl_count=1)
    output_data += body
    return output_data


def create_server(args, report_lock, update_event):
    port = args.client
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(1)
    if args.verbose:
        print("Serving honey on port %s" % port)
    while True:
        if update_event.is_set():
            break
        try:
            connection_socket, bot_socket = server_socket.accept()
        except KeyboardInterrupt:
            if 'connection_socket' in locals():
                connection_socket.close()
            break
        try:
            message = receive_timeout(connection_socket, BOT_TIMEOUT)
        except socket_error:
            if args.verbose:
                print("Failed to receive data from bot")
            continue
        handler = HTTPHandler(args, update_event)
        output_data = handler.handle_request(message)
        try:
            connection_socket.send(output_data)
            connection_socket.close()
        except socket_error:
            if args.verbose:
                print("Failed to send response to bot")
            continue
    server_socket.close()


def main(args, update_event):
    if getattr(signal, 'SIGCHLD', None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    create_server(args, Lock(), update_event)
