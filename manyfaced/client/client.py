import datetime
import json
import os
import signal
import threading
from multiprocessing import Event
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    error as socket_error,
)

from manyfaced.common.logging_setup import get_logger
from manyfaced.common.myenc import AESCipher
from manyfaced.common.status import BOT_TIMEOUT, UNKNOWN_HTTP
from manyfaced.common.settings import HIVEHOST, HIVEPORT
from manyfaced.handlers.http_handler import HTTPHandler
from manyfaced.common.utils import dump_file, receive_timeout

logger = get_logger(__name__)

# List of popular pages requested by incoming hostile bots, with appropriate face to show them
faces = {
    "zero": "zero",
    "/": "zero",
    "/3001": "webdav.xml",
    "/../../../../../../etc/passwd": "webdav.xml",
    "/?author=1": "webdav.xml",
    "/admin.php": "webdav.xml",
    "/admin/": "webdav.xml",
    "/bitrix/admin/": "webdav.xml",
    "/blog/CHANGELOG.txt": "webdav.xml",
    '/cgi-bin/php-cgi.bin?-d allow_url_include=on -d safe_mode=off -d suhosin.simulation=on -d disable_functions="" -d open_basedir=none -d auto_prepend_file=php://input -d cgi.force_redirect=0 -d cgi.redirect_status_env="yes" -d cgi.fix_pathinfo=1 -d auto_prepend_file=php://input -n': "webdav.xml",
    "/cgi/common.cgi": "webdav.xml",
    "/CHANGELOG.txt": "webdav.xml",
    "/command.php": "webdav.xml",
    "/dbadmin/": "webdav.xml",
    "/drupal/": "webdav.xml",
    "/drupal/CHANGELOG.txt": "webdav.xml",
    "/feed2js/magpie_debug.php": "webdav.xml",
    "/forum/CHANGELOG.txt": "webdav.xml",
    "/Http/DataLayCfg.xml": "webdav.xml",
    "/index.php/admin/": "webdav.xml",
    "/invoker/JMXInvokerServlet": "webdav.xml",
    "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo": "webdav.xml",
    "/joom/": "webdav.xml",
    "/joomla/": "webdav.xml",
    "/language/Swedish${IFS}&&echo${IFS}610cker>qt&&tar${IFS}/string.js": "webdav.xml",
    "/m/": "webdav.xml",
    "/manager/": "webdav.xml",
    "/manager/html": "webdav.xml",
    "/mss": "webdav.xml",
    "/mss-value/": "webdav.xml",
    "/mss/": "webdav.xml",
    "/mss/?preview_id=219&preview_nonce=6d5cf35da4&_thumbnail_id=-1&preview=true": "webdav.xml",
    "/muieblackcat": "webdav.xml",
    "/netcat/admin/": "webdav.xml",
    "/new/": "webdav.xml",
    "/OA_HTML/OA.jsp": "webdav.xml",
    "/old/": "webdav.xml",
    "/pma/scripts/setup.php": "webdav.xml",
    "/program/": "webdav.xml",
    "/RemoteControl.html": "webdav.xml",
    "/robots.txt": "webdav.xml",
    "/searchreplacedb2.php": "webdav.xml",
    "/shell?id": "webdav.xml",
    "/shop/CHANGELOG.txt": "webdav.xml",
    "/shopdb/": "webdav.xml",
    "/site/CHANGELOG.txt": "webdav.xml",
    "/sitemap.xml": "webdav.xml",
    "/store/CHANGELOG.txt": "webdav.xml",
    "/stssys.htm": "webdav.xml",
    "/test": "webdav.xml",
    "/test/": "webdav.xml",
    "/test/CHANGELOG.txt": "webdav.xml",
    "/uoytamiw.html": "webdav.xml",
    "/uplink_info.xml": "webdav.xml",
    "/user": "webdav.xml",
    "/user/": "webdav.xml",
    "/w00tw00t.at.blackhats.romanian.anti-sec:": "webdav.xml",
    "/web-console/ServerInfo.jsp": "webdav.xml",
    "/webdav/info.php": "webdav.xml",
    "/wp-content": "webdav.xml",
    "/wp-content/debug.log": "webdav.xml",
    "/www/start.html": "webdav.xml",
    "/x": "webdav.xml",
    "/xmlrpc.php": "webdav.xml",
    "http://www.baidu.com/favicon.ico": "webdav.xml",
    "http://www.qq.com/404/search_children.js": "webdav.xml",
}


def send_report(data, client, password):
    cypher = AESCipher(password)  # type: ignore[name-defined]
    # runtime import: from common.myenc import AESCipher
    message = (client + ":").encode()
    data_dict = {
        "ip": data.ip,
        "raw_request": data.raw_request,
        "timestamp": data.timestamp,
        "parsed_request": {
            "command": data.parsed_request.command,
            "path": data.parsed_request.path,
            "request_version": data.parsed_request.request_version,
            "headers": dict(data.parsed_request.headers),
        },
        "is_detected": data.is_detected,
        "HIVELOGIN": data.HIVELOGIN,
    }
    message += cypher.encrypt(json.dumps(data_dict).encode())
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.connect((HIVEHOST, HIVEPORT))
        s.sendall(message)
        response = s.recv(1024)
        if response.decode() != "200":
            logger.warning("Failed to send report: Non-200 response from server")
            print(response)
        s.close()
        logger.info("Report sent for %s", client)
    except socket_error:
        logger.error("Socket error sending report for %s – dumping to file", client)
        dump_file(data)
    except KeyboardInterrupt:
        pass
    return


def compile_banner(
    msg_size: int = 0,
    code: str = "HTTP/1.1 200 OK",
    server_version: str = (
        "Apache/1.3.42 (Unix)  (Red Hat/Linux)  OpenSSL/1.0.1e PHP/5.5.9 "
    ),
    content_type: str = "text/html; charset=UTF-8",
    connection: str = "close",
    date: str = str(datetime.datetime.now()),
    nl_count: int = 2,
) -> str:
    """
    Build an HTTP response banner and return it as a string.

    Works with default arguments in most faces; any parameter can be overridden.
    ``msg_size`` should equal the byte-length of the body (some browsers reject
    mismatched values).

    ``nl_count`` controls trailing CRLF blank lines:
        2 for ``text/html``,
        1 for ``application/xml``.
    """
    banner: list[str] = []
    c = "\r\n"
    if code != 0:
        banner.append(f"{code}{c}")
    if server_version != "":
        banner.append(f"Server: {server_version}{c}")
    if content_type != "":
        banner.append(f"Content-Type: {content_type}{c}")
    if connection != "":
        banner.append(f"Connection: {connection}{c}")
    if date != "":
        banner.append(f"Date: {date}{c}")
    if msg_size != "":
        banner.append(f"Content-Length: {msg_size}")
    for _ in range(nl_count):
        banner.append(c)
    return "".join(banner)


def banner_to_bytes(banner: str, body: str | None = None) -> bytes:
    """Encode a banner (optionally followed by body) into bytes for socket.send()."""
    if body is not None:
        return (banner + body).encode("iso-8859-1")
    return banner.encode("iso-8859-1")


def get_honey_http(request, bot_ip, verbose, ai_responder=None):
    """
    This is the place where magic happens. Function receives parsed HTTP
    request as an argument and returns an output as a string. If it
    is kind of static content, its being read from responses/. In some kind of
    harder case i use if-else to determine which code should i use. As an
    example, WEBDAV protocol uses different server banner and Content-Type of
    robots.txt should be text/plain(they are also dynamically generated).

    Args:
        request: HTTPRequest object with parsed request data
        bot_ip: Bot's IP address
        verbose: Whether to print verbose output
        ai_responder: Optional AIResponder instance for AI-powered responses
    """
    from manyfaced.common.ai_responder import AIResponder as _AIResponder

    if ai_responder and isinstance(ai_responder, _AIResponder) and ai_responder.is_available():
        # Try AI responder first
        try:
            response_bytes, detected = ai_responder.generate_response(
                request_path=request.path,
                raw_request=request.raw if hasattr(request, "raw") else str(request),
                bot_ip=bot_ip,
            )
            if verbose:
                print(f"{bot_ip} {request.path} gotcha! (AI)")
            return response_bytes, detected
        except Exception as e:
            logger.warning("AI response failed for %s %s: %s – falling back to static", bot_ip, request.path, e)

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
        output_data = honey_generic(faces["zero"])
        detected = UNKNOWN_HTTP
    return output_data, detected


def honey_generic(face):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(root_dir, "responses", face)
    with open(path, "r") as f:
        body = f.read()
    # Detect XML faces and use appropriate Content-Type
    content_type = "text/html; charset=UTF-8"
    if face.endswith(".xml"):
        content_type = "application/xml; charset=utf-8"
    output_data = compile_banner(msg_size=len(body), content_type=content_type)
    output_data += body
    return output_data


def honey_robots():
    body = "User-Agent: *\r\nAllow: /\r\n"
    for url in set(faces.keys()):
        body += "Disallow: " + url + "\r\n"
    output_data = compile_banner(
        msg_size=len(body), content_type="text/plain; charset=UTF-8"
    )
    output_data += body
    return output_data


def honey_webdav(bot_ip):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(root_dir, "responses", "webdav.xml")
    with open(path, "r") as f:
        body = f.read()
    output_data = compile_banner(
        code="HTTP/1.1 207 Multi-Status",
        content_type="application/xml; charset=utf-8",
        connection="",
        date="",
        server_version="",
        nl_count=1,
    )
    output_data += body
    return output_data


def create_server(args, update_event: Event, port: int):
    """Create a single-port honeypot server.
    
    Args:
        args: CLI arguments namespace
        update_event: Event to signal shutdown
        port: Port number to listen on
    """
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(("", port))
    server_socket.listen(1)
    logger.info("Client honeypot listening on port %d", port)
    if args.verbose:
        print(f"Serving honey on port {port}")
    try:
        while True:
            if update_event.is_set():
                break
            connection_socket: socket | None = None
            try:
                connection_socket, _bot_socket = server_socket.accept()
            except KeyboardInterrupt:
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
                connection_socket.sendall(output_data)
                connection_socket.close()
            except socket_error:
                if args.verbose:
                    print("Failed to send response to bot")
                continue
    finally:
        server_socket.close()


def create_multiport_server(args, update_event: Event, ports: list[int]):
    """Create a multi-port honeypot server that listens on multiple ports simultaneously.
    
    Each port runs in its own thread. All threads share the same update_event for shutdown.
    
    Args:
        args: CLI arguments namespace
        update_event: Event to signal shutdown
        ports: List of port numbers to listen on
    """
    threads: list[threading.Thread] = []
    
    for port in ports:
        t = threading.Thread(
            target=create_server,
            args=(args, update_event, port),
            name=f"honeyport-{port}",
            daemon=True,
        )
        threads.append(t)
    
    # Start all threads
    for t in threads:
        t.start()
    
    # Log all ports
    port_list_str = ", ".join(str(p) for p in ports)
    logger.info("Client honeypot listening on %d ports: %s", len(ports), port_list_str)
    if args.verbose:
        print(f"Serving honey on {len(ports)} ports: {port_list_str}")
    
    # Wait for shutdown signal
    try:
        while not update_event.is_set():
            update_event.wait(timeout=1)
    except KeyboardInterrupt:
        pass
    
    # Wait for all threads to finish
    for t in threads:
        t.join(timeout=5)
    
    logger.info("All honeypot threads stopped")


def main(args, update_event):
    if getattr(signal, "SIGCHLD", None) is not None:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    
    port_mode = getattr(args, "port_mode", "single")
    top_ports = getattr(args, "top_ports", "")
    
    if port_mode == "all":
        # All ports: 1-65535
        ports = list(range(1, 65536))
        logger.warning("Listening on ALL 65535 ports – this may take time to start")
        print(f"WARNING: Listening on all 65535 TCP ports...")
        create_multiport_server(args, update_event, ports)
    elif port_mode == "top":
        # Top 50 (or custom) ports
        if top_ports:
            try:
                ports = sorted({int(p.strip()) for p in top_ports.split(",") if p.strip()})
            except ValueError:
                ports = [
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                    143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
                    5432, 5900, 5901, 6379, 8080, 8443, 9200, 11211, 27017, 5672,
                    15672, 4369, 2181, 9090, 8888, 7001, 7002, 11300, 11301, 11302,
                    11303, 11304, 11305, 11306, 11307, 11308, 11309, 11310, 11311,
                    5000,
                ]
        else:
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
                5432, 5900, 5901, 6379, 8080, 8443, 9200, 11211, 27017, 5672,
                15672, 4369, 2181, 9090, 8888, 7001, 7002, 11300, 11301, 11302,
                11303, 11304, 11305, 11306, 11307, 11308, 11309, 11310, 11311,
                5000,
            ]
        create_multiport_server(args, update_event, ports)
    else:
        # Single port mode (default)
        port = args.client
        create_server(args, update_event, port)
