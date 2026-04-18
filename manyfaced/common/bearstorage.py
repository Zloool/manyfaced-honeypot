import socket
from geoip import geolite2  # type: ignore[import-untyped]


class BearStorage:
    """Stores bear (bot) data gathered from a connection."""

    def __init__(self, ip: str, raw_request: str, timestamp: str,
                 parsed_request: object, is_detected: int,
                 hostname: str) -> None:
        self.ip = ip
        self.raw_request = raw_request
        self.timestamp = timestamp
        self.path = ""
        self.command = ""
        self.version = ""
        self.ua = ""
        self.headers = ""  # type: ignore[assignment]
        self.country = ""
        self.continent = ""
        self.timezone = ""
        self.dns_name = ""
        self.tracert = ""  # TODO
        if hasattr(parsed_request, 'path'):
            self.path = parsed_request.path
        if parsed_request.command is not None:
            self.command = parsed_request.command
        if hasattr(parsed_request, 'request_version'):
            self.version = parsed_request.request_version
        if hasattr(parsed_request, 'headers'):
            self.headers = parsed_request.headers
            if 'user-agent' in parsed_request.headers:
                self.ua = parsed_request.headers['user-agent']
        self.isDetected = is_detected
        self.hostname = hostname
        location = geolite2.lookup(ip)
        if location is not None:
            self.country = location.country
            self.continent = location.continent
            self.timezone = location.timezone
        try:
            self.dns_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            pass

    def __str__(self) -> str:
        if self.path != "":
            output = ("hostname: " + self.hostname + "\r\n"
                      "IP: " + self.ip + "\r\n"
                      "timestamp: " + self.timestamp + "\r\n"
                      "User-Agent: " + self.ua + "\r\n"
                      "datected: " + str(self.isDetected) + "\r\n"
                      "path: " + self.path + "\r\n"
                      "command: " + self.command + "\r\n"
                      "version: " + self.version + "\r\n"
                      "country: " + self.country + "\r\n")
            if self.isDetected != 4294967295 - 3:
                output += "Detected: Yes" + "\r\n"
            else:
                output += "Detected: No" + "\r\n"
        else:
            output = ("hostname: " + self.hostname + "\r\n"
                      "IP: " + self.ip + "\r\n"
                      "timestamp: " + self.timestamp + "\r\n"
                      "raw_request: " + self.raw_request
                      "country: " + self.country + "\r\n")
        return output

    def __repr__(self) -> str:
        return self.__str__()
