import socket
from geoip import geolite2


class BearStorage:
    def __init__(self, ip, raw_request, timestamp, parsed_request, is_detected,
                 hostname, port):
        self.ip = ip
        self.port = port
        self.raw_request = raw_request
        self.timestamp = timestamp
        self.path = ""
        self.command = ""
        self.version = ""
        self.ua = ""
        self.headers = ""
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
        #location = geolite2.lookup(ip)
        #if location is not None:
        #    self.country = location.country
        #    self.continent = location.continent
        #    self.timezone = location.timezone
        try:
            self.dns_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            pass

    def __str__(self):
        output = "hostname: " + self.hostname + "\r\n"
        output += "IP: " + self.ip + "\r\n"
        output += "port: " + self.port + "\r\n"
        output += "timestamp: " + self.timestamp + "\r\n"
        if self.path is not "":
            output += "User-Agent: " + self.ua + "\r\n"
            output += "datected: " + str(self.isDetected) + "\r\n"
            output += "path: " + self.path + "\r\n"
            output += "command: " + self.command + "\r\n"
            output += "version: " + self.version + "\r\n"
            output += "country: " + self.country + "\r\n"
            if self.isDetected != 4294967295 - 3:
                output += "Detected: Yes" + "\r\n"
            else:
                output += "Detected: No" + "\r\n"
        else:
            output += "raw_request: " + self.raw_request
            output += "country: " + self.country + "\r\n"
        return output

    def __repr__(self):
        return self.__str__()
