import socket
from geoip import geolite2


class BearStorage():
    def __init__(self, ip, rawrequest, timestamp, parsed_request, isDetected,
                 hostname):
        self.ip = ip
        self.rawrequest = rawrequest
        self.timestamp = timestamp
        if hasattr(parsed_request, 'path'):
            self.path = parsed_request.path
        else:
            self.path = ""
        if parsed_request.command is not None:
            self.command = parsed_request.command
        else:
            self.command = ""
        if hasattr(parsed_request, 'request_version'):
            self.version = parsed_request.request_version
        else:
            self.version = ""
        if hasattr(parsed_request, 'headers'):
            self.headers = parsed_request.headers
            if 'User-Agent' in parsed_request.headers.keys():
                self.ua = parsed_request.headers['User-Agent']
            else:
                self.ua = ""
        else:
            self.headers = ""
            self.ua = ""
            self.version = ""
        self.isDetected = isDetected
        self.hostname = hostname
        location = geolite2.lookup(ip)
        if location is not None:
            self.country = location.country
            self.continent = location.continent
            self.timezone = location.timezone
        else:
            self.country = ''
            self.continent = ''
            self.timezone = ''
        self.tracert = ""  # TODO
        try:
            self.dnsname = socket.gethostbyaddr(ip)[0]
        except:
            self.dnsname = ""

    def __str__(self):
        if self.path is not "":
            output = "hostname: " + self.hostname + "\r\n"
            output += "IP: " + self.ip + "\r\n"
            output += "timestamp: " + self.timestamp + "\r\n"
            output += "User-Agent: " + self.ua + "\r\n"
            output += "path: " + self.path + "\r\n"
            output += "command: " + self.command + "\r\n"
            output += "version: " + self.version + "\r\n"
            output += "country: " + self.country + "\r\n"
            if self.isDetected:
                output += "Detected: Yes" + "\r\n"
            else:
                output += "Detected: No" + "\r\n"
        else:
            output = "hostname: " + self.hostname + "\r\n"
            output += "IP: " + self.ip + "\r\n"
            output += "timestamp: " + self.timestamp + "\r\n"
            output += "rawrequest: " + self.rawrequest
            output += "country: " + self.country + "\r\n"
        return output

    def __repr__(self):
        return self.__str__()
