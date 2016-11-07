import socket
from geoip import geolite2


class BearStorage():
    def __init__(self, ip, rawrequest, timestamp, parsed_request, isDetected,
                 hostname):
        self.ip = ip  # String
        self.rawrequest = rawrequest  # String
        self.timestamp = timestamp  # Datetime
        if hasattr(parsed_request, 'path'):
            self.path = parsed_request.path  # String
        else:
            self.path = ""
        if hasattr(parsed_request, 'command'):
            self.command = parsed_request.command  # String
        else:
            self.command = ""
        if hasattr(parsed_request, 'request_version'):
            self.version = parsed_request.request_version  # String
        else:
            self.version = ""
        if hasattr(parsed_request, 'headers'):
            self.headers = parsed_request.headers  # Dictionary
        else:
            self.headers = ""
        if 'User-Agent' in parsed_request.headers.keys():
            self.ua = parsed_request.headers['User-Agent']  # Dictionary
        else:
            self.ua = ""
        self.isDetected = isDetected  # Bool
        self.hostname = hostname  # Bool
        location = geolite2.lookup(ip)
        if location is not None:
            self.country = location.country  # String
            self.continent = location.continent  # String
            self.timezone = location.timezone  # String
        else:
            self.country = ''
            self.continent = ''
            self.timezone = ''
        self.tracert = ""  # TODO
        try:
            self.dnsname = socket.gethostbyaddr(ip)[0]  # String
        except:
            self.dnsname = ""

    def __str__(self):
        output = "hostname: " + self.hostname + "\r\n"
        output += "IP: " + self.ip + "\r\n"
        # output += "rawrequest: " + self.rawrequest + "\r\n"
        output += "timestamp: " + self.timestamp + "\r\n"
        output += "User-Agent: " + self.ua + "\r\n"
        output += "path: " + self.path + "\r\n"
        output += "command: " + self.command + "\r\n"
        output += "version: " + self.version + "\r\n"
        # output += "headers: " + str(self.headers) + "\r\n"
        output += "country: " + self.country + "\r\n"
        output += "continent: " + self.continent + "\r\n"
        output += "timezone: " + self.timezone + "\r\n"
        if self.isDetected:
            output += "Detected: Yes" + "\r\n"
        else:
            output += "Detected: No" + "\r\n"
        return output

    def __repr__(self):
        return self.__str__()

# import subprocess
# host = 'www.microsoft.com'
# p = subprocess.Popen(["tracert", '-d', '-w', '100', host],
#                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
# while True:
#     line = p.stdout.readline()
#     if not line:
#         break
#     print '-->', line,
# p.wait()
