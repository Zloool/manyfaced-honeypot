import socket
from geoip import geolite2


class BearStorage():
    def __init__(self, ip, rawrequest, timestamp, parsed_request, isDetected):
        self.ip = ip  # String
        self.rawrequest = rawrequest  # String
        self.timestamp = timestamp  # Datetime
        self.path = parsed_request.path  # String
        self.command = parsed_request.command  # String
        self.version = parsed_request.request_version  # String
        self.headers = parsed_request.headers  # Dictionary
        self.isDetected = isDetected  # Bool
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
