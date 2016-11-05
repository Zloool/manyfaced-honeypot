# Echo client program
import socket
import random
import string
import time

HOST = '127.0.0.1'    # The remote host
PORT = 80              # The same port as used by the server
for i in range(1, 10000):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        N = i
        ptr = string.ascii_uppercase + string.digits
        ptr += "!@#$%^&*()_+`-~"
        str = ''.join(random.choice(ptr) for _ in range(N))
        s.sendall(str)
        s.close()
        print str, ':\r\n'  # repr(data)
        time.sleep(0.001)
    except:
        print "babach"
        time.sleep(1)
