import os
import sys
import time

from multiprocessing import Process, Event

import mfhclient
import server
import update

from arguments import parse
from settings import HONEYPORT, HIVEPORT


def main():
    update_event = Event()
    client = create_process("client", mfhclient.main, args, update_event)
    serv = create_process("server", server.main, args, update_event)
    if args.client is not None:
        client.start()
    if args.client is not None:
        serv.start()
    if args.updater:
        trigger = create_process("trigger", update.trigger, update_event)
        trigger.start()
        trigger.join()
    while client.is_alive() or serv.is_alive():
        time.sleep(5)
    else:
        if args.updater:
            update.pull("origin", "master")
            sys.stdout.flush()
            os.execl(sys.executable, sys.executable, *sys.argv)


def create_process(name, function,  *arguments):
    process = Process(
        args=arguments,
        name="{0}_process".format(name),
        target=function,
        )
    return process

if __name__ == '__main__':
    # Parse arguments
    args = parse()
    if args.c:
        args.client = HONEYPORT
    if args.s:
        args.server = HIVEPORT
    processes = {}
    main()
