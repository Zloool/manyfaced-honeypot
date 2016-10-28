import os
import sys
import time

from multiprocessing import Process, Event

import client
import server
import update

from arguments import parse
from settings import HONEYPORT, HIVEPORT


def main():
    update_event = Event()
    client_proc = create_process("client", client.main, args, update_event)
    server_proc = create_process("server", server.main, args, update_event)
    if args.client is not None:
        client_proc.start()
    if args.client is not None:
        server_proc.start()
    if args.updater:
        trigger = create_process("trigger", update.trigger, update_event)
        trigger.start()
        trigger.join()
    while client_proc.is_alive() or server_proc.is_alive():
        time.sleep(5)
    else:
        if args.updater:
            # update.pull("origin", "master")
            sys.stdout.flush()
            os.execl(sys.executable, sys.executable, *sys.argv)


def create_process(name, function,  *arguments):
    process = Process(
        args=arguments,
        name=name,
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
    main()
