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
    if args.client is not None:
        client_proc = create_process("client", client.main, args, update_event)
        client_proc.start()
    if args.server is not None:
        server_proc = create_process("server", server.main, args, update_event)
        server_proc.start()
    if args.updater:
        trigger_proc = create_process("trigger", update.trigger, update_event)
        trigger_proc.start()
        trigger_proc.join()
    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            if 'client_proc' in locals():
                if client_proc.is_alive():
                    client_proc.terminate()
            if 'server_proc' in locals():
                if server_proc.is_alive():
                    server_proc.terminate()
            if 'trigger_proc' in locals():
                if trigger_proc.is_alive():
                    trigger_proc.terminate()
            break
    else:
        if args.updater:
            update.pull("origin", "master")
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
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
