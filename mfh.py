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
    mfhclient_process = Process(
        args=(args, update_event,),
        name="mfhclient_process",
        target=mfhclient.main,
        )
    server_process = Process(
        args=(args, update_event,),
        name="server_process",
        target=server.main,
        )
    if args.client is not None:
        mfhclient_process.start()
    if args.client is not None:
        server_process.start()
    if args.updater:
        trigger_process = Process(
            args=(update_event,),
            name="trigger_process",
            target=update.trigger,
            )
        trigger_process.start()
        trigger_process.join()
    while mfhclient_process.is_alive() or server_process.is_alive():
        time.sleep(5)
    else:
        if args.updater:
            # update.pull("origin", "master")
            sys.stdout.flush()
            os.execl(sys.executable, sys.executable, *sys.argv)

if __name__ == '__main__':
    # Parse arguments
    args = parse()
    if args.c:
        args.client = HONEYPORT
    if args.s:
        args.server = HIVEPORT
    main()
