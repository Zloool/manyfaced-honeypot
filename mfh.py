import os
import sys
import time
from multiprocessing import Process, Event

import mfhclient
import update
from arguments import parse
from settings import HONEYPORT


def main():
    update_event = Event()
    mfhclient_process = Process(
        args=(args, update_event,),
        name="mfhclient_process",
        target=mfhclient.main,
        )
    if args.client is not None:
        mfhclient_process.start()
    trigger_process = Process(
        args=(update_event,),
        name="trigger_process",
        target=update.trigger,
        )
    trigger_process.start()
    trigger_process.join()
    while mfhclient_process.is_alive():
        time.sleep(5)
    else:
        update.pull("origin", "master")
        sys.stdout.flush()
        os.execl(sys.executable, sys.executable, *sys.argv)

if __name__ == '__main__':
    # Parse arguments
    args = parse()
    if args.c:
        args.client = HONEYPORT
    main()
