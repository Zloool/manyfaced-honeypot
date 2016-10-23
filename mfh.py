import os
import sys
import time
from multiprocessing import Process, Event

import mfhclient
import update
from arguments import parse


def main():
    q = Event()
    mfhclient_process = Process(
        args=(args, q,),
        name="mfhclient_process",
        target=mfhclient.main,
        )
    mfhclient_process.start()
    trigger_process = Process(
        args=(q,),
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
    main()
