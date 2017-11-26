import os
import subprocess
import sys
import time
from shutil import copyfile
from multiprocessing import Process, Event

if not os.path.isfile(sys.path[0] + "/common/settings.py"):
        copyfile(sys.path[0] + "/common/settings.py.example",
                 sys.path[0] + "/common/settings.py")
from .client import client
from .server import server
from .common.update import trigger, pull
from .common.arguments import parse


def main():
    update_event = Event()
    if args.client is not None:
        client_proc = Process(
            args=(args, update_event,),
            name="client",
            target=client.main,
        )
        client_proc.start()
    if args.server is not None:
        server_proc = Process(
            args=(args, update_event,),
            name="server",
            target=server.main,
        )
        server_proc.start()
    if args.updater:
        trigger_proc = Process(
            args=(update_event,),
            name="trigger",
            target=trigger,
        )
        trigger_proc.start()
        trigger_proc.join()
    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            if 'client_proc' in locals():
                if client_proc.is_alive():
                    client_proc.terminate()
                    client_proc.join()
            if 'server_proc' in locals():
                if server_proc.is_alive():
                    server_proc.terminate()
                    server_proc.join()
            if 'trigger_proc' in locals():
                if trigger_proc.is_alive():
                    trigger_proc.terminate()
                    server_proc.join()
            break
    else:
        if args.updater:
            pull("origin", "master")
            sys.stdout.flush()
            os.execl(sys.executable, sys.executable, *sys.argv)

if __name__ == '__main__':
    # Parse arguments
    args = parse()
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
