import os
import subprocess
import sys
import time
from shutil import copyfile
from multiprocessing import Process, Event
from threading import Thread, Event as TEvent
if not os.path.isfile(os.path.join(sys.path[0], "manyfaced", "common", "settings.py")):
        copyfile(os.path.join(sys.path[0], "manyfaced", "common", "settings.py.example"),
                 os.path.join(sys.path[0], "manyfaced", "common", "settings.py"))
from manyfaced.client import client
from manyfaced.server import server
from manyfaced.common.update import trigger, pull
from manyfaced.common.arguments import parse


def main():
    if args.debug is not None:
        run_style = Thread
        update_event = TEvent()
    else:
        run_style = Process
        update_event = Event()
    if args.client is not None:
        client_proc = run_style(
            args=(args, update_event,),
            name="client",
            target=client.main,
        )
        client_proc.start()
    if args.server is not None:
        server_proc = run_style(
            args=(args, update_event,),
            name="server",
            target=server.main,
        )
        server_proc.start()
    # Need to be revised
    #if args.updater:
    #    trigger_proc = RunStyle(
    #        args=(update_event,),
    #        name="trigger",
    #        target=trigger,
    #    )
    #    trigger_proc.start()
    #    trigger_proc.join()
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
