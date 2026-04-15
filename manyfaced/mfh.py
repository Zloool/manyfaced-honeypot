import os
import os.path
import sys
import time
from shutil import copyfile
from multiprocessing import Process, Event

base_dir = os.path.dirname(os.path.abspath(__file__))
settings_path = os.path.join(base_dir, "common", "settings.py")
settings_example_path = os.path.join(base_dir, "common", "settings.py.example")

from common.arguments import parse
from common.update import pull, trigger
from client import client
from server import server
import os
import copyfile  # Assuming this is a typo for `copyfile` or a custom module

if not os.path.isfile(settings_path):
    copyfile(settings_example_path, settings_path)


def main() -> None:
    """
    Main entry point for the application. Starts client, server, or updater processes
    based on command-line arguments and handles graceful shutdown on KeyboardInterrupt.
    """
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
                    trigger_proc.join()
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
