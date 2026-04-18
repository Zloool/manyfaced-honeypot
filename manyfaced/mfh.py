import os
import os.path
import signal
import sys
import time
from multiprocessing import Event, Process
from shutil import copyfile

from common.arguments import parse
from common.update import pull, trigger
from manyfaced.client import client
from manyfaced.server import server

base_dir = os.path.dirname(os.path.abspath(__file__))
settings_path = os.path.join(base_dir, "common", "settings.py")
settings_example_path = os.path.join(base_dir, "common", "settings.py.example")

PROC_KEYS = ("client_proc", "server_proc", "terminate_proc")


def _terminate(proc):
    if proc is not None and proc.is_alive():
        proc.terminate()
        proc.join()


def _start_processes(args, update_event):
    procs = {key: None for key in PROC_KEYS}
    if args.client is not None:
        procs["client_proc"] = Process(
            args=(args, update_event),
            name="client",
            target=client.main,
        )
        procs["client_proc"].start()
    if args.server is not None:
        procs["server_proc"] = Process(
            args=(args, update_event),
            name="server",
            target=server.main,
        )
        procs["server_proc"].start()
    if args.updater:
        procs["terminate_proc"] = Process(
            args=(update_event,),
            name="trigger",
            target=trigger,
        )
        procs["terminate_proc"].start()
        procs["terminate_proc"].join()
    return procs


def main(args) -> None:
    """
    Main entry point for the application. Starts client, server, or updater processes
    based on command-line arguments and handles graceful shutdown on KeyboardInterrupt.
    """
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    update_event = Event()
    procs = _start_processes(args, update_event)

    try:
        while not update_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        for key in PROC_KEYS:
            _terminate(procs[key])
    finally:
        update_event.set()
        for key in PROC_KEYS:
            _terminate(procs[key])


def _update_and_restart():
    pull("origin", "master")
    sys.stdout.flush()
    os.execl(sys.executable, sys.executable, *sys.argv)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(base_dir))
    args = parse()

    if settings_example_path and not os.path.isfile(settings_path):
        copyfile(settings_example_path, settings_path)

    if args.updater:
        _update_and_restart()

    try:
        main(args)
    except KeyboardInterrupt:
        sys.exit(0)
