"""manyfaced – Multi-faced honeypot entry point."""

from __future__ import annotations

import os
import signal
import sys
import time
from multiprocessing import Event, Process


def run() -> None:
    """CLI entry point – called by the ``manyfaced`` console_scripts command."""
    from manyfaced.common.config import settings, Config

    # Auto-generate XDG config file if none exists
    xdg_config = os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config")),
        "manyfaced",
        "config.toml",
    )
    if not os.path.isfile(xdg_config):
        example = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common", "config.toml.example")
        if os.path.isfile(example):
            import shutil
            os.makedirs(os.path.dirname(xdg_config), exist_ok=True)
            shutil.copy2(example, xdg_config)
            print(f"[manyfaced] Generated config at {xdg_config} – edit it to customize.", file=sys.stderr)
        else:
            new_cfg = Config.load()
            new_cfg.generate_config_file(xdg_config)
            print(f"[manyfaced] Generated config at {xdg_config} – edit it to customize.", file=sys.stderr)

    from manyfaced.common.arguments import parse
    from manyfaced.client import client
    from manyfaced.server import server

    args = parse()
    update_event = Event()

    procs: dict[str, Process | None] = {"client_proc": None, "server_proc": None, "terminate_proc": None}

    def _terminate(proc: Process | None) -> None:
        if proc is not None and proc.is_alive():
            proc.terminate()
            proc.join()

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
        from manyfaced.common.update import pull, trigger

        procs["terminate_proc"] = Process(args=(update_event,), name="trigger", target=trigger)
        procs["terminate_proc"].start()
        procs["terminate_proc"].join()
        pull("origin", "master")
        sys.stdout.flush()
        os.execl(sys.executable, sys.executable, *sys.argv)

    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    try:
        while not update_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        update_event.set()
        for p in procs.values():
            _terminate(p)


if __name__ == "__main__":
    run()
