"""manyfaced – Multi-faced honeypot entry point."""

from __future__ import annotations

import os
import sys
import time
import logging

# fcntl is POSIX-only (absent on Windows). The lockfile feature relies on it,
# so import it defensively and degrade gracefully where it's unavailable.
try:  # pragma: no cover - platform branch
    import fcntl
except ImportError:  # pragma: no cover - platform branch
    fcntl = None  # type: ignore[assignment]
from multiprocessing import Event, Process

from manyfaced.common.logging_setup import setup_logging

from manyfaced.common.config import Config, settings, validate_secrets  # noqa: F401  (settings/Config re-exported for tests; importing no longer triggers secret validation)


logger = logging.getLogger(__name__)

_lock_fd = None

# Supervision tuning for the child-restart loop (see run()). Hoisted to module
# scope so they can be overridden in tests.
_BACKOFF_BASE = 1.0
_BACKOFF_MAX = 30.0
_MAX_RESTARTS_PER_WINDOW = 10
_RESTART_WINDOW_SEC = 60.0


def _acquire_lockfile():
    """Acquire an exclusive lockfile to prevent multiple instances.

    Uses fcntl.flock() for atomic lock acquisition. If the lock is already
    held (another instance running), exits with an error.
    """
    # Lazily import settings so this module-level helper can see it without
    # requiring the deferred import inside run() to have executed first.
    from manyfaced.common.config import settings

    global _lock_fd
    if fcntl is None:
        # Non-POSIX platform (e.g. Windows dev box): lockfile enforcement is
        # unavailable. Skip multi-instance prevention rather than crashing.
        logger.warning('Lockfile enforcement unavailable (fcntl missing on this platform)')
        return
    try:
        os.makedirs(os.path.dirname(settings.LOCKFILE), exist_ok=True)
        _lock_fd = open(settings.LOCKFILE, 'w')
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd.write(str(os.getpid()))
        _lock_fd.flush()
        # NOTE: the fd is intentionally kept open (not closed here) so the
        # fcntl lock stays held for the process lifetime — closing it would
        # release the lock on Linux and defeat multi-instance prevention.
        # It is closed in _release_lockfile() at shutdown.
        logger.info('Lockfile acquired (PID %d)', os.getpid())
    except (IOError, OSError) as e:
        if 'Text file busy' in str(e) or 'Resource temporarily unavailable' in str(e):
            logger.error('Another instance is already running (lockfile held)')
            sys.exit(1)
        raise


def _release_lockfile():
    """Release the lockfile and clean up."""
    from manyfaced.common.config import settings

    global _lock_fd
    if _lock_fd is not None:
        if fcntl is not None:
            try:
                fcntl.flock(_lock_fd, fcntl.LOCK_UN)
                _lock_fd.close()
                os.unlink(settings.LOCKFILE)
                logger.info('Lockfile released')
            except (IOError, OSError):
                logger.debug('swallowed exception', exc_info=True)
        _lock_fd = None


def run() -> None:
    """CLI entry point – called by the ``manyfaced`` console_scripts command."""
    # Parse args first to check for --generate-config before importing settings
    from manyfaced.common.arguments import parse

    args = parse()

    # --generate-config: create config file and exit (no secrets required)
    # (Config is available at module level)
    if args.generate_config:
        cfg = Config.load(validate_secrets=False)
        path = cfg.generate_config_file()
        print(f'[manyfaced] Generated config at {path}', file=sys.stderr)
        return

    # Normal startup: NOW validate that required secrets are present. This is
    # deferred to here (not module import) so --generate-config can run without
    # secrets (issue #177). validate_secrets() raises ConfigValidationError if
    # HIVEPASS / DEFAULT_KEY are missing.
    validate_secrets()

    # settings/Config are imported at module level (see top of file). Using the
    # module-level names (rather than re-importing here) lets tests patch
    # manyfaced.mfh.settings / .Config. Importing the names does not trigger
    # secret validation; only attribute access does (and --generate-config
    # returns before touching settings).

    # Initialise system-wide logging early
    setup_logging(level='DEBUG', log_file=settings.LOG_FILE)

    # Acquire lockfile to prevent multiple instances
    _acquire_lockfile()

    # Auto-generate XDG config file if none exists (always uses Config.generate_config_file)
    xdg_config = os.path.join(
        os.environ.get('XDG_CONFIG_HOME', os.path.join(os.path.expanduser('~'), '.config')),
        'manyfaced',
        'config.toml',
    )
    if not os.path.isfile(xdg_config):
        new_cfg = Config.load()
        path = new_cfg.generate_config_file(xdg_config)
        print(
            f'[manyfaced] Generated config at {path} – edit it to customize.',
            file=sys.stderr,
        )

    from manyfaced.client import client
    from manyfaced.server import server

    args = parse()

    # Auto-detect: if neither -c nor -s specified, start both based on config
    if args.client is None and args.server is None:
        args.client = settings.HONEYPORT
        args.server = settings.HIVEPORT
        # Also apply port_mode and top_ports from config when starting client
        if (
            getattr(args, 'port_mode', 'single') == 'single'
            and settings.HONEY_PORT_MODE != 'single'
        ):
            args.port_mode = settings.HONEY_PORT_MODE
            if settings.HONEY_TOP_PORTS:
                args.top_ports = settings.HONEY_TOP_PORTS
        logger.info(
            'No CLI args specified — starting client on port %d, server on port %d',
            args.client,
            args.server,
        )

    # --generate-config: create config file and exit
    if args.generate_config:
        cfg = Config.load()
        path = cfg.generate_config_file()
        print(f'[manyfaced] Generated config at {path}', file=sys.stderr)
        return

    update_event = Event()

    procs: dict[str, Process | None] = {
        'client_proc': None,
        'server_proc': None,
        'dashboard_proc': None,
    }

    def _spawn_client() -> Process:
        return Process(args=(args, update_event), name='client', target=client.main)

    def _spawn_server() -> Process:
        return Process(args=(args, update_event), name='server', target=server.main)

    def _spawn_dashboard() -> Process:
        from manyfaced.web import dashboard

        return Process(args=(args, update_event), name='dashboard', target=dashboard.run_dashboard)

    def _terminate(proc: Process | None) -> None:
        if proc is not None and proc.is_alive():
            proc.terminate()
            proc.join()

    if args.client is not None:
        procs['client_proc'] = _spawn_client()
        procs['client_proc'].start()

    if args.server is not None:
        procs['server_proc'] = _spawn_server()
        procs['server_proc'].start()

    # Dashboard (issue #234): read-only stats view. Runs alongside the server
    # (it reads the shared DB) only when explicitly enabled in config.
    if args.server is not None and getattr(settings, 'DASHBOARD_ENABLED', False):
        procs['dashboard_proc'] = _spawn_dashboard()
        procs['dashboard_proc'].start()

    # NOTE: we deliberately do NOT ignore SIGCHLD. The parent supervises its
    # children and restarts any that exit unexpectedly (see loop below). If a
    # child dies (e.g. the server / DB-writer crashes) and is left unrestarted,
    # the client keeps capturing bots but can never deliver reports, so
    # recording goes silently silent while the service still reports "active".
    # Supervision with exponential backoff + a crash-loop guard. A child that
    # dies on startup would otherwise be restarted every ~1s forever, spawning a
    # fresh process each second and bypassing systemd's Restart=on-failure (the
    # parent stays alive, so systemd never sees a unit failure). Instead we back
    # off between restarts and, if a child keeps dying, fail the whole service
    # so systemd escalates recovery (and its own alerting can fire).
    supervise: dict[str, dict] = {
        key: {'attempts': 0, 'last': 0.0, 'times': []}
        for key in ('client_proc', 'server_proc', 'dashboard_proc')
    }

    def _maybe_restart(key: str, spawn) -> None:
        st = supervise[key]
        now = time.time()
        # Still cooling down after the previous restart — wait this round.
        backoff = min(_BACKOFF_BASE * (2 ** st['attempts']), _BACKOFF_MAX)
        if st['last'] and now - st['last'] < backoff:
            return
        # Crash-loop guard: give up once the child has been restarted too many
        # times since its last healthy run, so systemd's Restart=on-failure (and
        # its alerting) takes over. We count cumulative `attempts` (reset to 0
        # whenever the child is observed healthy in the supervise loop above),
        # NOT a sliding time window — once backoff saturates at _BACKOFF_MAX the
        # window can never accumulate enough timestamps to trip the cap, so a
        # continuously-crashing child would restart forever (#222).
        if st['attempts'] >= _MAX_RESTARTS_PER_WINDOW:
            logger.critical(
                'Child %s restarted %d times since last healthy run — giving up so systemd can recover',
                key,
                st['attempts'],
            )
            sys.exit(1)
        logger.warning(
            '%s child exited unexpectedly -- restarting (attempt %d)', key, st['attempts'] + 1
        )
        new_proc = spawn()
        new_proc.start()
        procs[key] = new_proc
        st['attempts'] += 1
        st['last'] = now
        st['times'].append(now)

    try:
        while not update_event.is_set():
            # Supervise children: restart any that have exited. A dead server
            # child means reports can't be persisted; a dead client child means
            # no bots are captured. Either way we must recover without a full
            # service restart (which Restart=on-failure would otherwise miss,
            # since the parent process itself stays alive). A child that is
            # healthy resets its restart bookkeeping so the crash-loop guard
            # only counts sustained failures.
            if args.client is not None:
                if procs['client_proc'] is not None and procs['client_proc'].is_alive():
                    supervise['client_proc'] = {'attempts': 0, 'last': 0.0, 'times': []}
                elif procs['client_proc'] is None or not procs['client_proc'].is_alive():
                    _maybe_restart('client_proc', _spawn_client)
            if args.server is not None:
                if procs['server_proc'] is not None and procs['server_proc'].is_alive():
                    supervise['server_proc'] = {'attempts': 0, 'last': 0.0, 'times': []}
                elif procs['server_proc'] is None or not procs['server_proc'].is_alive():
                    _maybe_restart('server_proc', _spawn_server)
            if args.server is not None and getattr(settings, 'DASHBOARD_ENABLED', False):
                if procs['dashboard_proc'] is not None and procs['dashboard_proc'].is_alive():
                    supervise['dashboard_proc'] = {'attempts': 0, 'last': 0.0, 'times': []}
                elif procs['dashboard_proc'] is None or not procs['dashboard_proc'].is_alive():
                    _maybe_restart('dashboard_proc', _spawn_dashboard)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        update_event.set()
        for p in procs.values():
            _terminate(p)
        # Gracefully shut down the report thread pool
        from manyfaced.handlers.report_queue import shutdown_report_executor

        shutdown_report_executor()
        # Gracefully drain + shut down the alert-delivery pool so in-flight
        # credential-capture alerts aren't killed mid-send on restart (#216).
        from manyfaced.common.alerting import shutdown_alert_executor

        shutdown_alert_executor()
        # Release lockfile
        _release_lockfile()


if __name__ == '__main__':
    run()
