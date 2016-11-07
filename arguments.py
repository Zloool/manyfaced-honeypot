import argparse
import sys

import settings

"""
usage: mfh.py [-h] [-c | --client [PORT]] [-s | --server [PORT]] [-u] [-v]

Serve some sweet honey to the ubiquitous bots!

optional arguments:
  -h, --help       show this help message and exit
  -c               launch client with on port defined in settings
  --client [PORT]  port to start a client on
  -s               launch server with on port defined in settings
  --server [PORT]  port to start a server on
  -u, --updater    enable self updating
  -v, --verbose    increase output verbosity

And that`s how you`d detect a sneaky chinese bot.
"""


def parse():
    parser = argparse.ArgumentParser(
        description='Serve some sweet honey to the ubiquitous bots!',
        epilog='And that`s how you`d detect a sneaky chinese bot.',
        prog='mfh.py',
        )

    parser.add_argument(
        '-c',
        '--client',
        const=settings.HONEYPORT,
        help='port to start a CLIENT on',
        metavar='PORT',
        nargs='?',
        type=int,
        )

    parser.add_argument(
        '-s',
        '--server',
        const=settings.HIVEPORT,
        help='port to start a SERVER on',
        metavar='PORT',
        nargs='?',
        type=int,
        )

    parser.add_argument(
        '-u',
        '--updater',
        action='store_true',
        help='enable self updating',
        )

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='increase output verbosity',
        )
    if len(sys.argv[1:]) == 0:
        parser.print_usage()
        parser.exit()
    return parser.parse_args()
