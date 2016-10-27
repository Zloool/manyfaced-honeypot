import argparse

from settings import HONEYPORT

"""
usage: mfh.py [-h] [-c | --client [PORT]] [-u] [-v]

Serve some sweet honey to the ubiquitous bots!

optional arguments:
  -h, --help       show this help message and exit
  -c               launch client with on port defined in settings
  --client [PORT]  port to start a client on
  -u, --updater    enable self updating
  -v, --verbose    increase output verbosity
"""


def parse():
    parser = argparse.ArgumentParser(
        description='Serve some sweet honey to the ubiquitous bots!',
        epilog='And that`s how you`d detect a sneaky chinese bot.',
        prog='mfh.py',
        )

    client_group = parser.add_mutually_exclusive_group()

    client_group.add_argument(
        '-c',
        action='store_true',
        help='launch client with on port defined in settings',
        )

    client_group.add_argument(
        '--client',
        help='port to start a client on',
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

    return parser.parse_args()
