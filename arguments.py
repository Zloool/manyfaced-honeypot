import argparse
import sys

import settings

"""
usage: mfh.py [-h] [-c [PORT]] [-s [PORT]] [-u] [-v]

Serve some sweet honey to the ubiquitous bots!

optional arguments:
  -h, --help     show this help message and exit
  -c [PORT]      port to start a CLIENT on
  -s [PORT]      port to start a SERVER on
  -u             enable self updating
  -v, --verbose  increase output verbosity

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
        const=settings.HONEYPORT,
        dest='client',
        help='port to start a CLIENT on',
        metavar='PORT',
        nargs='?',
        type=int,
        )

    parser.add_argument(
        '-s',
        const=settings.HIVEPORT,
        dest='server',
        help='port to start a SERVER on',
        metavar='PORT',
        nargs='?',
        type=int,
        )

    parser.add_argument(
        '-u',
        action='store_true',
        dest='updater',
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
