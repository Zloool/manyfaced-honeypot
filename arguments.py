import argparse

from settings import HONEYPORT


def parse():
    parser = argparse.ArgumentParser(
            description='Serve some sweet honey to the ubiquitous bots!',
            epilog='And that`s how you`d detect a sneaky chinese bot.',
            prog='arguments.py',
        )
    parser.add_argument(
            'port',
            default=HONEYPORT,
            help='port to start a listener on (default: %(default)s, %(type)s)',
            nargs='?',
            type=int,
        )
    parser.add_argument(
            '-v',
            '--verbose',
            action='store_true',
            help='increase output verbosity',
        )

    return parser.parse_args()
