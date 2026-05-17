import sys

SRC_CAP = 400
TEST_CAP = 600


def main(paths: list[str]) -> int:
    failed = False
    for path in paths:
        norm = path.replace('\\', '/')
        cap = TEST_CAP if norm.startswith('test/') else SRC_CAP
        with open(path, 'rb') as f:
            n = sum(1 for _ in f)
        if n > cap:
            print(f'{path}: {n} lines exceeds cap of {cap}')
            failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
