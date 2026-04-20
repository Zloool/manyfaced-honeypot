import sys
import unittest
from pathlib import Path
from shutil import copyfile

from manyfaced.client import client
from manyfaced.client.client import faces

settings_dst = (
    Path(sys.path[0]).parent
    / "manyfaced-honeypot"
    / "manyfaced"
    / "common"
    / "settings.py"
)
settings_src = settings_dst.with_suffix(".example")

if not settings_dst.exists():
    copyfile(settings_src, settings_dst)


def test_gethoney():
    test_face = faces["/"]
    client.honey_generic(test_face)
    pass


if __name__ == "__main__":
    unittest.main()
