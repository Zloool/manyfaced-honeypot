import os
import sys
from shutil import copyfile

def test_create_config():
    if not os.path.isfile(os.path.join(sys.path[0], "manyfaced", "common", "settings.py")):
        copyfile(os.path.join(sys.path[0], "manyfaced", "common", "settings.py.example"),
                 os.path.join(sys.path[0], "manyfaced", "common", "settings.py"))
    pass

from manyfaced.client import faces
from manyfaced.client import client





def test_gethoney():
    test_face = faces.faces['/']
    response = client.honey_generic(test_face)
    pass
