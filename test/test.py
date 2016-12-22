import os
import sys
from shutil import copyfile


if not os.path.isfile(os.path.join(os.path.split(sys.path[0])[0], "manyfaced-honeypot", "manyfaced", "common", "settings.py")):
    copyfile(os.path.join(os.path.split(sys.path[0])[0], "manyfaced-honeypot", "manyfaced", "common", "settings.py.example"),
             os.path.join(os.path.split(sys.path[0])[0], "manyfaced-honeypot", "manyfaced", "common", "settings.py"))


from manyfaced.client import faces
from manyfaced.client import client





def test_gethoney():
    test_face = faces.faces['/']
    response = client.honey_generic(test_face)
    pass
