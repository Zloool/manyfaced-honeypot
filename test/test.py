from manyfaced.client import client, faces
from pathlib import Path
import sys
from shutil import copyfile


settings_dst = Path(sys.path[0]).parent / "manyfaced-honeypot" / "manyfaced" / "common" / "settings.py"
settings_src = settings_dst.with_suffix(".example")

if not settings_dst.exists():
    copyfile(settings_src, settings_dst)





def test_gethoney():
    test_face = faces.faces['/']
    client.honey_generic(test_face)
    pass
