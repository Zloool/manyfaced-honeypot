from manyfaced.client import faces
from manyfaced.client import client


def test_gethoney():
    test_face = faces.faces['/']
    response = client.honey_generic(test_face)
    pass
