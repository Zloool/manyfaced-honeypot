import pytest
from manyfaced.client.client import honey_generic
import manyfaced.db as db
import manyfaced.server as server
from manyfaced.common import faces


def test_gethoney():
    test_face = faces.faces['/']
    response = honey_generic(test_face)
    pass
