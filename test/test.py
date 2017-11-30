import os
import sys
from socket import error as socket_error
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from shutil import copyfile


if not os.path.isfile(os.path.join(os.path.split(sys.path[0])[0], "manyfaced-honeypot", "manyfaced", "common", "settings.py")):
    copyfile(os.path.join(os.path.split(sys.path[0])[0], "manyfaced-honeypot", "manyfaced", "common", "settings.py.example"),
             os.path.join(os.path.split(sys.path[0])[0], "manyfaced-honeypot", "manyfaced", "common", "settings.py"))


from manyfaced.client import faces, client
from manyfaced.server import server
from manyfaced.common import settings

def test_gethoney():
    test_face = faces.faces['/pma/']
    response = client.honey_generic(test_face)
    root_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(root_dir, '..', 'manyfaced', 'client', 'responses', test_face)
    with open(path) as file:
        body = file.read()
    print()
    assert body == response.split("\r\n\r\n")[1]
    
def test_communication():
    input_message = "СлучайныхСтрок"
    encrypted_message = client.compile_report(input_message)
    decoded_message = server.decode_report(encrypted_message)
    assert decoded_message == input_message

def test_gethoney_robots():
    robots_packet = client.honey_robots()
    assert len(robots_packet.split("\r\n\r\n")[1]) > 10