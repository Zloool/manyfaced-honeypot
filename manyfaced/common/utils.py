import time
import pickle
from socket import error as socket_error

from .status import CLIENT_TIMEOUT


def dump_file(data):
    try:
        with open('temp.db') as f:
            string_file = f.read()
        db = pickle.loads(string_file)
    except:
        db = list()
    db.append(data)
    with open('temp.db', "w") as f:
        f.write(str(pickle.dumps(db)))


def receive_timeout(the_socket, timeout=CLIENT_TIMEOUT):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = []

    # beginning time
    begin = time.time()
    while True:
        # if you got some data, then break after timeout
        if total_data and time.time() - begin > timeout:
            break

        # if you got no data at all, wait a little longer, twice the timeout
        elif time.time() - begin > timeout * 2:
            break

        # recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                # change the beginning time for measurement
                begin = time.time()
            else:
                # sleep for sometime to indicate a gap
                time.sleep(0.1)
        except socket_error:
            pass

    # join all parts to make final string
    res = ""
    for frame in total_data:
        res += frame.decode()
    return res
