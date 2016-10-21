import datetime
import time


def trigger(updateq):
    current_time = datetime.datetime.now()
    delta = datetime.timedelta(seconds=10)
    while True:
        time.sleep(10)
        current_time += delta
        updateq.put("update")
