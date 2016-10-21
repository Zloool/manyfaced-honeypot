import datetime
import time


def trigger(updateq):
    current_time = datetime.datetime.now()
    delta = datetime.timedelta(hours=1)
    while True:
        time.sleep(10)
        current_time += delta
        updateq.put("update")
