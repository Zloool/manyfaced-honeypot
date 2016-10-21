import datetime
import time


def trigger(updateq):
    current_time = datetime.datetime.now()
    delta = datetime.timedelta(hours=1)
    while True:
        time.sleep(3600)
        current_time += delta
        updateq.put("update")
