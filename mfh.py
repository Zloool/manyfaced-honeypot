import mfhclient
import os
import Queue
import sys
import threading
import trigger
import update


def main():
    q = Queue.Queue()
    updateq = Queue.Queue()
    mfhclient_thread = threading.Thread(
        args=(q,),
        name="mfhclient_thread",
        target=mfhclient.main,
        )
    mfhclient_thread.start()
    trigger_thread = threading.Thread(
        args=(updateq,),
        name="trigger_thread",
        target=trigger.trigger,
        )
    trigger_thread.start()
    count = 0
    while True:
        if updateq.empty() and updateq.get() == "update":
            q.put("quit")
        if not mfhclient_thread.is_alive():
            updater_thread = threading.Thread(
                args=("origin", "master"),
                name="updater_thread",
                target=update.pull,
                )
            updater_thread.start()
            updater_thread.join()
            sys.stdout.flush()
            os.execl(sys.executable, sys.executable, *sys.argv)
        count += 1

if __name__ == '__main__':
    main()
