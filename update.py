import subprocess
import sys
import time


def trigger(update_event):
    try:
        time.sleep(3600)
        update_event.set()
    except KeyboardInterrupt:
        sys.exit()


def pull(repo, branch):
    subprocess.call(("git", "pull", repo, branch))
    subprocess.call(("pip", "install", "-r", "requirements.txt"))
