import subprocess
import time


def trigger(update_event):
    time.sleep(3600)
    update_event.set()


def pull(repo, branch):
    subprocess.call(("git", "pull", repo, branch))
    subprocess.call(("pip", "install", "-r", "requirements.txt"))
