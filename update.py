import subprocess


def pull(repo, branch):
    subprocess.call(("git", "pull", repo, branch))
    subprocess.call(("pip", "install", "-r", "requirements.txt"))
