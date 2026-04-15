# common/process_utils.py
from multiprocessing import Process, Lock

def safe_process_task(lock, target_func, *args):
    """Wrapper for process-safe database/file operations"""
    with lock:
        try:
            target_func(*args)
        except Exception as e:
            # Centralized error handling
            print(f"Process error: {e}")
