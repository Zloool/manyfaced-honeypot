import json
import signal
from abc import ABC, abstractmethod
from multiprocessing import Process, Lock
from socket import error as socket_error

class BaseHandler(ABC):
    def __init__(self, args, update_event):
        self.args = args
        self.update_event = update_event

    def parse_message(self, message):
        request = message.split(":", 1)
        if len(request) != 2:
            raise ValueError("Invalid message format")
        return request

    @abstractmethod
    def get_key(self, identifier):
        pass
        
    def process_request(self, data):
        try:
            self._common_processing(data)
        except Exception as e:
            print(f"Error processing request: {e}")

    def _common_processing(self, data):
        # Common processing logic can be added here
        pass
