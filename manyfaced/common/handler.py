from abc import ABC, abstractmethod
from typing import Any, Dict

from common.myenc import AESCipher
import json


class RequestHandler(ABC):
    def __init__(self, args: Any, update_event: Any):
        self.args = args
        self.update_event = update_event
        
    @abstractmethod
    def handle_request(self, message: str) -> Any:
        request = self.parse_message(message)
        decrypted = self.decrypt_message(request)
        data = self.parse_json(decrypted)
        
        response = self.process_request(data)
        return response

    @abstractmethod
    def parse_message(self, message: str) -> Any:
        raise NotImplementedError("Subclasses should implement this method.")

    def decrypt_message(self, request: Any) -> str:
        key = self.get_key(request[0])
        decipher = AESCipher(key)
        return decipher.decrypt(request[1])

    def parse_json(self, decrypted_data: str) -> Dict[str, Any]:
        try:
            data = json.loads(decrypted_data.decode('utf-8'))
            return data
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid JSON format: {e}")

    @abstractmethod
    def process_request(self, data: Dict[str, Any]) -> Any:
        raise NotImplementedError("Subclasses should implement this method.")

    @abstractmethod
    def get_key(self, identifier: str) -> str:
        raise NotImplementedError("Subclasses should implement this method.")
