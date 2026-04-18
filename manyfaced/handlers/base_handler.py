import json
from abc import ABC, abstractmethod
from typing import Any, Dict

from manyfaced.common.myenc import AESCipher


class BaseHandler(ABC):
    """Abstract handler. Subclasses implement get_key and process_request."""

    def __init__(self, args: Any, update_event: Any) -> None:
        self.args = args
        self.update_event = update_event

    def handle_request(self, message: str) -> Any:
        """Decrypt and route a message to process_request."""
        request = self.parse_message(message)
        decrypted = self.decrypt_message(request)
        data = self.parse_json(decrypted)
        return self.process_request(data)

    def parse_message(self, message: str):
        request = message.split(":", 1)
        if len(request) != 2:
            raise ValueError("Invalid message format")
        return request

    def decrypt_message(self, request) -> bytes:
        """Decrypt the second part of request using the key for identifier."""
        key = self.get_key(request[0])
        decipher = AESCipher(key)
        return decipher.decrypt(request[1])

    def parse_json(self, decrypted_data: str) -> Dict[str, Any]:
        try:
            data = json.loads(decrypted_data.decode("utf-8"))
            return data
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid JSON format: {e}")

    @abstractmethod
    def get_key(self, identifier) -> str:
        """Return the decryption key for the given bear identifier."""
        ...

    @abstractmethod
    def process_request(self, data: Dict[str, Any]) -> Any:
        """Process decrypted request data. Subclasses must implement."""
        ...

    def _common_processing(self, data: Dict[str, Any]) -> None:
        """Common processing logic. Override in subclasses as needed."""
        pass

    def process_request_safe(self, data: Dict[str, Any]) -> Any:
        """Wrapper that catches exceptions during processing."""
        try:
            self._common_processing(data)
        except Exception as e:
            print(f"Error processing request: {e}")
