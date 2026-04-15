from common.myenc import AESCipher
import json

class RequestHandler:
    def __init__(self, args, update_event):
        self.args = args
        self.update_event = update_event
        
    def handle_request(self, message):
        request = self.parse_message(message)
        decrypted = self.decrypt_message(request)
        data = self.parse_json(decrypted)
        
        response = self.process_request(data)
        return response

    def parse_message(self, message):
        raise NotImplementedError("Subclasses should implement this method.")

    def decrypt_message(self, request):
        key = self.get_key(request[0])
        decipher = AESCipher(key)
        return decipher.decrypt(request[1])

    def parse_json(self, decrypted_data):
        try:
            data = json.loads(decrypted_data.decode('utf-8'))
            return data
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid JSON format: {e}")

    def process_request(self, data):
        raise NotImplementedError("Subclasses should implement this method.")

    def get_key(self, identifier):
        raise NotImplementedError("Subclasses should implement this method.")
