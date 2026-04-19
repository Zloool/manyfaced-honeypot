import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESCipher(object):
    """
    Code from
    http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    """

    BLOCK_SIZE = 16

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = os.urandom(self.BLOCK_SIZE)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ct = encryptor.update(raw) + encryptor.finalize()
        return base64.b64encode(iv + ct)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[: self.BLOCK_SIZE]
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        pt = decryptor.update(enc[self.BLOCK_SIZE :]) + decryptor.finalize()
        return self._unpad(pt)

    def _pad(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        pad_len = self.bs - len(s) % self.bs
        return s + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(s):
        pad_len = s[-1]
        return s[:-pad_len]
