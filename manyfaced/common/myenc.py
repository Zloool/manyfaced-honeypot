import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESCipher(object):
    """AES-256-GCM encrypt/decrypt.

    Wire format (after base64 encoding):
        nonce(12 bytes) || ciphertext || tag(16 bytes)

    Key derivation: SHA-256(password) → 32 bytes
    """

    NONCE_LEN = 12
    TAG_LEN = 16

    def __init__(self, key: str):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: bytes) -> str:
        """Encrypt *raw* bytes. Returns base64(nonce || ciphertext || tag)."""
        nonce = os.urandom(self.NONCE_LEN)
        aesgcm = AESGCM(self.key)
        # AAD is empty; ciphertext includes the 16-byte GCM tag appended
        ct_with_tag = aesgcm.encrypt(nonce, raw, None)
        return base64.b64encode(nonce + ct_with_tag).decode("ascii")

    def decrypt(self, enc: str) -> bytes:
        """Decrypt a base64-encoded GCM message. Returns plaintext bytes."""
        raw = base64.b64decode(enc)
        nonce = raw[: self.NONCE_LEN]
        ct_with_tag = raw[self.NONCE_LEN :]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ct_with_tag, None)
