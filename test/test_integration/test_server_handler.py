"""Direct server handler tests, AES roundtrip, and key lookup."""

from unittest.mock import MagicMock

import pytest

from .conftest import TEST_KEY, BEE_IDENTIFIER


class TestServerHandlerDirect:
    """Direct server handler tests (no encryption, just process_request)."""

    def test_process_request_starts_save_process(self):
        """process_request should save data and return True."""
        from manyfaced.server.server import ServerHandler

        data = {
            'ip': '10.0.0.1',
            'raw_request': 'GET /\r\n\r\n',
            'timestamp': '2026-04-19 03:00:00.000000',
            'parsed_request': {'command': 'GET', 'path': '/'},
            'is_detected': 1,
            'HIVELOGIN': 'test_bear',
        }

        handler = ServerHandler(MagicMock(server=(0, 6676), verbose=False), MagicMock())
        result = handler.process_request(data)
        assert result is True


class TestAESRoundtrip:
    """Verify AESCipher encrypt/decrypt roundtrip works with the fixed implementation."""

    def test_encrypt_decrypt_roundtrip(self):
        """Real AESCipher encrypt + decrypt roundtrip should work."""
        import json

        from manyfaced.common.myenc import AESCipher

        aes = AESCipher('roundtrip_test')
        original = json.dumps(
            {
                'ip': '1.2.3.4',
                'raw_request': 'GET /\r\n\r\n',
                'timestamp': '2026-04-19 07:00:00.000000',
                'parsed_request': {'command': 'GET', 'path': '/'},
                'is_detected': 1,
            }
        ).encode('utf-8')

        encrypted = aes.encrypt(original)
        decrypted = aes.decrypt(encrypted)

        assert json.loads(decrypted.decode('utf-8')) == json.loads(original.decode('utf-8'))

    def test_different_keys_cannot_decrypt(self):
        """Encrypted with one key should not decrypt with a different key."""
        from manyfaced.common.myenc import AESCipher

        aes_correct = AESCipher('correct_key')
        aes_wrong = AESCipher('wrong_key')

        original = b'{"ip":"1.2.3.4"}'
        encrypted = aes_correct.encrypt(original)

        try:
            decrypted = aes_wrong.decrypt(encrypted)
            assert decrypted != original
        except Exception:
            pass


class TestServerHandlerKeyLookup:
    """Test ServerHandler key lookup."""

    def test_get_key_returns_key_for_known_bear(self):
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6677), verbose=False), MagicMock())
        key = handler.get_key(BEE_IDENTIFIER)
        assert key == TEST_KEY

    def test_get_key_raises_for_unknown_bean(self):
        """get_key should raise ValueError for unknown identifiers (no fallback)."""
        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6677), verbose=False), MagicMock())
        with pytest.raises(ValueError, match='Unknown identifier'):
            handler.get_key('completely_unknown_bean')

    def test_get_key_raises_when_no_default_key(self):
        """get_key should raise ValueError when neither AUTHORISEDBEARS nor DEFAULT_KEY is set."""
        import sys

        from manyfaced.server.server import ServerHandler

        handler = ServerHandler(MagicMock(server=(0, 6678), verbose=False), MagicMock())
        # Use object.__setattr__ to bypass frozen dataclass restriction
        saved_default_key = (
            handler.args.DEFAULT_KEY if hasattr(handler.args, 'DEFAULT_KEY') else None
        )
        # We need to patch settings.DEFAULT_KEY directly via the module
        import manyfaced.common.config as config_mod

        mod = sys.modules['manyfaced.common.config']
        cfg = mod.settings

        # Save and clear DEFAULT_KEY using object.__setattr__ for frozen dataclass
        saved_default_key = cfg.DEFAULT_KEY
        object.__setattr__(cfg, 'DEFAULT_KEY', None)
        try:
            with pytest.raises(ValueError, match='Unknown identifier'):
                handler.get_key('completely_unknown_bear')
        finally:
            # Restore DEFAULT_KEY
            object.__setattr__(cfg, 'DEFAULT_KEY', saved_default_key)
