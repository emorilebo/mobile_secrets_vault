"""Unit tests for the crypto module."""

import pytest
from mobile_secrets_vault.crypto import CryptoEngine


class TestCryptoEngine:
    """Test cases for encryption and decryption."""
    
    def test_generate_key(self):
        """Test key generation produces valid 32-byte keys."""
        key1 = CryptoEngine.generate_key()
        key2 = CryptoEngine.generate_key()
        
        # Check key size
        assert len(key1) == 32
        assert len(key2) == 32
        
        # Keys should be unique
        assert key1 != key2
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        key = CryptoEngine.generate_key()
        plaintext = "my secret password"
        
        # Encrypt
        encrypted = CryptoEngine.encrypt(plaintext, key)
        
        # Verify encrypted structure
        assert 'ciphertext' in encrypted
        assert 'nonce' in encrypted
        assert encrypted['ciphertext'] != plaintext
        
        # Decrypt
        decrypted = CryptoEngine.decrypt(encrypted, key)
        
        # Should match original
        assert decrypted == plaintext
    
    def test_decrypt_with_wrong_key_fails(self):
        """Test decryption fails with wrong key."""
        key1 = CryptoEngine.generate_key()
        key2 = CryptoEngine.generate_key()
        plaintext = "secret data"
        
        encrypted = CryptoEngine.encrypt(plaintext, key1)
        
        # Should raise exception with wrong key
        with pytest.raises(Exception):
            CryptoEngine.decrypt(encrypted, key2)
    
    def test_tampering_detection(self):
        """Test that tampering with ciphertext is detected."""
        key = CryptoEngine.generate_key()
        plaintext = "important data"
        
        encrypted = CryptoEngine.encrypt(plaintext, key)
        
        # Tamper with ciphertext
        tampered = encrypted.copy()
        tampered['ciphertext'] = tampered['ciphertext'][:-5] + 'XXXXX'
        
        # Should raise exception
        with pytest.raises(Exception):
            CryptoEngine.decrypt(tampered, key)
    
    def test_invalid_key_size(self):
        """Test that invalid key sizes are rejected."""
        invalid_key = b"short"
        plaintext = "test"
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            CryptoEngine.encrypt(plaintext, invalid_key)
        
        encrypted = {'ciphertext': 'abc', 'nonce': 'def'}
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            CryptoEngine.decrypt(encrypted, invalid_key)
    
    def test_malformed_encrypted_data(self):
        """Test decryption with malformed data."""
        key = CryptoEngine.generate_key()
        
        # Missing fields
        with pytest.raises(ValueError, match="must contain"):
            CryptoEngine.decrypt({}, key)
        
        with pytest.raises(ValueError, match="must contain"):
            CryptoEngine.decrypt({'ciphertext': 'abc'}, key)
    
    def test_unicode_support(self):
        """Test encryption of Unicode characters."""
        key = CryptoEngine.generate_key()
        plaintext = "Hello 世界 🔐 Emoji"
        
        encrypted = CryptoEngine.encrypt(plaintext, key)
        decrypted = CryptoEngine.decrypt(encrypted, key)
        
        assert decrypted == plaintext
    
    def test_key_to_from_string(self):
        """Test key serialization to/from base64 string."""
        key = CryptoEngine.generate_key()
        
        # Convert to string
        key_string = CryptoEngine.key_to_string(key)
        assert isinstance(key_string, str)
        
        # Convert back
        key_restored = CryptoEngine.string_to_key(key_string)
        assert key_restored == key
    
    def test_empty_plaintext(self):
        """Test encrypting empty string."""
        key = CryptoEngine.generate_key()
        plaintext = ""
        
        encrypted = CryptoEngine.encrypt(plaintext, key)
        decrypted = CryptoEngine.decrypt(encrypted, key)
        
        assert decrypted == plaintext
    
    def test_long_plaintext(self):
        """Test encrypting large text."""
        key = CryptoEngine.generate_key()
        plaintext = "x" * 10000  # 10KB of data
        
        encrypted = CryptoEngine.encrypt(plaintext, key)
        decrypted = CryptoEngine.decrypt(encrypted, key)
        
        assert decrypted == plaintext
