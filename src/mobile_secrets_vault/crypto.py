"""
Cryptography engine for Mobile Secrets Vault.

Implements AES-GCM-256 authenticated encryption for securing secrets.
"""

import os
import base64
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoEngine:
    """
    Handles encryption and decryption of secrets using AES-GCM-256.

    AES-GCM provides:
    - Confidentiality through AES-256 encryption
    - Authenticity through Galois/Counter Mode authentication
    - Detection of tampering attempts
    """

    # AES-256 requires 32-byte keys
    KEY_SIZE = 32  # 256 bits

    # Nonce size for AES-GCM (96 bits is recommended)
    NONCE_SIZE = 12  # 96 bits

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a cryptographically secure 256-bit AES key.

        Returns:
            bytes: A 32-byte (256-bit) random key suitable for AES-256
        """
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> Dict[str, str]:
        """
        Encrypt plaintext using AES-GCM-256.

        Args:
            plaintext: The secret value to encrypt
            key: 32-byte AES-256 key

        Returns:
            Dictionary containing:
                - ciphertext: Base64-encoded encrypted data
                - nonce: Base64-encoded nonce (required for decryption)

        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != CryptoEngine.KEY_SIZE:
            raise ValueError(f"Key must be {CryptoEngine.KEY_SIZE} bytes, got {len(key)}")

        # Generate a random nonce for this encryption operation
        nonce = os.urandom(CryptoEngine.NONCE_SIZE)

        # Initialize AES-GCM with the key
        aesgcm = AESGCM(key)

        # Encrypt the plaintext (GCM automatically adds authentication tag)
        ciphertext = aesgcm.encrypt(
            nonce=nonce,
            data=plaintext.encode("utf-8"),
            associated_data=None,  # Could add metadata here if needed
        )

        # Return base64-encoded values for safe YAML/JSON storage
        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
        }

    @staticmethod
    def decrypt(encrypted_data: Dict[str, str], key: bytes) -> str:
        """
        Decrypt ciphertext using AES-GCM-256.

        Args:
            encrypted_data: Dictionary with 'ciphertext' and 'nonce' (base64-encoded)
            key: 32-byte AES-256 key (must be the same key used for encryption)

        Returns:
            The decrypted plaintext string

        Raises:
            ValueError: If key is not 32 bytes or data is malformed
            cryptography.exceptions.InvalidTag: If authentication fails (tampering detected)
        """
        if len(key) != CryptoEngine.KEY_SIZE:
            raise ValueError(f"Key must be {CryptoEngine.KEY_SIZE} bytes, got {len(key)}")

        if "ciphertext" not in encrypted_data or "nonce" not in encrypted_data:
            raise ValueError("Encrypted data must contain 'ciphertext' and 'nonce'")

        # Decode base64-encoded values
        try:
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            nonce = base64.b64decode(encrypted_data["nonce"])
        except Exception as e:
            raise ValueError(f"Failed to decode encrypted data: {e}")

        # Initialize AES-GCM with the key
        aesgcm = AESGCM(key)

        # Decrypt and verify authentication tag
        # This will raise InvalidTag if the data has been tampered with
        plaintext_bytes = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)

        return plaintext_bytes.decode("utf-8")

    @staticmethod
    def key_to_string(key: bytes) -> str:
        """Convert a key to base64 string for storage."""
        return base64.b64encode(key).decode("utf-8")

    @staticmethod
    def string_to_key(key_string: str) -> bytes:
        """Convert a base64 string back to key bytes."""
        return base64.b64decode(key_string)
