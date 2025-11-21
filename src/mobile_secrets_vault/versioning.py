"""
Versioning system for Mobile Secrets Vault.

Manages multiple versions of secrets with metadata and history tracking.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime


class SecretVersion:
    """Represents a single version of a secret."""

    def __init__(
        self,
        version: int,
        encrypted_value: Dict[str, str],
        timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize a secret version.

        Args:
            version: Version number (1-indexed)
            encrypted_value: Encrypted secret data (ciphertext + nonce)
            timestamp: ISO format timestamp (UTC)
            metadata: Additional version metadata
        """
        self.version = version
        self.encrypted_value = encrypted_value
        self.timestamp = timestamp or datetime.utcnow().isoformat() + "Z"
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "version": self.version,
            "encrypted_value": self.encrypted_value,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecretVersion":
        """Create from dictionary."""
        return cls(
            version=data["version"],
            encrypted_value=data["encrypted_value"],
            timestamp=data.get("timestamp"),
            metadata=data.get("metadata", {}),
        )


class VersionManager:
    """
    Manages versioned secrets.

    Each secret key can have multiple versions, allowing:
    - History tracking
    - Rollback capabilities
    - Audit trails
    """

    def __init__(self) -> None:
        """Initialize the version manager."""
        # Storage format: {key: {versions: [SecretVersion, ...], current_version: int}}
        self._secrets: Dict[str, Dict[str, Any]] = {}

    def add_version(
        self, key: str, encrypted_value: Dict[str, str], metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Add a new version for a secret key.

        Args:
            key: Secret key name
            encrypted_value: Encrypted secret data
            metadata: Optional metadata for this version

        Returns:
            The new version number
        """
        if key not in self._secrets:
            # First version for this key
            self._secrets[key] = {"versions": [], "current_version": 0}

        # Calculate next version number
        next_version = self._secrets[key]["current_version"] + 1

        # Create the version
        version = SecretVersion(
            version=next_version, encrypted_value=encrypted_value, metadata=metadata
        )

        # Add to storage
        self._secrets[key]["versions"].append(version)
        self._secrets[key]["current_version"] = next_version

        return int(next_version)

    def get_version(self, key: str, version: Optional[int] = None) -> Optional[SecretVersion]:
        """
        Get a specific version of a secret.

        Args:
            key: Secret key name
            version: Version number (None for latest)

        Returns:
            SecretVersion if found, None otherwise
        """
        if key not in self._secrets:
            return None

        versions = self._secrets[key]["versions"]

        if not versions:
            return None

        if version is None:
            # Return latest version
            last_version = versions[-1]
            assert isinstance(last_version, SecretVersion)
            return last_version

        # Find specific version
        for v in versions:
            if v.version == version:
                assert isinstance(v, SecretVersion)
                return v

        return None

    def list_versions(self, key: str) -> List[Dict[str, Any]]:
        """
        List all versions for a secret key.

        Args:
            key: Secret key name

        Returns:
            List of version metadata (without encrypted values)
        """
        if key not in self._secrets:
            return []

        versions = self._secrets[key]["versions"]

        return [
            {"version": v.version, "timestamp": v.timestamp, "metadata": v.metadata}
            for v in versions
        ]

    def delete_key(self, key: str) -> bool:
        """
        Delete all versions of a secret key.

        Args:
            key: Secret key name

        Returns:
            True if key was deleted, False if it didn't exist
        """
        if key in self._secrets:
            del self._secrets[key]
            return True
        return False

    def delete_version(self, key: str, version: int) -> bool:
        """
        Delete a specific version (keep other versions).

        Args:
            key: Secret key name
            version: Version number to delete

        Returns:
            True if version was deleted, False if not found
        """
        if key not in self._secrets:
            return False

        versions = self._secrets[key]["versions"]
        original_count = len(versions)

        # Remove the version
        self._secrets[key]["versions"] = [v for v in versions if v.version != version]

        return len(self._secrets[key]["versions"]) < original_count

    def get_all_keys(self) -> List[str]:
        """Get list of all secret keys."""
        return list(self._secrets.keys())

    def rotate_key(self, old_key: bytes, new_key: bytes, crypto_engine: Any) -> None:
        """
        Re-encrypt all secrets with a new master key.

        Args:
            old_key: Current encryption key
            new_key: New encryption key to use
            crypto_engine: CryptoEngine instance for encryption/decryption
        """
        for key in self._secrets:
            for version in self._secrets[key]["versions"]:
                # Decrypt with old key
                try:
                    plaintext = crypto_engine.decrypt(version.encrypted_value, old_key)

                    # Re-encrypt with new key
                    new_encrypted = crypto_engine.encrypt(plaintext, new_key)
                    version.encrypted_value = new_encrypted

                except Exception as e:
                    # Log error but continue with other secrets
                    print(f"Warning: Failed to rotate key for {key} v{version.version}: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Export all secrets to dictionary for storage."""
        return {
            key: {
                "versions": [v.to_dict() for v in data["versions"]],
                "current_version": data["current_version"],
            }
            for key, data in self._secrets.items()
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        """Import secrets from dictionary."""
        self._secrets = {}
        for key, key_data in data.items():
            self._secrets[key] = {
                "versions": [SecretVersion.from_dict(v) for v in key_data["versions"]],
                "current_version": key_data["current_version"],
            }
