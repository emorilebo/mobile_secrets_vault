"""Unit tests for the versioning module."""

import pytest
from mobile_secrets_vault.versioning import VersionManager, SecretVersion
from mobile_secrets_vault.crypto import CryptoEngine


class TestSecretVersion:
    """Test SecretVersion class."""

    def test_create_version(self):
        """Test creating a secret version."""
        encrypted = {"ciphertext": "abc", "nonce": "xyz"}
        version = SecretVersion(version=1, encrypted_value=encrypted, metadata={"source": "test"})

        assert version.version == 1
        assert version.encrypted_value == encrypted
        assert version.metadata["source"] == "test"
        assert version.timestamp is not None

    def test_to_dict(self):
        """Test conversion to dictionary."""
        encrypted = {"ciphertext": "abc", "nonce": "xyz"}
        version = SecretVersion(version=1, encrypted_value=encrypted)

        data = version.to_dict()
        assert data["version"] == 1
        assert data["encrypted_value"] == encrypted
        assert "timestamp" in data

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "version": 2,
            "encrypted_value": {"ciphertext": "test", "nonce": "123"},
            "timestamp": "2025-01-01T00:00:00Z",
            "metadata": {"key": "value"},
        }

        version = SecretVersion.from_dict(data)
        assert version.version == 2
        assert version.encrypted_value == data["encrypted_value"]
        assert version.timestamp == data["timestamp"]
        assert version.metadata == data["metadata"]


class TestVersionManager:
    """Test VersionManager class."""

    def test_add_first_version(self):
        """Test adding the first version of a secret."""
        manager = VersionManager()
        encrypted = {"ciphertext": "abc", "nonce": "xyz"}

        version_num = manager.add_version("DATABASE_URL", encrypted)

        assert version_num == 1
        assert "DATABASE_URL" in manager.get_all_keys()

    def test_add_multiple_versions(self):
        """Test adding multiple versions."""
        manager = VersionManager()

        v1 = manager.add_version("API_KEY", {"ciphertext": "old", "nonce": "1"})
        v2 = manager.add_version("API_KEY", {"ciphertext": "new", "nonce": "2"})

        assert v1 == 1
        assert v2 == 2

    def test_get_latest_version(self):
        """Test retrieving the latest version."""
        manager = VersionManager()

        manager.add_version("SECRET", {"ciphertext": "v1", "nonce": "1"})
        manager.add_version("SECRET", {"ciphertext": "v2", "nonce": "2"})

        latest = manager.get_version("SECRET")
        assert latest.version == 2
        assert latest.encrypted_value["ciphertext"] == "v2"

    def test_get_specific_version(self):
        """Test retrieving a specific version."""
        manager = VersionManager()

        manager.add_version("TOKEN", {"ciphertext": "v1", "nonce": "1"})
        manager.add_version("TOKEN", {"ciphertext": "v2", "nonce": "2"})
        manager.add_version("TOKEN", {"ciphertext": "v3", "nonce": "3"})

        v2 = manager.get_version("TOKEN", version=2)
        assert v2.version == 2
        assert v2.encrypted_value["ciphertext"] == "v2"

    def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist."""
        manager = VersionManager()

        result = manager.get_version("NONEXISTENT")
        assert result is None

    def test_get_nonexistent_version(self):
        """Test getting a version that doesn't exist."""
        manager = VersionManager()
        manager.add_version("KEY", {"ciphertext": "v1", "nonce": "1"})

        result = manager.get_version("KEY", version=999)
        assert result is None

    def test_list_versions(self):
        """Test listing all versions for a key."""
        manager = VersionManager()

        manager.add_version("PASSWORD", {"ciphertext": "v1", "nonce": "1"})
        manager.add_version("PASSWORD", {"ciphertext": "v2", "nonce": "2"})

        versions = manager.list_versions("PASSWORD")

        assert len(versions) == 2
        assert versions[0]["version"] == 1
        assert versions[1]["version"] == 2
        assert "timestamp" in versions[0]

    def test_delete_key(self):
        """Test deleting all versions of a key."""
        manager = VersionManager()

        manager.add_version("TEMP", {"ciphertext": "v1", "nonce": "1"})
        manager.add_version("TEMP", {"ciphertext": "v2", "nonce": "2"})

        # Delete should succeed
        assert manager.delete_key("TEMP") is True
        assert "TEMP" not in manager.get_all_keys()

        # Second delete should fail
        assert manager.delete_key("TEMP") is False

    def test_delete_version(self):
        """Test deleting a specific version."""
        manager = VersionManager()

        manager.add_version("KEY", {"ciphertext": "v1", "nonce": "1"})
        manager.add_version("KEY", {"ciphertext": "v2", "nonce": "2"})
        manager.add_version("KEY", {"ciphertext": "v3", "nonce": "3"})

        # Delete version 2
        assert manager.delete_version("KEY", 2) is True

        # Should have 2 versions left
        versions = manager.list_versions("KEY")
        assert len(versions) == 2
        assert 2 not in [v["version"] for v in versions]

    def test_get_all_keys(self):
        """Test getting all secret keys."""
        manager = VersionManager()

        manager.add_version("KEY1", {"ciphertext": "v1", "nonce": "1"})
        manager.add_version("KEY2", {"ciphertext": "v2", "nonce": "2"})
        manager.add_version("KEY3", {"ciphertext": "v3", "nonce": "3"})

        keys = manager.get_all_keys()
        assert set(keys) == {"KEY1", "KEY2", "KEY3"}

    def test_to_from_dict(self):
        """Test serialization and deserialization."""
        manager1 = VersionManager()

        manager1.add_version("SECRET1", {"ciphertext": "v1", "nonce": "1"})
        manager1.add_version("SECRET1", {"ciphertext": "v2", "nonce": "2"})
        manager1.add_version("SECRET2", {"ciphertext": "v1", "nonce": "3"})

        # Export to dict
        data = manager1.to_dict()

        # Import into new manager
        manager2 = VersionManager()
        manager2.from_dict(data)

        # Should have same data
        assert manager2.get_all_keys() == manager1.get_all_keys()
        assert len(manager2.list_versions("SECRET1")) == 2
        assert len(manager2.list_versions("SECRET2")) == 1

    def test_rotate_key(self):
        """Test key rotation."""
        manager = VersionManager()
        crypto = CryptoEngine()

        old_key = crypto.generate_key()
        new_key = crypto.generate_key()

        # Add encrypted secrets
        plaintext1 = "secret value 1"
        plaintext2 = "secret value 2"

        encrypted1 = crypto.encrypt(plaintext1, old_key)
        encrypted2 = crypto.encrypt(plaintext2, old_key)

        manager.add_version("KEY1", encrypted1)
        manager.add_version("KEY2", encrypted2)

        # Rotate to new key
        manager.rotate_key(old_key, new_key, crypto)

        # Should be able to decrypt with new key
        v1 = manager.get_version("KEY1")
        v2 = manager.get_version("KEY2")

        decrypted1 = crypto.decrypt(v1.encrypted_value, new_key)
        decrypted2 = crypto.decrypt(v2.encrypted_value, new_key)

        assert decrypted1 == plaintext1
        assert decrypted2 == plaintext2

        # Should NOT work with old key
        with pytest.raises(Exception):
            crypto.decrypt(v1.encrypted_value, old_key)
