"""
Mobile Secrets Vault - Main API

A secure secrets management library for mobile backend applications.
"""

import os
from pathlib import Path
from typing import Optional, List, Dict, Any

from .crypto import CryptoEngine
from .storage import StorageBackend
from .versioning import VersionManager
from .audit import AuditLogger, Operation


class VaultError(Exception):
    """Base exception for vault errors."""

    pass


class MasterKeyNotFoundError(VaultError):
    """Raised when master key cannot be located."""

    pass


class SecretNotFoundError(VaultError):
    """Raised when a requested secret doesn't exist."""

    pass


class MobileSecretsVault:
    """
    Main API for Mobile Secrets Vault.

    Provides secure storage, retrieval, and management of secrets with:
    - AES-GCM-256 encryption
    - Version history
    - Audit logging
    - Key rotation

    Example:
        >>> vault = MobileSecretsVault(
        ...     master_key_file=".vault/master.key",
        ...     secrets_filepath=".vault/secrets.yaml"
        ... )
        >>> vault.set("DATABASE_URL", "postgresql://localhost/mydb")
        >>> vault.get("DATABASE_URL")
        'postgresql://localhost/mydb'
    """

    def __init__(
        self,
        master_key: Optional[bytes] = None,
        master_key_file: Optional[str] = None,
        secrets_filepath: Optional[str] = None,
        audit_log_file: Optional[str] = None,
        auto_save: bool = True,
    ):
        """
        Initialize the vault.

        Master key priority: constructor param > env var > file > error

        Args:
            master_key: Direct master key bytes (highest priority)
            master_key_file: Path to master key file
            secrets_filepath: Path to encrypted secrets file
            audit_log_file: Path to audit log file (optional)
            auto_save: Automatically save after modifications

        Raises:
            MasterKeyNotFoundError: If master key cannot be located
        """
        self.auto_save = auto_save

        # Load master key with priority
        self.master_key = self._load_master_key(master_key, master_key_file)

        # Initialize storage
        self.secrets_filepath = Path(secrets_filepath or ".vault/secrets.yaml")
        self.storage = StorageBackend(self.secrets_filepath)

        # Initialize components
        self.crypto = CryptoEngine()
        self.version_manager = VersionManager()

        # Initialize audit logger
        audit_path = Path(audit_log_file) if audit_log_file else None
        self.audit_logger = AuditLogger(log_file=audit_path)

        # Load existing secrets
        self._load_secrets()

        # Log initialization
        self.audit_logger.log(Operation.INIT, success=True)

    def _load_master_key(self, direct_key: Optional[bytes], key_file: Optional[str]) -> bytes:
        """
        Load master key from various sources with priority.

        Priority: direct_key > env var > key_file
        """
        # 1. Direct key parameter (highest priority)
        if direct_key is not None:
            return direct_key

        # 2. Environment variable
        env_key = os.environ.get("VAULT_MASTER_KEY")
        if env_key:
            try:
                return CryptoEngine.string_to_key(env_key)
            except Exception:
                pass  # Fall through to next option

        # 3. Key file
        if key_file:
            key_path = Path(key_file)
            if key_path.exists():
                try:
                    with open(key_path, "rb") as f:
                        return f.read()
                except Exception as e:
                    raise MasterKeyNotFoundError(f"Failed to read key file: {e}")

        # 4. Default key file location
        default_key_path = Path.home() / ".vault" / "master.key"
        if default_key_path.exists():
            try:
                with open(default_key_path, "rb") as f:
                    return f.read()
            except Exception:
                pass

        raise MasterKeyNotFoundError(
            "Master key not found. Provide key via:\n"
            "  1. master_key parameter\n"
            "  2. VAULT_MASTER_KEY environment variable\n"
            "  3. master_key_file parameter\n"
            "  4. ~/.vault/master.key file"
        )

    def _load_secrets(self) -> None:
        """Load secrets from storage."""
        try:
            data = self.storage.load()
            if data:
                self.version_manager.from_dict(data)
        except Exception as e:
            # If loading fails, start with empty vault
            print(f"Warning: Failed to load secrets: {e}")

    def set(self, key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Set or update a secret.

        Creates a new version each time the secret is updated.

        Args:
            key: Secret key name
            value: Secret value (plaintext)
            metadata: Optional metadata for this version

        Returns:
            Version number of the new secret
        """
        try:
            # Encrypt the value
            encrypted = self.crypto.encrypt(value, self.master_key)

            # Add new version
            version = self.version_manager.add_version(key, encrypted, metadata)

            # Auto-save if enabled
            if self.auto_save:
                self.save()

            # Log operation
            self.audit_logger.log(Operation.SET, key=key, success=True, version=version)

            return version

        except Exception as e:
            self.audit_logger.log(Operation.SET, key=key, success=False, error=str(e))
            raise VaultError(f"Failed to set secret: {e}")

    def get(self, key: str, version: Optional[int] = None) -> str:
        """
        Get a secret value.

        Args:
            key: Secret key name
            version: Specific version to retrieve (None for latest)

        Returns:
            Decrypted secret value

        Raises:
            SecretNotFoundError: If secret doesn't exist
        """
        try:
            # Get the version
            secret_version = self.version_manager.get_version(key, version)

            if secret_version is None:
                raise SecretNotFoundError(f"Secret '{key}' not found")

            # Decrypt the value
            plaintext = self.crypto.decrypt(secret_version.encrypted_value, self.master_key)

            # Log operation
            self.audit_logger.log(
                Operation.GET, key=key, success=True, version=secret_version.version
            )

            return plaintext

        except SecretNotFoundError:
            self.audit_logger.log(Operation.GET, key=key, success=False, error="Secret not found")
            raise
        except Exception as e:
            self.audit_logger.log(Operation.GET, key=key, success=False, error=str(e))
            raise VaultError(f"Failed to get secret: {e}")

    def delete(self, key: str) -> bool:
        """
        Delete a secret and all its versions.

        Args:
            key: Secret key name

        Returns:
            True if secret was deleted, False if it didn't exist
        """
        try:
            deleted = self.version_manager.delete_key(key)

            if deleted and self.auto_save:
                self.save()

            self.audit_logger.log(Operation.DELETE, key=key, success=deleted)

            return deleted

        except Exception as e:
            self.audit_logger.log(Operation.DELETE, key=key, success=False, error=str(e))
            raise VaultError(f"Failed to delete secret: {e}")

    def rotate(self, new_key: Optional[bytes] = None) -> None:
        """
        Rotate the master encryption key.

        Re-encrypts all secrets with a new key. If no new key is provided,
        generates a random key.

        Args:
            new_key: New master key (None to generate random)

        Returns:
            The new master key (if generated)
        """
        try:
            # Generate new key if not provided
            if new_key is None:
                new_key = self.crypto.generate_key()

            # Re-encrypt all secrets
            old_key = self.master_key
            self.version_manager.rotate_key(old_key, new_key, self.crypto)

            # Update master key
            self.master_key = new_key

            # Save changes
            self.save()

            # Log operation
            self.audit_logger.log(
                Operation.ROTATE,
                success=True,
                secret_count=len(self.version_manager.get_all_keys()),
            )

            return new_key if new_key else None

        except Exception as e:
            self.audit_logger.log(Operation.ROTATE, success=False, error=str(e))
            raise VaultError(f"Failed to rotate key: {e}")

    def list_versions(self, key: str) -> List[Dict[str, Any]]:
        """
        List all versions for a secret.

        Args:
            key: Secret key name

        Returns:
            List of version metadata
        """
        try:
            versions = self.version_manager.list_versions(key)

            self.audit_logger.log(
                Operation.LIST_VERSIONS, key=key, success=True, version_count=len(versions)
            )

            return versions

        except Exception as e:
            self.audit_logger.log(Operation.LIST_VERSIONS, key=key, success=False, error=str(e))
            raise VaultError(f"Failed to list versions: {e}")

    def list_keys(self) -> List[str]:
        """
        Get list of all secret keys.

        Returns:
            List of secret key names
        """
        return self.version_manager.get_all_keys()

    def save(self) -> None:
        """Persist secrets to storage."""
        data = self.version_manager.to_dict()
        self.storage.save(data)

    def get_audit_log(
        self, key: Optional[str] = None, limit: Optional[int] = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs.

        Args:
            key: Filter by specific key (None for all)
            limit: Maximum number of logs to return

        Returns:
            List of audit log entries
        """
        return self.audit_logger.get_logs(key=key, limit=limit)
