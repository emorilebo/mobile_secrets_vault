"""Mobile Secrets Vault - Secure secrets management for mobile backends."""

__version__ = "0.1.0"

from .vault import (
    MobileSecretsVault,
    VaultError,
    MasterKeyNotFoundError,
    SecretNotFoundError,
)
from .crypto import CryptoEngine
from .audit import AuditLogger, Operation

__all__ = [
    "MobileSecretsVault",
    "VaultError",
    "MasterKeyNotFoundError",
    "SecretNotFoundError",
    "CryptoEngine",
    "AuditLogger",
    "Operation",
    "__version__",
]
