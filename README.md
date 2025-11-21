# Mobile Secrets Vault 🔐

[![PyPI version](https://badge.fury.io/py/mobile-secrets-vault.svg)](https://badge.fury.io/py/mobile-secrets-vault)
[![Python Versions](https://img.shields.io/pypi/pyversions/mobile-secrets-vault.svg)](https://pypi.org/project/mobile-secrets-vault/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/godfreylebo/mobile_secrets_vault/branch/main/graph/badge.svg)](https://codecov.io/gh/godfreylebo/mobile_secrets_vault)

A robust, secure Python package for managing secrets in mobile backend applications (FastAPI, Django, Flask) with AES-GCM-256 encryption, versioning, rotation, and audit logging.

## ✨ Features

- **🔒 Military-Grade Encryption**: AES-GCM-256 authenticated encryption
- **📚 Version Control**: Track secret history with automatic versioning
- **🔄 Key Rotation**: Seamlessly rotate encryption keys without downtime
- **📝 Audit Logging**: Complete audit trail of all operations
- **🖥️ CLI & Python API**: Use via command line or integrate programmatically
- **🚀 Backend Integration**: Ready-to-use examples for FastAPI and Django
- **🧪 Battle-Tested**: Comprehensive test suite with 95%+ coverage
- **🐍 Modern Python**: Supports Python 3.8+

## 🚀 Quick Start

### Installation

```bash
pip install mobile-secrets-vault
```

### CLI Usage

```bash
# Initialize a new vault
vault init

# Set secrets
vault set DATABASE_URL "postgresql://localhost/mydb"
vault set API_KEY "secret-key-12345"

# Get secrets
vault get DATABASE_URL

# List all secrets
vault list

# View version history
vault list-versions DATABASE_URL

# Rotate encryption key
vault rotate
```

### Python API Usage

```python
from mobile_secrets_vault import MobileSecretsVault

# Initialize vault
vault = MobileSecretsVault(
    master_key_file=".vault/master.key",
    secrets_filepath=".vault/secrets.yaml"
)

# Set a secret
version = vault.set("API_KEY", "my-secret-value")
print(f"Secret saved as version {version}")

# Get a secret
api_key = vault.get("API_KEY")
print(f"API Key: {api_key}")

# List all secrets
secrets = vault.list_keys()
print(f"Stored secrets: {secrets}")

# View version history
versions = vault.list_versions("API_KEY")
for v in versions:
    print(f"Version {v['version']}: {v['timestamp']}")

# Rotate encryption key
new_key = vault.rotate()
print("All secrets re-encrypted with new key!")
```

## 📖 Documentation

### CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `vault init` | Initialize vault and generate master key | `vault init --output-dir .vault` |
| `vault set <key> <value>` | Set or update a secret | `vault set DB_PASS mypassword` |
| `vault get <key>` | Retrieve a secret | `vault get DB_PASS` |
| `vault delete <key>` | Delete a secret | `vault delete OLD_KEY --yes` |
| `vault list` | List all secret keys | `vault list` |
| `vault list-versions <key>` | Show version history | `vault list-versions API_KEY` |
| `vault rotate` | Rotate master encryption key | `vault rotate --new-key-file new.key` |
| `vault audit` | View audit logs | `vault audit --key API_KEY` |

### Python API Methods

```python
class MobileSecretsVault:
    def __init__(
        self,
        master_key: bytes = None,
        master_key_file: str = None,
        secrets_filepath: str = None,
        audit_log_file: str = None,
        auto_save: bool = True
    )
    
    def set(self, key: str, value: str, metadata: dict = None) -> int
    def get(self, key: str, version: int = None) -> str
    def delete(self, key: str) -> bool
    def list_keys(self) -> list[str]
    def list_versions(self, key: str) -> list[dict]
    def rotate(self, new_key: bytes = None) -> bytes
    def get_audit_log(self, key: str = None, limit: int = 100) -> list[dict]
    def save(self) -> None
```

## 🏗️ Integration Examples

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from mobile_secrets_vault import MobileSecretsVault

app = FastAPI()
vault = None

@app.on_event("startup")
async def startup():
    global vault
    vault = MobileSecretsVault(
        master_key_file=".vault/master.key",
        secrets_filepath=".vault/secrets.yaml"
    )

@app.get("/config")
def get_config():
    return {
        "database_url": vault.get("DATABASE_URL"),
        "api_key": vault.get("API_KEY")
    }
```

See [examples/fastapi_example.py](examples/fastapi_example.py) for a complete implementation.

### Django Integration

```python
# settings.py
from mobile_secrets_vault import MobileSecretsVault

VAULT = MobileSecretsVault(
    master_key_file=BASE_DIR / '.vault' / 'master.key',
    secrets_filepath=BASE_DIR / '.vault' / 'secrets.yaml'
)

SECRET_KEY = VAULT.get('DJANGO_SECRET_KEY')
DATABASES = {
    'default': {
        'PASSWORD': VAULT.get('DB_PASSWORD'),
        'USER': VAULT.get('DB_USER'),
    }
}
```

See [examples/django_example.py](examples/django_example.py) for a complete implementation.

## 🔐 Security Best Practices

### Master Key Management

> [!CAUTION]
> **NEVER commit your master key to version control!**

1. **Add to .gitignore**:
   ```bash
   echo ".vault/" >> .gitignore
   ```

2. **Store securely in production**:
   - Use environment variables
   - Use cloud secret managers (AWS Secrets Manager, Google Secret Manager)
   - Use hardware security modules (HSM) for enterprise deployments

3. **Backup your master key**:
   - Store encrypted backups in multiple secure locations
   - Use password managers for team access
   - Document key recovery procedures

### Encryption Details

- **Algorithm**: AES-GCM-256 (Authenticated Encryption with Associated Data)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: Random 96-bit nonce per encryption
- **Authentication**: Built-in authentication tag prevents tampering

### Production Deployment

```bash
# Option 1: Environment variable
export VAULT_MASTER_KEY="<base64-encoded-key>"

# Option 2: Mounted key file (Kubernetes, Docker)
vault --master-key-file /run/secrets/vault_key get API_KEY

# Option 3: Cloud secret manager
# Retrieve master key from AWS Secrets Manager, then initialize vault
```

## 🧪 Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/godfreylebo/mobile_secrets_vault.git
cd mobile_secrets_vault

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=mobile_secrets_vault --cov-report=html

# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type check
mypy src/
```

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_vault.py

# With coverage report
pytest --cov=mobile_secrets_vault --cov-report=term-missing

# Verbose output
pytest -v
```

## 📦 Publishing to PyPI

### Prerequisites

1. **Create PyPI Account**: Sign up at [pypi.org](https://pypi.org)
2. **Create API Token**: Settings → API tokens → Add API token
3. **Install build tools**:
   ```bash
   pip install build twine
   ```

### Build and Publish

```bash
# 1. Update version in pyproject.toml
# version = "0.1.0" -> "0.1.1"

# 2. Build package
python -m build

# 3. Check package
twine check dist/*

# 4. Upload to TestPyPI (optional)
twine upload --repository testpypi dist/*

# 5. Test installation
pip install --index-url https://test.pypi.org/simple/ mobile-secrets-vault

# 6. Upload to PyPI (production)
twine upload dist/*
```

### Automated Publishing with GitHub Actions

The package includes a CI/CD workflow that automatically:
- Runs tests on Python 3.8-3.12
- Checks code formatting and linting
- Publishes to PyPI on tagged releases

To trigger automated publishing:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run tests: `pytest`
5. Format code: `black src/ tests/`
6. Commit: `git commit -m 'Add amazing feature'`
7. Push: `git push origin feature/amazing-feature`
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Godfrey Lebo**

- GitHub: [@godfreylebo](https://github.com/godfreylebo)
- PyPI: [mobile-secrets-vault](https://pypi.org/project/mobile-secrets-vault/)

## 🙏 Acknowledgments

- Built with [cryptography](https://cryptography.io/) for encryption
- CLI powered by [click](https://click.palletsprojects.com/)
- Storage using [PyYAML](https://pyyaml.org/)

## 📊 Project Stats

- **Lines of Code**: ~2,000
- **Test Coverage**: 95%+
- **Dependencies**: 4 (cryptography, click, PyYAML, python-dotenv)
- **Python Versions**: 3.8, 3.9, 3.10, 3.11, 3.12

---

**⭐ If you find this project useful, please consider giving it a star on GitHub!**
