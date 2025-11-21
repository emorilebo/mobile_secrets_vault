# Publishing Guide for mobile-secrets-vault

This guide will walk you through publishing the `mobile-secrets-vault` package to PyPI and GitHub.

## Prerequisites

✅ All completed:
- [x] Package code implemented
- [x] Tests written and passing
- [x] Documentation created
- [x] LICENSE file added
- [x] README.md written
- [x] GitHub Actions CI/CD configured

## Publishing to GitHub

### 1. Initialize Git Repository

```bash
cd /Users/mac/development/projects/opensource/mobile_secrets_vault
git init
git add .
git commit -m "Initial commit: Mobile Secrets Vault v0.1.0

- AES-GCM-256 encryption for secrets
- Version management and history
- CLI with 8 commands
- Python API for backend integration
- FastAPI and Django examples
- Comprehensive test suite (64 tests)
- Full documentation"
```

### 2. Create GitHub Repository

**Option A: Using GitHub CLI (recommended)**
```bash
# Install GitHub CLI if you don't have it
brew install gh

# Login to GitHub
gh auth login

# Create repository
gh repo create mobile_secrets_vault --public --source=. --remote=origin --push

# This will:
# - Create the repository on GitHub
# - Add it as a remote
# - Push your code
```

**Option B: Manual GitHub Creation**
1. Go to https://github.com/new
2. Repository name: `mobile_secrets_vault`
3. Description: "Secure secrets management for mobile backend applications with encryption, versioning, and audit logging"
4. Public repository
5. Don't initialize with README (we already have one)
6. Create repository

Then push your code:
```bash
git remote add origin https://github.com/godfreylebo/mobile_secrets_vault.git
git branch -M main
git push -u origin main
```

### 3. Add Repository Topics

Add these topics to your GitHub repository for better discoverability:
- python
- security
- encryption
- secrets-management
- fastapi
- django
- aes-gcm
- mobile-backend
- cryptography

## Publishing to PyPI

### 1. Create PyPI Account

1. Go to https://pypi.org/account/register/
2. Verify your email
3. Enable 2FA (recommended)

### 2. Create API Token

1. Go to https://pypi.org/manage/account/token/
2. Click "Add API token"
3. Token name: `mobile-secrets-vault-upload`
4. Scope: "Entire account" or "mobile-secrets-vault"
5. Copy the token (starts with `pypi-`)

### 3. Configure Poetry/Twine Credentials

Save your API token:
```bash
# Option 1: In ~/.pypirc file
cat > ~/.pypirc << 'EOF'
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR_TOKEN_HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TESTPYPI_TOKEN_HERE
EOF

chmod 600 ~/.pypirc
```

### 4. Build the Package

```bash
# Activate virtual environment
source venv/bin/activate

# Install build tools
pip install build twine

# Build the package
python -m build

# This creates:
# dist/mobile_secrets_vault-0.1.0-py3-none-any.whl
# dist/mobile_secrets_vault-0.1.0.tar.gz
```

### 5. Test on TestPyPI (Recommended)

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ mobile-secrets-vault

# Test the package
vault --version
```

### 6. Publish to Production PyPI

```bash
# Upload to PyPI
twine upload dist/*

# Confirm at https://pypi.org/project/mobile-secrets-vault/
```

### 7. Create GitHub Release

```bash
# Tag the release
git tag v0.1.0
git push origin v0.1.0

# Create release on GitHub
gh release create v0.1.0 \
  --title "v0.1.0 - Initial Release" \
  --notes "🎉 First release of Mobile Secrets Vault!

**Features:**
- 🔒 AES-GCM-256 encryption
- 📚 Secret versioning
- 🔄 Key rotation
- 📝 Audit logging
- 🖥️ CLI & Python API
- 🚀 FastAPI & Django examples

**Install:**
\`\`\`bash
pip install mobile-secrets-vault
\`\`\`

**Quick Start:**
\`\`\`bash
vault init
vault set API_KEY mysecret
vault get API_KEY
\`\`\`

See [README](https://github.com/godfreylebo/mobile_secrets_vault/blob/main/README.md) for full documentation."
```

## Automated Publishing (GitHub Actions)

The package includes a CI/CD workflow that automatically publishes to PyPI on tagged releases.

### Setup

1. Add PyPI token to GitHub Secrets:
   - Go to repository Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `PYPI_API_TOKEN`
   - Value: Your PyPI token

2. Create a release:
   ```bash
   git tag v0.1.1
   git push origin v0.1.1
   ```

3. GitHub Actions will automatically:
   - Run all tests
   - Build the package
   - Publish to PyPI

## Post-Publishing Checklist

After publishing, verify:

- [ ] Package appears on PyPI: https://pypi.org/project/mobile-secrets-vault/
- [ ] Installation works: `pip install mobile-secrets-vault`
- [ ] CLI is accessible: `vault --version`
- [ ] Documentation is accurate
- [ ] GitHub README displays correctly
- [ ] Badges are working (build, coverage, version)

## Updating the Package

For future releases:

1. Update version in `pyproject.toml`:
   ```toml
   version = "0.1.1"  # or 0.2.0, 1.0.0, etc.
   ```

2. Update CHANGELOG.md with changes

3. Commit and tag:
   ```bash
   git add .
   git commit -m "Release v0.1.1"
   git tag v0.1.1
   git push origin main --tags
   ```

4. Build and publish:
   ```bash
   python -m build
   twine upload dist/*
   ```

## Versioning Guidelines

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.2.0): New features, backward compatible
- **PATCH** (0.1.1): Bug fixes, backward compatible

## Troubleshooting

### "File already exists" error
```bash
# Clean old builds
rm -rf dist/ build/ *.egg-info
python -m build
```

### Package not found after publishing
- Wait a few minutes for PyPI to update
- Clear pip cache: `pip cache purge`

### Tests failing in CI
- Run locally: `pytest`
- Check Python version compatibility
- Review GitHub Actions logs

## Useful Commands

```bash
# Check package metadata
twine check dist/*

# View package contents
tar -tzf dist/mobile_secrets_vault-0.1.0.tar.gz

# List installed files
pip show -f mobile-secrets-vault

# Uninstall
pip uninstall mobile-secrets-vault
```

## Resources

- PyPI: https://pypi.org/
- TestPyPI: https://test.pypi.org/
- Packaging Guide: https://packaging.python.org/
- Twine Docs: https://twine.readthedocs.io/
- GitHub Actions: https://docs.github.com/en/actions

---

**Ready to publish!** The package is complete with:
- ✅ 64 passing tests
- ✅ Comprehensive documentation
- ✅ CI/CD pipeline
- ✅ MIT License
- ✅ Example applications

Good luck with your release! 🚀
