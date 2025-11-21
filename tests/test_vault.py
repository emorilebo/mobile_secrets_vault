"""Unit tests for the main Vault API."""

import pytest
import tempfile
from pathlib import Path

from mobile_secrets_vault import (
    MobileSecretsVault,
    CryptoEngine,
    MasterKeyNotFoundError,
    SecretNotFoundError
)


class TestMobileSecretsVault:
    """Test cases for MobileSecretsVault class."""
    
    @pytest.fixture
    def temp_vault(self):
        """Create a temporary vault for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            key_file = tmppath / 'master.key'
            secrets_file = tmppath / 'secrets.yaml'
            
            # Generate and save master key
            master_key = CryptoEngine.generate_key()
            with open(key_file, 'wb') as f:
                f.write(master_key)
            
            yield {
                'key_file': str(key_file),
                'secrets_file': str(secrets_file),
                'master_key': master_key
            }
    
    def test_init_with_key_file(self, temp_vault):
        """Test initializing vault with key file."""
        vault = MobileSecretsVault(
            master_key_file=temp_vault['key_file'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        assert vault.master_key == temp_vault['master_key']
    
    def test_init_with_direct_key(self, temp_vault):
        """Test initializing vault with direct key parameter."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        assert vault.master_key == temp_vault['master_key']
    
    def test_init_without_key_fails(self):
        """Test that initialization fails without a master key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(MasterKeyNotFoundError):
                MobileSecretsVault(
                    secrets_filepath=str(Path(tmpdir) / 'secrets.yaml')
                )
    
    def test_set_and_get_secret(self, temp_vault):
        """Test setting and retrieving a secret."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        # Set a secret
        version = vault.set('DATABASE_URL', 'postgresql://localhost/mydb')
        assert version == 1
        
        # Get the secret
        value = vault.get('DATABASE_URL')
        assert value == 'postgresql://localhost/mydb'
    
    def test_get_nonexistent_secret(self, temp_vault):
        """Test getting a secret that doesn't exist."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        with pytest.raises(SecretNotFoundError):
            vault.get('NONEXISTENT')
    
    def test_update_secret_creates_new_version(self, temp_vault):
        """Test that updating a secret creates a new version."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        v1 = vault.set('API_KEY', 'old-key-123')
        v2 = vault.set('API_KEY', 'new-key-456')
        
        assert v2 == v1 + 1
        
        # Latest should be new value
        assert vault.get('API_KEY') == 'new-key-456'
        
        # Can still get old version
        assert vault.get('API_KEY', version=v1) == 'old-key-123'
    
    def test_delete_secret(self, temp_vault):
        """Test deleting a secret."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        vault.set('TEMP_SECRET', 'temporary')
        
        # Delete should succeed
        assert vault.delete('TEMP_SECRET') is True
        
        # Secret should be gone
        with pytest.raises(SecretNotFoundError):
            vault.get('TEMP_SECRET')
        
        # Second delete should return False
        assert vault.delete('TEMP_SECRET') is False
    
    def test_list_versions(self, temp_vault):
        """Test listing version history."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        vault.set('PASSWORD', 'password1')
        vault.set('PASSWORD', 'password2')
        vault.set('PASSWORD', 'password3')
        
        versions = vault.list_versions('PASSWORD')
        
        assert len(versions) == 3
        assert versions[0]['version'] == 1
        assert versions[2]['version'] == 3
    
    def test_list_keys(self, temp_vault):
        """Test listing all secret keys."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        vault.set('KEY1', 'value1')
        vault.set('KEY2', 'value2')
        vault.set('KEY3', 'value3')
        
        keys = vault.list_keys()
        assert set(keys) == {'KEY1', 'KEY2', 'KEY3'}
    
    def test_persistence(self, temp_vault):
        """Test that secrets are persisted to disk."""
        # Create vault and add secrets
        vault1 = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file'],
            auto_save=True
        )
        
        vault1.set('PERSISTENT', 'saved-value')
        
        # Create new vault instance from same files
        vault2 = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        # Should load the saved secret
        assert vault2.get('PERSISTENT') == 'saved-value'
    
    def test_rotate_key(self, temp_vault):
        """Test key rotation."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        # Add some secrets
        vault.set('SECRET1', 'value1')
        vault.set('SECRET2', 'value2')
        
        # Rotate key
        new_key = vault.rotate()
        
        # Should still be able to access secrets
        assert vault.get('SECRET1') == 'value1'
        assert vault.get('SECRET2') == 'value2'
        
        # Master key should be different
        assert vault.master_key == new_key
        assert new_key != temp_vault['master_key']
    
    def test_audit_log(self, temp_vault):
        """Test audit logging."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        vault.set('TEST', 'value')
        vault.get('TEST')
        vault.delete('TEST')
        
        logs = vault.get_audit_log()
        
        # Should have logs for init, set, get, delete
        assert len(logs) >= 4
        
        operations = [log['operation'] for log in logs]
        assert 'set' in operations
        assert 'get' in operations
        assert 'delete' in operations
    
    def test_unicode_secrets(self, temp_vault):
        """Test handling of Unicode in secrets."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        unicode_value = "Hello 世界 🔐 Password"
        vault.set('UNICODE_KEY', unicode_value)
        
        retrieved = vault.get('UNICODE_KEY')
        assert retrieved == unicode_value
    
    def test_long_secret_value(self, temp_vault):
        """Test storing large secret values."""
        vault = MobileSecretsVault(
            master_key=temp_vault['master_key'],
            secrets_filepath=temp_vault['secrets_file']
        )
        
        long_value = "x" * 10000  # 10KB
        vault.set('LONG_SECRET', long_value)
        
        retrieved = vault.get('LONG_SECRET')
        assert retrieved == long_value
