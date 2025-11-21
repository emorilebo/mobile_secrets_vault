#!/usr/bin/env python3
"""
Verification script to test Mobile Secrets Vault functionality.

This script tests the core functionality without requiring full installation.
"""

import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mobile_secrets_vault import MobileSecretsVault, CryptoEngine
from pathlib import Path
import tempfile
import shutil


def test_crypto():
    """Test encryption/decryption."""
    print("🧪 Testing Encryption...")
    
    key = CryptoEngine.generate_key()
    plaintext = "Test secret value"
    
    # Encrypt
    encrypted = CryptoEngine.encrypt(plaintext, key)
    print(f"   ✅ Encrypted: {encrypted['ciphertext'][:20]}...")
    
    # Decrypt
    decrypted = CryptoEngine.decrypt(encrypted, key)
    assert decrypted == plaintext
    print(f"   ✅ Decrypted successfully: {decrypted}")
    
    # Test tampering detection
    try:
        tampered = encrypted.copy()
        tampered['ciphertext'] = tampered['ciphertext'][:-5] + 'XXXXX'
        CryptoEngine.decrypt(tampered, key)
        print("   ❌ Tampering not detected!")
        return False
    except:
        print("   ✅ Tampering detected correctly")
    
    return True


def test_vault():
    """Test vault operations."""
    print("\n🧪 Testing Vault Operations...")
    
    # Create temporary directory
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Generate master key
        master_key = CryptoEngine.generate_key()
        key_file = Path(tmpdir) / 'master.key'
        secrets_file = Path(tmpdir) / 'secrets.yaml'
        
        with open(key_file, 'wb') as f:
            f.write(master_key)
        
        # Create vault
        vault = MobileSecretsVault(
            master_key_file=str(key_file),
            secrets_filepath=str(secrets_file)
        )
        print("   ✅ Vault initialized")
        
        # Set secrets
        v1 = vault.set('DATABASE_URL', 'postgresql://localhost/mydb')
        v2 = vault.set('API_KEY', 'secret-key-12345')
        print(f"   ✅ Secrets set (versions: {v1}, {v2})")
        
        # Get secrets
        db_url = vault.get('DATABASE_URL')
        api_key = vault.get('API_KEY')
        assert db_url == 'postgresql://localhost/mydb'
        assert api_key == 'secret-key-12345'
        print(f"   ✅ Secrets retrieved correctly")
        
        # Test versioning
        v3 = vault.set('API_KEY', 'new-key-67890')
        assert v3 == 2
        latest = vault.get('API_KEY')
        old = vault.get('API_KEY', version=1)
        assert latest == 'new-key-67890'
        assert old == 'secret-key-12345'
        print("   ✅ Versioning works correctly")
        
        # Test list versions
        versions = vault.list_versions('API_KEY')
        assert len(versions) == 2
        print(f"   ✅ Version history: {len(versions)} versions")
        
        # Test list keys
        keys = vault.list_keys()
        assert set(keys) == {'DATABASE_URL', 'API_KEY'}
        print(f"   ✅ Keys listed: {keys}")
        
        # Test delete
        deleted = vault.delete('DATABASE_URL')
        assert deleted is True
        print("   ✅ Secret deleted")
        
        # Test persistence
        vault.save()
        vault2 = MobileSecretsVault(
            master_key_file=str(key_file),
            secrets_filepath=str(secrets_file)
        )
        assert vault2.get('API_KEY') == 'new-key-67890'
        print("   ✅ Persistence works")
        
        # Test key rotation
        vault2.rotate()
        assert vault2.get('API_KEY') == 'new-key-67890'
        print("   ✅ Key rotation successful")
        
        # Test audit log
        logs = vault2.get_audit_log()
        assert len(logs) > 0
        print(f"   ✅ Audit log has {len(logs)} entries")
        
        return True
        
    finally:
        # Cleanup
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_cli_basic():
    """Test that CLI module can be imported."""
    print("\n🧪 Testing CLI Import...")
    
    try:
        from mobile_secrets_vault import cli
        print("   ✅ CLI module imported successfully")
        return True
    except Exception as e:
        print(f"   ❌ CLI import failed: {e}")
        return False


def main():
    """Run all verification tests."""
    print("=" * 60)
    print("Mobile Secrets Vault - Verification Script")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Encryption", test_crypto()))
    results.append(("Vault Operations", test_vault()))
    results.append(("CLI Import", test_cli_basic()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:25} {status}")
    
    all_passed = all(result for _, result in results)
    
    print("=" * 60)
    if all_passed:
        print("🎉 ALL TESTS PASSED! Package is working correctly.")
        return 0
    else:
        print("❌ SOME TESTS FAILED. Please review the errors above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
