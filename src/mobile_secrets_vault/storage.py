"""
Storage backend for Mobile Secrets Vault.

Handles reading and writing encrypted secrets to YAML files with file locking.
"""

import yaml
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
import fcntl
import tempfile


class StorageBackend:
    """
    Manages persistent storage of encrypted secrets in YAML format.
    
    Features:
    - Safe file operations with atomic writes
    - Automatic backups before modifications
    - File locking to prevent concurrent writes
    """
    
    def __init__(self, filepath: Path):
        """
        Initialize storage backend.
        
        Args:
            filepath: Path to the secrets file
        """
        self.filepath = Path(filepath)
    
    def load(self) -> Dict[str, Any]:
        """
        Load secrets from file.
        
        Returns:
            Dictionary containing secrets data, or empty dict if file doesn't exist
            
        Raises:
            yaml.YAMLError: If file contains invalid YAML
            IOError: If file cannot be read
        """
        if not self.filepath.exists():
            return {}
        
        try:
            with open(self.filepath, 'r') as f:
                # Acquire shared lock for reading
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    data = yaml.safe_load(f) or {}
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            return data
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Failed to parse secrets file: {e}")
        except Exception as e:
            raise IOError(f"Failed to read secrets file: {e}")
    
    def save(self, data: Dict[str, Any], create_backup: bool = True) -> None:
        """
        Save secrets to file atomically.
        
        Uses atomic write pattern:
        1. Write to temporary file
        2. Create backup if requested
        3. Atomically replace original file
        
        Args:
            data: Secrets data to save
            create_backup: Whether to create a backup before writing
            
        Raises:
            IOError: If file cannot be written
        """
        # Ensure parent directory exists
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Create backup if file exists and backup is requested
        if create_backup and self.filepath.exists():
            self._create_backup()
        
        # Write to temporary file first (atomic operation)
        temp_file = None
        try:
            # Create temp file in same directory to ensure same filesystem
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=self.filepath.parent,
                delete=False,
                suffix='.tmp'
            ) as f:
                temp_file = Path(f.name)
                
                # Acquire exclusive lock
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    yaml.safe_dump(
                        data,
                        f,
                        default_flow_style=False,
                        sort_keys=False,
                        allow_unicode=True
                    )
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomically replace the original file
            temp_file.replace(self.filepath)
            
        except Exception as e:
            # Clean up temp file if something went wrong
            if temp_file and temp_file.exists():
                temp_file.unlink()
            raise IOError(f"Failed to save secrets file: {e}")
    
    def _create_backup(self) -> None:
        """Create a backup of the current secrets file."""
        backup_path = self.filepath.with_suffix(self.filepath.suffix + '.backup')
        try:
            shutil.copy2(self.filepath, backup_path)
        except Exception:
            # If backup fails, continue anyway (not critical)
            pass
    
    def delete(self) -> bool:
        """
        Delete the secrets file.
        
        Returns:
            True if file was deleted, False if it didn't exist
        """
        if self.filepath.exists():
            self.filepath.unlink()
            return True
        return False
    
    def exists(self) -> bool:
        """Check if the secrets file exists."""
        return self.filepath.exists()
    
    def get_backup_path(self) -> Optional[Path]:
        """
        Get path to the most recent backup file if it exists.
        
        Returns:
            Path to backup file, or None if no backup exists
        """
        backup_path = self.filepath.with_suffix(self.filepath.suffix + '.backup')
        return backup_path if backup_path.exists() else None
    
    def restore_from_backup(self) -> bool:
        """
        Restore secrets from backup file.
        
        Returns:
            True if backup was restored, False if no backup exists
        """
        backup_path = self.get_backup_path()
        if backup_path:
            shutil.copy2(backup_path, self.filepath)
            return True
        return False
