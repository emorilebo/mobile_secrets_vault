"""
Command-line interface for Mobile Secrets Vault.

Provides commands for initializing, managing, and rotating secrets.
"""

import sys
import click
from pathlib import Path
from typing import Optional

from . import MobileSecretsVault, CryptoEngine, __version__
from .vault import MasterKeyNotFoundError, SecretNotFoundError


# Global options
@click.group()
@click.version_option(version=__version__)
@click.option(
    '--vault-file',
    type=click.Path(),
    envvar='VAULT_FILE',
    default='.vault/secrets.yaml',
    help='Path to secrets vault file'
)
@click.option(
    '--master-key-file',
    type=click.Path(exists=True),
    envvar='VAULT_MASTER_KEY_FILE',
    help='Path to master key file'
)
@click.pass_context
def cli(ctx: click.Context, vault_file: str, master_key_file: Optional[str]) -> None:
    """
    Mobile Secrets Vault - Secure secrets management for mobile backends.
    
    Manage encrypted secrets with versioning, rotation, and audit logging.
    """
    ctx.ensure_object(dict)
    ctx.obj['vault_file'] = vault_file
    ctx.obj['master_key_file'] = master_key_file


@cli.command()
@click.option(
    '--output-dir',
    type=click.Path(),
    default='.vault',
    help='Directory to create vault files'
)
@click.option(
    '--force',
    is_flag=True,
    help='Overwrite existing files without confirmation'
)
def init(output_dir: str, force: bool) -> None:
    """Initialize a new vault with master key and secrets file."""
    output_path = Path(output_dir)
    key_file = output_path / 'master.key'
    secrets_file = output_path / 'secrets.yaml'
    
    # Check if files exist
    if (key_file.exists() or secrets_file.exists()) and not force:
        click.echo("❌ Vault already exists in this directory.")
        click.echo(f"   Key file: {key_file}")
        click.echo(f"   Secrets file: {secrets_file}")
        click.echo("\nUse --force to overwrite existing files.")
        sys.exit(1)
    
    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Generate master key
    master_key = CryptoEngine.generate_key()
    
    # Save master key
    with open(key_file, 'wb') as f:
        f.write(master_key)
    
    # Set restrictive permissions on key file (Unix only)
    try:
        key_file.chmod(0o600)
    except Exception:
        pass
    
    # Create empty secrets file
    secrets_file.touch()
    
    click.echo("✅ Vault initialized successfully!")
    click.echo(f"\n📁 Vault directory: {output_path.absolute()}")
    click.echo(f"🔑 Master key: {key_file}")
    click.echo(f"🗄️  Secrets file: {secrets_file}")
    click.echo("\n⚠️  IMPORTANT: Keep your master key secure!")
    click.echo("   - Never commit it to version control")
    click.echo("   - Add .vault/ to your .gitignore")
    click.echo("   - Back it up in a secure location")


@cli.command()
@click.argument('key')
@click.argument('value', required=False)
@click.option(
    '--stdin',
    is_flag=True,
    help='Read value from stdin (for sensitive input)'
)
@click.pass_context
def set(ctx: click.Context, key: str, value: Optional[str], stdin: bool) -> None:
    """Set or update a secret value."""
    # Get value from stdin if requested
    if stdin:
        value = click.get_text_stream('stdin').read().strip()
    elif value is None:
        value = click.prompt(f"Enter value for '{key}'", hide_input=True)
    
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        version = vault.set(key, value)
        click.echo(f"✅ Secret '{key}' set successfully (version {version})")
        
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        click.echo("\n💡 Run 'vault init' to create a new vault", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to set secret: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('key')
@click.option(
    '--version',
    type=int,
    help='Get specific version (default: latest)'
)
@click.option(
    '--raw',
    is_flag=True,
    help='Output only the value (for scripting)'
)
@click.pass_context
def get(ctx: click.Context, key: str, version: Optional[int], raw: bool) -> None:
    """Retrieve and display a secret value."""
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        value = vault.get(key, version=version)
        
        if raw:
            click.echo(value)
        else:
            version_info = f" (version {version})" if version else ""
            click.echo(f"🔓 Secret '{key}'{version_info}:")
            click.echo(f"   {value}")
        
    except SecretNotFoundError:
        click.echo(f"❌ Secret '{key}' not found", err=True)
        sys.exit(1)
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to get secret: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('key')
@click.option(
    '--yes',
    is_flag=True,
    help='Skip confirmation prompt'
)
@click.pass_context
def delete(ctx: click.Context, key: str, yes: bool) -> None:
    """Delete a secret and all its versions."""
    if not yes:
        confirmation = click.confirm(
            f"Are you sure you want to delete '{key}' and all its versions?"
        )
        if not confirmation:
            click.echo("❌ Deletion cancelled")
            return
    
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        deleted = vault.delete(key)
        
        if deleted:
            click.echo(f"✅ Secret '{key}' deleted successfully")
        else:
            click.echo(f"❌ Secret '{key}' not found")
            sys.exit(1)
        
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to delete secret: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    '--new-key-file',
    type=click.Path(),
    help='Path to save the new master key'
)
@click.option(
    '--yes',
    is_flag=True,
    help='Skip confirmation prompt'
)
@click.pass_context
def rotate(ctx: click.Context, new_key_file: Optional[str], yes: bool) -> None:
    """Rotate the master encryption key (re-encrypt all secrets)."""
    if not yes:
        confirmation = click.confirm(
            "⚠️  This will re-encrypt all secrets with a new master key. Continue?"
        )
        if not confirmation:
            click.echo("❌ Rotation cancelled")
            return
    
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        secret_count = len(vault.list_keys())
        
        click.echo(f"🔄 Rotating encryption key for {secret_count} secrets...")
        
        new_key = vault.rotate()
        
        # Save new key if path provided
        if new_key_file:
            output_path = Path(new_key_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(new_key)
            
            try:
                output_path.chmod(0o600)
            except Exception:
                pass
            
            click.echo(f"✅ Rotation complete! New key saved to: {output_path}")
        else:
            click.echo("✅ Rotation complete!")
            click.echo(f"\n🔑 New master key (base64):")
            click.echo(f"   {CryptoEngine.key_to_string(new_key)}")
            click.echo("\n⚠️  Save this key securely - you'll need it to access your secrets!")
        
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to rotate key: {e}", err=True)
        sys.exit(1)


@cli.command('list-versions')
@click.argument('key')
@click.pass_context
def list_versions(ctx: click.Context, key: str) -> None:
    """Show version history for a secret."""
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        versions = vault.list_versions(key)
        
        if not versions:
            click.echo(f"❌ No versions found for '{key}'")
            sys.exit(1)
        
        click.echo(f"📋 Version history for '{key}':\n")
        for v in reversed(versions):  # Show newest first
            click.echo(f"  Version {v['version']}")
            click.echo(f"    Timestamp: {v['timestamp']}")
            if v.get('metadata'):
                click.echo(f"    Metadata: {v['metadata']}")
            click.echo()
        
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to list versions: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    '--key',
    help='Filter logs by secret key'
)
@click.option(
    '--limit',
    type=int,
    default=50,
    help='Maximum number of log entries to show'
)
@click.pass_context
def audit(ctx: click.Context, key: Optional[str], limit: int) -> None:
    """Display audit log of vault operations."""
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        logs = vault.get_audit_log(key=key, limit=limit)
        
        if not logs:
            click.echo("📋 No audit logs found")
            return
        
        title = f"Audit log for '{key}'" if key else "Audit log"
        click.echo(f"📋 {title} (showing {len(logs)} entries):\n")
        
        for log in logs:
            status = "✅" if log['success'] else "❌"
            key_info = f" - {log['key']}" if log['key'] else ""
            click.echo(f"{status} {log['timestamp']} - {log['operation']}{key_info}")
            
            if log.get('error'):
                click.echo(f"   Error: {log['error']}")
            
            if log.get('metadata'):
                click.echo(f"   Metadata: {log['metadata']}")
        
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to retrieve audit log: {e}", err=True)
        sys.exit(1)


@cli.command('list')
@click.pass_context
def list_keys(ctx: click.Context) -> None:
    """List all secret keys in the vault."""
    try:
        vault = MobileSecretsVault(
            master_key_file=ctx.obj['master_key_file'],
            secrets_filepath=ctx.obj['vault_file']
        )
        
        keys = vault.list_keys()
        
        if not keys:
            click.echo("📋 Vault is empty")
            return
        
        click.echo(f"📋 Secrets in vault ({len(keys)}):\n")
        for key in sorted(keys):
            versions = vault.list_versions(key)
            click.echo(f"  • {key} ({len(versions)} versions)")
        
    except MasterKeyNotFoundError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to list keys: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
