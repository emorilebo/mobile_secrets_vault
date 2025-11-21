"""
FastAPI Integration Example

Demonstrates how to integrate Mobile Secrets Vault with a FastAPI application.
"""

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import os

from mobile_secrets_vault import MobileSecretsVault

# Initialize FastAPI app
app = FastAPI(title="Mobile Secrets Vault - FastAPI Example")

# Global vault instance (initialized at startup)
vault: Optional[MobileSecretsVault] = None


# Startup event to load vault
@app.on_event("startup")
async def startup_event():
    """Load secrets vault on application startup."""
    global vault
    
    try:
        vault = MobileSecretsVault(
            master_key_file=os.getenv("VAULT_MASTER_KEY_FILE", ".vault/master.key"),
            secrets_filepath=os.getenv("VAULT_FILE", ".vault/secrets.yaml")
        )
        print("✅ Secrets vault loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load secrets vault: {e}")
        raise


# Dependency to get vault instance
def get_vault() -> MobileSecretsVault:
    """Dependency to access the vault."""
    if vault is None:
        raise HTTPException(status_code=500, detail="Vault not initialized")
    return vault


# Pydantic models
class SecretRequest(BaseModel):
    """Request model for setting a secret."""
    key: str
    value: str
    metadata: Optional[dict] = None


class SecretResponse(BaseModel):
    """Response model for secrets."""
    key: str
    value: str
    version: int


class VersionInfo(BaseModel):
    """Version information."""
    version: int
    timestamp: str
    metadata: dict


# API Endpoints

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Mobile Secrets Vault API",
        "version": "0.1.0"
    }


@app.post("/secrets", response_model=dict)
async def create_secret(
    request: SecretRequest,
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """
    Create or update a secret.
    
    Creates a new version each time.
    """
    try:
        version = vault_instance.set(
            request.key,
            request.value,
            metadata=request.metadata
        )
        return {
            "message": f"Secret '{request.key}' saved successfully",
            "version": version
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/secrets/{key}", response_model=SecretResponse)
async def get_secret(
    key: str,
    version: Optional[int] = None,
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """
    Retrieve a secret.
    
    By default returns the latest version.
    """
    try:
        value = vault_instance.get(key, version=version)
        
        # Get current version number
        versions = vault_instance.list_versions(key)
        current_version = versions[-1]['version'] if versions else 1
        
        return SecretResponse(
            key=key,
            value=value,
            version=version or current_version
        )
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Secret not found: {e}")


@app.delete("/secrets/{key}")
async def delete_secret(
    key: str,
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """Delete a secret and all its versions."""
    try:
        deleted = vault_instance.delete(key)
        if deleted:
            return {"message": f"Secret '{key}' deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Secret not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/secrets/{key}/versions", response_model=list[VersionInfo])
async def list_secret_versions(
    key: str,
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """List all versions for a secret."""
    try:
        versions = vault_instance.list_versions(key)
        return [VersionInfo(**v) for v in versions]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/secrets")
async def list_secrets(
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """List all secret keys."""
    try:
        keys = vault_instance.list_keys()
        return {
            "count": len(keys),
            "keys": sorted(keys)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit")
async def get_audit_log(
    key: Optional[str] = None,
    limit: int = 50,
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """Get audit log entries."""
    try:
        logs = vault_instance.get_audit_log(key=key, limit=limit)
        return {
            "count": len(logs),
            "logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rotate")
async def rotate_key(
    vault_instance: MobileSecretsVault = Depends(get_vault)
):
    """
    Rotate the master encryption key.
    
    WARNING: This re-encrypts all secrets with a new key.
    Make sure to save the new key securely!
    """
    try:
        new_key = vault_instance.rotate()
        
        # In production, you'd want to save this key securely
        # and update your key management infrastructure
        
        return {
            "message": "Key rotated successfully",
            "warning": "Save the new master key securely!",
            "new_key_hint": "Check server logs or update key management"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Example usage of secrets in application logic
@app.get("/config")
async def get_config(vault_instance: MobileSecretsVault = Depends(get_vault)):
    """
    Example endpoint that uses secrets from the vault.
    
    This demonstrates how to use secrets in your application logic.
    """
    try:
        # In a real app, you'd use these secrets to configure services
        config = {}
        
        # Try to get some example secrets
        for key in ['DATABASE_URL', 'API_KEY', 'JWT_SECRET']:
            try:
                config[key] = vault_instance.get(key)
            except:
                config[key] = None
        
        return {
            "message": "Application configuration",
            "secrets_loaded": sum(1 for v in config.values() if v is not None),
            "config_keys": list(config.keys())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting FastAPI application with Mobile Secrets Vault")
    print("\n⚠️  Before running, make sure you have:")
    print("   - Initialized vault: vault init")
    print("   - Set some secrets: vault set DATABASE_URL <value>")
    print("\n📚 API Documentation: http://localhost:8000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
