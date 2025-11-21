"""
Django Integration Example

Demonstrates how to integrate Mobile Secrets Vault with Django settings.

Add this to your Django project's settings.py file.
"""

import os
from pathlib import Path
from mobile_secrets_vault import MobileSecretsVault, MasterKeyNotFoundError

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================================
# Mobile Secrets Vault Integration
# ============================================================================

def load_secrets_vault():
    """
    Load the secrets vault at Django startup.
    
    Returns:
        MobileSecretsVault instance or None if vault is not configured
    """
    try:
        vault = MobileSecretsVault(
            master_key_file=os.getenv(
                'VAULT_MASTER_KEY_FILE',
                str(BASE_DIR / '.vault' / 'master.key')
            ),
            secrets_filepath=os.getenv(
                'VAULT_FILE',
                str(BASE_DIR / '.vault' / 'secrets.yaml')
            )
        )
        print("✅ Secrets vault loaded successfully")
        return vault
    except MasterKeyNotFoundError:
        print("⚠️  Secrets vault not found - using environment variables")
        return None
    except Exception as e:
        print(f"❌ Failed to load secrets vault: {e}")
        return None


# Initialize vault
SECRETS_VAULT = load_secrets_vault()


def get_secret(key: str, default=None):
    """
    Get a secret from the vault or environment variables.
    
    Priority:
    1. Vault (if available)
    2. Environment variable
    3. Default value
    
    Args:
        key: Secret key name
        default: Default value if secret not found
        
    Returns:
        Secret value or default
    """
    # Try vault first
    if SECRETS_VAULT is not None:
        try:
            return SECRETS_VAULT.get(key)
        except:
            pass
    
    # Fall back to environment variable
    return os.getenv(key, default)


# ============================================================================
# Django Settings Using Vault
# ============================================================================

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret(
    'DJANGO_SECRET_KEY',
    default='django-insecure-change-this-in-production'
)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')


# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Your apps here
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'myproject.urls'

WSGI_APPLICATION = 'myproject.wsgi.application'


# Database configuration using vault
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': get_secret('DB_NAME', 'mydb'),
        'USER': get_secret('DB_USER', 'postgres'),
        'PASSWORD': get_secret('DB_PASSWORD', 'postgres'),
        'HOST': get_secret('DB_HOST', 'localhost'),
        'PORT': get_secret('DB_PORT', '5432'),
    }
}


# Email configuration using vault
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = get_secret('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(get_secret('EMAIL_PORT', '587'))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = get_secret('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = get_secret('EMAIL_HOST_PASSWORD', '')


# Third-party service credentials
AWS_ACCESS_KEY_ID = get_secret('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = get_secret('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = get_secret('AWS_STORAGE_BUCKET_NAME')

STRIPE_PUBLIC_KEY = get_secret('STRIPE_PUBLIC_KEY')
STRIPE_SECRET_KEY = get_secret('STRIPE_SECRET_KEY')

SENDGRID_API_KEY = get_secret('SENDGRID_API_KEY')


# ============================================================================
# Example: Custom Management Command to Set Secrets
# ============================================================================
"""
Create this file: management/commands/set_secret.py

from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = 'Set a secret in the vault'

    def add_arguments(self, parser):
        parser.add_argument('key', type=str, help='Secret key')
        parser.add_argument('value', type=str, help='Secret value')

    def handle(self, *args, **options):
        vault = settings.SECRETS_VAULT
        
        if vault is None:
            self.stdout.write(
                self.style.ERROR('Vault not initialized. Run: vault init')
            )
            return
        
        key = options['key']
        value = options['value']
        
        version = vault.set(key, value)
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully set '{key}' (version {version})"
            )
        )


# Usage:
# python manage.py set_secret DATABASE_URL "postgresql://..."
"""


# ============================================================================
# Example: Loading Secrets in Views
# ============================================================================
"""
from django.conf import settings
from django.http import JsonResponse


def config_view(request):
    '''Example view that uses vault secrets.'''
    
    vault = settings.SECRETS_VAULT
    
    if vault is None:
        return JsonResponse({
            'error': 'Vault not configured'
        }, status=500)
    
    # Get secrets
    api_keys = {
        'stripe': vault.get('STRIPE_PUBLIC_KEY', default='not configured'),
        'aws_configured': vault.get('AWS_ACCESS_KEY_ID') is not None,
    }
    
    return JsonResponse({
        'status': 'ok',
        'keys_configured': api_keys
    })
"""


# ============================================================================
# Setup Instructions
# ============================================================================
"""
1. Install the package:
   pip install mobile-secrets-vault

2. Initialize vault in your Django project root:
   cd /path/to/django/project
   vault init

3. Set your Django secrets:
   vault set DJANGO_SECRET_KEY "your-secret-key-here"
   vault set DB_PASSWORD "your-db-password"
   vault set AWS_ACCESS_KEY_ID "your-aws-key"
   vault set AWS_SECRET_ACCESS_KEY "your-aws-secret"

4. Add .vault/ to your .gitignore:
   echo ".vault/" >> .gitignore

5. Update your settings.py to use this integration

6. For production:
   - Store master.key in a secure location (e.g., AWS Secrets Manager)
   - Mount it or set via environment variable
   - Never commit master.key to version control!
"""
