import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEV = os.environ.get('VIPERNET_DEV') == '1'
STATE = Path(os.environ.get('VIPERNET_STATE', str(BASE_DIR / '.state')))
STATE.mkdir(parents=True, exist_ok=True)
if DEV:
    from cryptography.fernet import Fernet
    import secrets
    for name, value in [('session.key', secrets.token_urlsafe(48)), ('vault.key', Fernet.generate_key().decode())]:
        path = STATE / name
        if not path.exists():
            path.write_text(value)
    SECRET_KEY = (STATE / 'session.key').read_text()
    VAULT_KEY = (STATE / 'vault.key').read_text()
else:
    SECRET_KEY = os.environ['VIPERNET_SESSION_KEY']
    VAULT_KEY = os.environ['VIPERNET_VAULT_KEY']
if not SECRET_KEY or not VAULT_KEY:
    raise RuntimeError('Session and vault keys are required')
DEBUG = False
PUBLIC_ORIGIN = os.environ.get('VIPERNET_ORIGIN', 'http://127.0.0.1:8765' if DEV else 'https://members.vipernet.app').rstrip('/')
from urllib.parse import urlsplit
origin_parts = urlsplit(PUBLIC_ORIGIN)
if not DEV and (origin_parts.scheme != 'https' or not origin_parts.hostname or origin_parts.username or origin_parts.password or origin_parts.path or origin_parts.query or origin_parts.fragment):
    raise RuntimeError('Use an exact HTTPS service origin')
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver'] if DEV else [__import__('urllib.parse', fromlist=['urlparse']).urlparse(PUBLIC_ORIGIN).hostname]
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles', 'members']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware', 'members.middleware.SecurityHeaders']
ROOT_URLCONF = 'service.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': STATE / 'membership.sqlite3', 'OPTIONS': {'timeout': 30}}}
if os.environ.get('VIPERNET_DB_NAME'):
    DATABASES['default'] = {'ENGINE': 'django.db.backends.postgresql', 'NAME': os.environ['VIPERNET_DB_NAME'], 'USER': os.environ['VIPERNET_DB_USER'], 'PASSWORD': os.environ['VIPERNET_DB_PASSWORD'], 'HOST': os.environ.get('VIPERNET_DB_HOST', '127.0.0.1'), 'PORT': os.environ.get('VIPERNET_DB_PORT', '5432')}
AUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}}, {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'}, {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'}]
EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend' if DEV else ('service.brevo_email.EmailBackend' if os.environ.get('VIPERNET_BREVO_API_KEY') else 'django.core.mail.backends.smtp.EmailBackend')
EMAIL_FILE_PATH = STATE / 'mail'
EMAIL_HOST = os.environ.get('VIPERNET_SMTP_HOST', '')
EMAIL_PORT = int(os.environ.get('VIPERNET_SMTP_PORT', '587'))
EMAIL_HOST_USER = os.environ.get('VIPERNET_SMTP_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('VIPERNET_SMTP_PASSWORD', '')
EMAIL_USE_TLS = True
EMAIL_TIMEOUT = 15
DEFAULT_FROM_EMAIL = os.environ.get('VIPERNET_MAIL_FROM', 'ViperNet <info@vipernet.app>')
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = not DEV
CSRF_COOKIE_SECURE = not DEV
CSRF_FAILURE_VIEW = 'members.views.csrf_failure'
SESSION_COOKIE_AGE = 43200
SESSION_SAVE_EVERY_REQUEST = False
SECURE_SSL_REDIRECT = not DEV
SECURE_HSTS_SECONDS = 31536000 if not DEV else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
PASSWORD_RESET_TIMEOUT = 1800
DATA_UPLOAD_MAX_MEMORY_SIZE = 1048576
LOGIN_URL = '/member/sign-in/'
LOGIN_REDIRECT_URL = '/member/account/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
STATIC_URL = '/member-static/'
STATIC_ROOT = BASE_DIR / '.static'
STATICFILES_DIRS = [BASE_DIR / 'static']

TIME_ZONE = 'UTC'
SESSION_COOKIE_NAME = 'sessionid' if DEV else '__Host-vipernet-session'
CSRF_COOKIE_NAME = 'csrftoken' if DEV else '__Host-vipernet-csrf'
