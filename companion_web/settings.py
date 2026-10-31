"""Deployment configuration is private and separate from public source code."""
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG = json.loads(Path(os.environ['COMPANION_WEB_CONFIG']).read_text())
SECRET_KEY = CONFIG['secret_key']
DEBUG = False
ALLOWED_HOSTS = [CONFIG['host']]
ROOT_URLCONF = 'companion_web.urls'
WSGI_APPLICATION = 'companion_web.wsgi.application'
STATE = Path(CONFIG['state_directory'])
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': STATE / 'accounts.sqlite3',
                          'OPTIONS': {'timeout': 15}}}
INSTALLED_APPS = [
    'django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions',
    'django.contrib.messages', 'django.contrib.staticfiles', 'django.contrib.humanize',
    'allauth', 'allauth.account', 'allauth.mfa', 'allauth.usersessions',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'allauth.usersessions.middleware.UserSessionsMiddleware',
    'companion_web.security.OperatorBoundary',
]
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates',
              'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True,
              'OPTIONS': {'context_processors': [
                  'django.template.context_processors.request',
                  'django.contrib.auth.context_processors.auth',
                  'django.contrib.messages.context_processors.messages',
              ]}}]
AUTHENTICATION_BACKENDS = ['allauth.account.auth_backends.AuthenticationBackend']
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 14}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
ACCOUNT_ADAPTER = 'companion_web.security.OperatorAccountAdapter'
# Only the private Unix-socket frontend can reach this application. Nginx
# replaces X-Forwarded-For with the actual peer, rather than appending input.
ALLAUTH_TRUSTED_PROXY_COUNT = 1
ACCOUNT_LOGIN_METHODS = {'username'}
ACCOUNT_EMAIL_VERIFICATION = 'none'
ACCOUNT_SESSION_REMEMBER = True
ACCOUNT_REAUTHENTICATION_REQUIRED = True
ACCOUNT_REAUTHENTICATION_TIMEOUT = 300
MFA_SUPPORTED_TYPES = ['totp', 'recovery_codes']
MFA_PASSKEY_LOGIN_ENABLED = False
MFA_RECOVERY_CODES_SHOW_ONCE = True
MFA_TOTP_ISSUER = 'CloudPanel Companion'
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/accounts/login/'
# Operator accounts are provisioned locally. Until an explicit email transport is
# configured, no reset token or authenticator secret is written to service logs.
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'
SESSION_COOKIE_NAME = '__Host-companion_session'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 43200
CSRF_COOKIE_NAME = '__Host-companion_csrf'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
SECURE_SSL_REDIRECT = True
# The application listens on a private Unix socket. Its Nginx frontend replaces
# this header; it is never trusted from a publicly reachable application port.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = 65536
DATA_UPLOAD_MAX_NUMBER_FIELDS = 100
STATIC_URL = '/static/'
STATIC_ROOT = STATE / 'static'
STATICFILES_DIRS = [BASE_DIR / 'static']
STORAGES = {
    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'},
}
# A private Redis socket provides atomic add for single-use MFA codes across
# workers. Never share this security state with a website's object cache.
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.redis.RedisCache',
                       'LOCATION': CONFIG['security_cache_url'],
                       'OPTIONS': {'socket_connect_timeout': 2, 'socket_timeout': 2}}}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
TIME_ZONE = 'UTC'
