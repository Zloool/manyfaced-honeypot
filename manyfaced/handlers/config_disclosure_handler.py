"""ConfigDisclosureHandler – handles config file disclosure attempts.

Provides realistic fake configuration file responses including:
- wp-config.php (WordPress config with fake credentials)
- config.php (Joomla/Drupal config)
- .env (environment variables)
- database.yml (Rails config)
- settings.py (Django config)
- config.json (various configs)
- .htaccess / .htpasswd
- xmlrpc.php (WordPress XML-RPC endpoint)

This handler catches bots probing for sensitive configuration files
that could reveal database credentials, API keys, and other secrets.
"""

from __future__ import annotations

import datetime
import logging
import re
from typing import Any

from manyfaced.handlers.base_handler import HTTPHandlerBase

logger = logging.getLogger(__name__)


class ConfigDisclosureHandler(HTTPHandlerBase):
    """Config file disclosure honeypot handler."""

    domain = "config_disclosure"
    PATH_PATTERNS = [
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/wp-config.php.dist", "/wp-config.php.txt",
        "/config.php", "/config.php.bak", "/config.php.old",
        "/configuration.php", "/configuration.php.bak",
        "/settings.py", "/settings.py.bak", "/settings.py.old",
        "/database.yml", "/database.yml.bak",
        "/config.json", "/config.json.bak",
        "/.env", "/.env.bak", "/.env.local", "/.env.prod",
        "/.env.example", "/.env.sample",
        "/.htaccess", "/.htaccess.bak", "/.htaccess.old",
        "/.htpasswd", "/.htpasswd.bak",
        "/xmlrpc.php", "/xmlrpc.php.bak",
        "/web.config", "/web.config.bak",
        "/conf.php", "/conf.php.bak",
        "/db.php", "/db.php.bak",
        "/local.php", "/local.php.bak",
        "/app.config", "/app.config.bak",
        "/application.ini", "/application.ini.bak",
        "/globals.php", "/globals.php.bak",
        "/initialize.php", "/initialize.php.bak",
        "/constants.php", "/constants.php.bak",
        "/parameters.yml", "/parameters.yml.dist",
        "/service.yml", "/service.yml.bak",
        "/doctrine.yml", "/doctrine.yml.bak",
        "/routing.yml", "/routing.yml.bak",
        "/security.yml", "/security.yml.bak",
        "/appsettings.json", "/appsettings.json.bak",
        "/package.json", "/package.json.bak",
        "/composer.json", "/composer.json.bak",
        "/Gemfile", "/Gemfile.lock",
        "/pip.conf", "/pip.conf.bak",
        "/requirements.txt", "/requirements.txt.bak",
        "/setup.cfg", "/setup.cfg.bak",
        "/tox.ini", "/tox.ini.bak",
        "/Makefile", "/Makefile.bak",
        "/Dockerfile", "/Dockerfile.bak",
        "/docker-compose.yml", "/docker-compose.yml.bak",
        "/nginx.conf", "/nginx.conf.bak",
        "/apache.conf", "/apache.conf.bak",
        "/httpd.conf", "/httpd.conf.bak",
        "/my.cnf", "/my.cnf.bak", "/mysqld.cnf",
        "/postgresql.conf", "/postgresql.conf.bak",
        "/redis.conf", "/redis.conf.bak",
        "/php.ini", "/php.ini.bak",
        "/phpinfo.php", "/phpinfo.php.bak",
        "/info.php", "/info.php.bak",
        "/test.php", "/test.php.bak",
        "/debug.php", "/debug.php.bak",
        "/console.php", "/console.php.bak",
        "/cli.php", "/cli.php.bak",
        "/install.php", "/install.php.bak",
        "/upgrade.php", "/upgrade.php.bak",
        "/backup.sql", "/backup.sql.bak",
        "/dump.sql", "/dump.sql.bak",
        "/database.sql", "/database.sql.bak",
        "/db.sql", "/db.sql.bak",
        "/dump.sql.gz", "/dump.sql.zip",
        "/backup.tar.gz", "/backup.zip",
        "/sql/", "/mysql/", "/postgres/",
    ]
    DETECTED_ID = 1

    def matches_path(self, path: str) -> bool:
        """Check if this handler should handle the given path."""
        path_lower = path.lower().split("?")[0]
        return any(path_lower.startswith(pattern) or path_lower == pattern for pattern in self.PATH_PATTERNS)

    def generate_response(
        self,
        path: str,
        raw_request: str,
        bot_ip: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[bytes, int]:
        """Generate a config disclosure response for the given request."""
        profile = self.get_or_create_profile(bot_ip)

        request_data = {
            "path": path,
            "method": self._extract_method(raw_request),
            "headers": dict(headers) if headers else {},
            "raw": raw_request,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        profile.record_request(request_data)

        method = self._extract_method(raw_request)
        path_lower = path.lower()

        # Escalate on config file access attempts
        profile.escalation_label = "config_file_probe"

        # Determine which config file to serve
        if "/wp-config.php" in path_lower:
            body = self._wp_config_php()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/x-httpd-php"}), self.DETECTED_ID

        if "/xmlrpc.php" in path_lower:
            body = self._xmlrpc_php()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/x-httpd-php"}), self.DETECTED_ID

        if "/.env" in path_lower:
            body = self._env_file()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/.htaccess" in path_lower:
            body = self._htaccess_file()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/.htpasswd" in path_lower:
            body = self._htpasswd_file()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/config.php" in path_lower or "/configuration.php" in path_lower:
            body = self._config_php()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/x-httpd-php"}), self.DETECTED_ID

        if "/settings.py" in path_lower:
            body = self._settings_py()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/x-python"}), self.DETECTED_ID

        if "/database.yml" in path_lower:
            body = self._database_yml()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/x-yaml"}), self.DETECTED_ID

        if "/config.json" in path_lower:
            body = self._config_json()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/json"}), self.DETECTED_ID

        if "/web.config" in path_lower:
            body = self._web_config()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/xml"}), self.DETECTED_ID

        if "/phpinfo.php" in path_lower or "/info.php" in path_lower:
            body = self._phpinfo_php()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/html"}), self.DETECTED_ID

        if "/php.ini" in path_lower:
            body = self._php_ini()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/my.cnf" in path_lower or "/mysqld.cnf" in path_lower:
            body = self._my_cnf()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/nginx.conf" in path_lower:
            body = self._nginx_conf()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/docker-compose.yml" in path_lower:
            body = self._docker_compose_yml()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/x-yaml"}), self.DETECTED_ID

        if "/Dockerfile" in path_lower:
            body = self._dockerfile()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/plain"}), self.DETECTED_ID

        if "/composer.json" in path_lower:
            body = self._composer_json()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/json"}), self.DETECTED_ID

        if "/package.json" in path_lower:
            body = self._package_json()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/json"}), self.DETECTED_ID

        if "/backup.sql" in path_lower or "/dump.sql" in path_lower or "/database.sql" in path_lower:
            body = self._backup_sql()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "application/sql"}), self.DETECTED_ID

        if "/db/" in path_lower or "/mysql/" in path_lower or "/postgres/" in path_lower:
            body = self._db_directory()
            return self._build_http_response(body, 200, "OK", {"Content-Type": "text/html"}), self.DETECTED_ID

        # Default: serve wp-config.php as the most common target
        body = self._wp_config_php()
        return self._build_http_response(body, 200, "OK", {"Content-Type": "application/x-httpd-php"}), self.DETECTED_ID

    def _wp_config_php(self) -> str:
        """Fake wp-config.php with realistic but fake credentials."""
        return r"""<?php
/**
 * Custom WordPress configurations on "wp-config.php" file.
 *
 * This file has the following configurations: MySQL settings, Table Prefix, Secret Keys, WordPress Language, ABSPATH and more.
 * For more information visit {@link https://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php} Codex page.
 * Created using {@link http://generatewp.com/wp-config/ wp-config.php File Generator} on GenerateWP.com.
 *
 * @package WordPress
 * @generator GenerateWP.com
 */

/* MySQL settings */
define( 'DB_NAME',     'wpdb' );
define( 'DB_USER',     'root' );
define( 'DB_PASSWORD', 'jadolbaeb' );
define( 'DB_HOST',     'localhost' );
define( 'DB_CHARSET',  'utf8mb4' );
define( 'DB_COLLATE',  '' );

/* MySQL database table prefix. */
$table_prefix = 'wp_';

/* Authentication Unique Keys and Salts. */
define('AUTH_KEY',         'Xm3Kp9vN2lR8wQ7jH5tY6uI1oP0aS4dFgBcVnMxZlKjHgFdSaWqWeRtYuIoP');
define('SECURE_AUTH_KEY',  'QwErTyUiOpAsDfGhJkLzXcVbNmWqWeRtYuIoPaSdFgHjKlZxCvBnM');
define('LOGGED_IN_KEY',    'ZxCvBnMqWeRtYuIoPaSdFgHjKlZxQwErTyUiOpAsDfGhJkLzXcVbNm');
define('NONCE_KEY',        'LkMjNhBgYtUeWrOpIaDsFgHjKlZxQwErTyUiOpAsDfGhJkLzXcVbNm');
define('AUTH_SALT',        'BnMqWeRtYuIoPaSdFgHjKlZxQwErTyUiOpAsDfGhJkLzXcVbNmQwEr');
define('SECURE_AUTH_SALT', 'TyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLzXcVbNmQwErTy');
define('LOGGED_IN_SALT',   'UiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUi');
define('NONCE_SALT',       'OpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOp');

/* WordPress Localized Language. */
define('WPLANG', '');
define('WP_LANG_DIR', WP_CONTENT_DIR . '/languages');

/* Debug mode */
// define('WP_DEBUG', true);
// define('WP_DEBUG_LOG', true);
// define('WP_DEBUG_DISPLAY', false);

/* Absolute path to the WordPress directory. */
if ( ! defined('ABSPATH') )
    define('ABSPATH', dirname(__FILE__) . '/');

/* Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');

/** Mail server information */
define('SMTP_HOST', 'mail.example.com');
define('SMTP_PORT', 587);
define('SMTP_USER', 'wordpress@example.com');
define('SMTP_PASS', 'Wp$M@il2024!');
define('SMTP_FROM', 'wordpress@example.com');
define('SMTP_NAME', 'WordPress Site');
"""

    def _xmlrpc_php(self) -> str:
        """Fake xmlrpc.php with realistic but fake response."""
        return r"""<?php
// XML-RPC endpoint for WordPress
// This file is used to allow remote procedure calls to WordPress

define('WP_USE_THEMES', false);
require('./wp-blog-header.php');

/**
 * WordPress RPC handler
 *
 * @package WordPress
 */

$XRPC_REQUEST = true;
$wp = new WP();
$wp->main();

class WP {
    function main() {
        global $HTTP_RAW_POST_DATA;
        if (isset($HTTP_RAW_POST_DATA)) {
            $request = $HTTP_RAW_POST_DATA;
        }
        
        // Handle pingback
        if (isset($request)) {
            $ixr = new IXR_Request($request);
            $error = $ixr->error;
            if ($error) {
                $ixr->sendError(-32700, 'Parse error. Not SOAP or XML-RPC');
                return;
            }
            $method = $ixr->method;
            $params = $ixr->params;
            
            // Simulate response
            $response = new IXR_Response("200 OK");
            $response->send();
        }
    }
}
"""

    def _env_file(self) -> str:
        """Fake .env file."""
        return r"""# Environment Configuration File
# This file contains sensitive environment variables

# Application Settings
APP_NAME="MyApp"
APP_ENV=production
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz123456=
APP_DEBUG=true
APP_URL=http://localhost

# Database Settings
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=myapp_db
DB_USERNAME=root
DB_PASSWORD=R00tP@ssw0rd!2024

# Redis Settings
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=RedisP@ss!

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

# Mail Settings
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=mailtrap_username
MAIL_PASSWORD=mailtrap_password
MAIL_ENCRYPTION=tls

# API Keys
STRIPE_KEY=sk_test_51234567890abcdefghijklmnop
STRIPE_SECRET=sk_test_51234567890qrstuvwxyzabcdef
SENDGRID_API_KEY=SG.abcdefghijklmnop.qrstuvwxyz1234567890ABCDEF
GOOGLE_MAPS_API_KEY=AIzaSyA1B2C3D4E5F6G7H8I9J0K
FACEBOOK_APP_SECRET=1234567890abcdefghijklmnop
TWITTER_SECRET=abcdefghijklmnopqrstuvwxyz1234567890ABCDEF

# JWT Settings
JWT_SECRET=my-secret-jwt-key-that-should-not-be-here
JWT_EXPIRATION=3600

# Session Settings
SESSION_DRIVER=file
SESSION_LIFETIME=120
"""

    def _htaccess_file(self) -> str:
        """Fake .htaccess file."""
        return r"""# Apache Configuration
# Generated by Apache/2.4.57 (Ubuntu)

# Prevent directory listing
Options -Indexes

# Disable server signature
ServerSignature Off
ServerTokens Prod

# Security Headers
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-XSS-Protection "1; mode=block"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
</IfModule>

# Deny access to hidden files
<FilesMatch "^\.">
    Order allow,deny
    Deny from all
</FilesMatch>

# PHP settings
<IfModule mod_php.c>
    php_flag display_errors Off
    php_flag allow_url_include Off
    php_flag expose_php Off
    php_value max_execution_time 30
    php_value max_input_time 60
    php_value memory_limit 256M
    php_value post_max_size 20M
    php_value upload_max_filesize 20M
</IfModule>

# Cache control
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>

# Rewrite rules
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>

# Block access to sensitive files
<FilesMatch "(^\.ht|\.sql|\.log|\.ini|\.conf)$">
    Order allow,deny
    Deny from all
</FilesMatch>
"""

    def _htpasswd_file(self) -> str:
        """Fake .htpasswd file."""
        return r"""# Apache htpasswd file
# Generated for basic authentication
admin:$apr1$xyz$KjH8gF2dLmNpQrStUvWxYz
webmaster:$apr1$abc$AbCdEfGhIjKlMnOpQrStUv
backup:$apr1$def$BcDeFgHiJkLmNoPqRsTuVw
deploy:$apr1$ghi$CdEfGhIjKlMnOpQrStUvWx
"""

    def _config_php(self) -> str:
        """Fake config.php for Joomla/Drupal."""
        return r"""<?php
/**
 * Joomla! Configuration Object
 * Generated: 2024-01-15 10:30:00 UTC
 */

class JConfig {
    public $offline = '0';
    public $offline_message = 'Site is currently under maintenance.<br /> Please check back soon.';
    public $display_offline_message = '1';
    public $offline_image = '';
    public $sitename = 'My Joomla Site';
    public $editor = 'tinymce';
    public $captcha = '0';
    public $list_limit = '20';
    public $access = '1';
    public $cache_path = JPATH_CACHE . '/';
    public $cache_handler = 'file';
    public $cachetime = '15';
    public $cache_platformprefix = '0';
    public $MetaDesc = 'My Joomla Site Description';
    public $MetaKeys = 'joomla,website';
    public $MetaTitle = '1';
    public $MetaAuthor = '1';
    public $MetaVersion = '0';
    public $robots = '';
    public $sef = '1';
    public $sef_rewrite = '1';
    public $sef_suffix = '0';
    public $unicodeslugs = '0';
    public $meta_mode = '1';
    public $MetaRights = '';
    public $list_reverse_order = '0';
    public $config_lifetime = '1';
    public $helpurl = 'https://help.joomla.org';
    public $force_ssl = '0';
    public $host = 'localhost';
    public $port = '3306';
    public $user = 'root';
    public $password = 'J00ml@P@ss!2024';
    public $dbtype = 'mysqli';
    public $db = 'joomladb';
    public $live_site = '';
    public $log_path = JPATH_SITE . '/logs';
    public $tmp_path = JPATH_SITE . '/tmp';
    public $ftp_host = '127.0.0.1';
    public $ftp_port = '21';
    public $ftp_user = 'ftpuser';
    public $ftp_pass = 'FtpP@ss!';
    public $ftp_root = '';
    public $ftp_enable = '0';
    public $offset = 'UTC';
    public $salt = 'abcdefghijklmnopqrstuvwxyz123456';
    public $crypted = '1';
    public $mailer = 'mail';
    public $mailfrom = 'admin@example.com';
    public $fromname = 'My Joomla Site';
    public $sendmail = '/usr/sbin/sendmail';
    public $smtpauth = '0';
    public $smtpuser = '';
    public $smtppass = '';
    public $smtphost = 'localhost';
    public $smtpsecure = 'none';
    public $smtpport = '25';
    public $caching = '1';
    public $cachetime = '15';
    public $cache_session = '0';
    public $cache_plugin = '0';
    public $caching_locking = '1';
    public $check_version = '0';
    public $error_reporting = 'default';
    public $debug = '0';
    public $debug_lang = '0';
    public $debug_lang_const = '0';
    public $dblegacy = '0';
    public $lifetime = '15';
    public $session_handler = 'database';
    public $shared_session = '0';
}
"""

    def _settings_py(self) -> str:
        """Fake Django settings.py."""
        return r"""# Django settings configuration
# Generated: 2024-01-15

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz1234567890'

DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'example.com', '*.example.com']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'django.contrib.admindocs',
    'django.contrib.sitemaps',
    'django.contrib.humanize',
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

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'myproject_db',
        'USER': 'root',
        'PASSWORD': 'Djang0DBP@ss!',
        'HOST': 'localhost',
        'PORT': '3306',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.example.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'noreply@example.com'
EMAIL_HOST_PASSWORD = 'Em@ilP@ss2024!'
EMAIL_USE_TLS = True

# AWS S3 configuration
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
AWS_STORAGE_BUCKET_NAME = 'myproject-media'
AWS_S3_REGION_NAME = 'us-east-1'
AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'

# Redis cache
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PASSWORD': 'RedisP@ss!',
        }
    }
}

# Celery configuration
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/1'
"""

    def _database_yml(self) -> str:
        """Fake Rails database.yml."""
        return r"""# Rails database configuration
# Generated: 2024-01-15

default: &default
  adapter: mysql2
  encoding: unicode
  pool: 5
  timeout: 5000
  host: localhost
  port: 3306

development:
  <<: *default
  database: myapp_development
  username: root
  password: RailsDBP@ss!

test:
  <<: *default
  database: myapp_test
  username: root
  password: RailsDBP@ss!

staging:
  <<: *default
  database: myapp_staging
  username: rails_user
  password: St@gingDBP@ss!
  host: staging-db.example.com

production:
  <<: *default
  database: myapp_production
  username: rails_prod
  password: Pr0ductionDBP@ss!2024
  host: production-db.example.com
  pool: 25
  timeout: 10000

# Additional services
redis:
  url: redis://127.0.0.1:6379/0
  password: RedisP@ss!

aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: us-east-1
"""

    def _config_json(self) -> str:
        """Fake config.json."""
        import json
        return json.dumps({
            "database": {
                "host": "localhost",
                "port": 3306,
                "name": "myapp_db",
                "username": "root",
                "password": "JSONDBP@ss!",
                "driver": "mysql",
            },
            "redis": {
                "host": "127.0.0.1",
                "port": 6379,
                "password": "RedisP@ss!",
                "db": 0,
            },
            "aws": {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
                "bucket": "myapp-assets",
            },
            "smtp": {
                "host": "smtp.example.com",
                "port": 587,
                "username": "noreply@example.com",
                "password": "SmtpP@ss!",
                "from": "noreply@example.com",
            },
            "jwt": {
                "secret": "my-secret-jwt-key-should-not-be-here",
                "expiration": 3600,
            },
            "app": {
                "name": "MyApp",
                "version": "1.0.0",
                "debug": False,
                "port": 8080,
                "host": "0.0.0.0",
            },
        }, indent=2)

    def _web_config(self) -> str:
        """Fake web.config for .NET."""
        return r"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection" 
         connectionString="Data Source=SERVER\SQLSERVER;Initial Catalog=MyAppDB;User Id=admin;Password=NetDBP@ss!2024;" 
         providerName="System.Data.SqlClient" />
    <add name="RedisConnection" 
         connectionString="127.0.0.1:6379,password=RedisP@ss!,defaultdatabase=0" 
         providerName="StackExchange.Redis" />
  </connectionStrings>
  <appSettings>
    <add key="AWSAccessKey" value="AKIAIOSFODNN7EXAMPLE" />
    <add key="AWSSecretKey" value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" />
    <add key="SmtpHost" value="smtp.example.com" />
    <add key="SmtpPort" value="587" />
    <add key="SmtpUser" value="noreply@example.com" />
    <add key="SmtpPass" value="SmtpP@ss!" />
    <add key="JWTSecret" value="my-secret-jwt-key-should-not-be-here" />
    <add key="GoogleMapsApiKey" value="AIzaSyA1B2C3D4E5F6G7H8I9J0K" />
  </appSettings>
  <system.web>
    <compilation debug="true" targetFramework="4.8" />
    <httpRuntime targetFramework="4.8" />
    <customErrors mode="Off" />
  </system.web>
</configuration>
"""

    def _phpinfo_php(self) -> str:
        """Fake phpinfo() output."""
        return r"""<?php
phpinfo();
?>
"""

    def _php_ini(self) -> str:
        """Fake php.ini."""
        return r"""[PHP]
engine = On
short_open_tag = Off
precision = 14
y2k_compliance = On
error_reporting = E_ALL
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
error_log = /var/log/php/errors.log
track_errors = Off
html_errors = Off
variables_order = "GPCS"
request_order = "GP"
register_globals = Off
register_long_arrays = Off
magic_quotes_gpc = Off
magic_quotes_runtime = Off
magic_quotes_sybase = Off
auto_globals_jit = On
post_max_size = 50M
upload_max_filesize = 50M
max_file_uploads = 20
max_execution_time = 30
max_input_time = 60
memory_limit = 256M
expose_php = Off
realpath_cache_size = 16k
realpath_cache_ttl = 3600
default_mimetype = "text/html"
default_charset = "UTF-8"
file_uploads = On
allow_url_fopen = On
allow_url_include = Off
disable_functions = "passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_restore,dl,pfsockopen,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,fopen,fsockopen"
disable_classes = ""
zend.enable_gc = On
extension_dir = "/usr/lib/php/20210902"
extension=mysqli.so
extension=pdo_mysql.so
extension=gd.so
extension=mbstring.so
extension=xml.so
extension=curl.so
extension=zip.so
extension=opcache.so

[mail function]
SMTP = localhost
smtp_port = 25
mail.add_x_header = On

[session]
session.save_handler = files
session.save_path = "/tmp"
session.use_strict_mode = On
session.use_cookies = On
session.use_only_cookies = On
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 0
session.cookie_path = /
session.cookie_domain = 
session.cookie_httponly = On
session.cookie_samesite = Lax
session.serialize_handler = php
session.gc_maxlifetime = 1440
session.gc_probability = 1
session.gc_divisor = 1000
"""

    def _my_cnf(self) -> str:
        """Fake my.cnf (MySQL config)."""
        return r"""[mysqld]
user = root
port = 3306
socket = /var/run/mysqld/mysqld.sock
pid-file = /var/run/mysqld/mysqld.pid
datadir = /var/lib/mysql
max_connections = 200
max_allowed_packet = 64M
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_error = /var/log/mysql/error.log
bind-address = 0.0.0.0
server-id = 1
log_bin = /var/log/mysql/mysql-bin.log
binlog_format = ROW
expire_logs_days = 7
max_binlog_size = 100M
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

[client]
port = 3306
socket = /var/run/mysqld/mysqld.sock
default-character-set = utf8mb4

[mysql]
auto-rehash
default-character-set = utf8mb4

[mysqldump]
quick
quote-names
max_allowed_packet = 64M
user = root
password = MySQLR00tP@ss!2024
"""

    def _nginx_conf(self) -> str:
        """Fake nginx.conf."""
        return r"""# Main nginx configuration
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;

events {
    worker_connections 768;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Upstream configuration
    upstream backend {
        server 127.0.0.1:8080;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name example.com www.example.com;
        root /var/www/html;
        index index.php index.html;

        location / {
            try_files $uri $uri/ /index.php?$query_string;
        }

        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }

        location ~ /\.ht {
            deny all;
        }

        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # API proxy
        location /api/ {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # SSL configuration
        # listen 443 ssl http2;
        # ssl_certificate /etc/ssl/certs/example.com.crt;
        # ssl_certificate_key /etc/ssl/private/example.com.key;
        # ssl_protocols TLSv1.2 TLSv1.3;
        # ssl_ciphers HIGH:!aNULL:!MD5;
    }

    # Include additional configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""

    def _docker_compose_yml(self) -> str:
        """Fake docker-compose.yml."""
        return r"""version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=mysql://root:R00tP@ss!2024@db:3306/myapp
      - REDIS_URL=redis://:RedisP@ss!@redis:6379/0
      - AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      - JWT_SECRET=my-secret-jwt-key-should-not-be-here
      - SMTP_PASSWORD=SmtpP@ss!
    depends_on:
      - db
      - redis
    volumes:
      - ./app:/app
      - /app/node_modules

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: R00tP@ss!2024
      MYSQL_DATABASE: myapp
      MYSQL_USER: appuser
      MYSQL_PASSWORD: AppUs3rP@ss!
    ports:
      - "3306:3306"
    volumes:
      - db_data:/var/lib/mysql

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass RedisP@ss!
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - app

volumes:
  db_data:
"""

    def _dockerfile(self) -> str:
        """Fake Dockerfile."""
        return r"""FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DATABASE_URL=mysql://root:R00tP@ss!2024@db:3306/myapp
ENV REDIS_URL=redis://:RedisP@ss!@redis:6379/0
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Expose port
EXPOSE 8080

# Start the application
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:create_app"]
"""

    def _composer_json(self) -> str:
        """Fake composer.json."""
        import json
        return json.dumps({
            "name": "mycompany/myapp",
            "description": "My Application",
            "type": "project",
            "license": "MIT",
            "require": {
                "php": ">=8.1",
                "laravel/framework": "^10.0",
                "laravel/sanctum": "^3.2",
                "laravel/socialite": "^5.9",
                "laravel/ui": "^4.2",
                "guzzlehttp/guzzle": "^7.2",
                "doctrine/dbal": "^3.6",
                "predis/predis": "^2.1",
                "laravel/passport": "^11.6",
                "spatie/laravel-permission": "^5.9",
                "barryvdh/laravel-debugbar": "^3.8",
                "barryvdh/laravel-ide-helper": "^2.13",
                "fakerphp/faker": "^1.23",
                "phpunit/phpunit": "^10.0",
            },
            "config": {
                "optimize-autoloader": true,
                "preferred-install": "dist",
                "sort-packages": true,
            },
            "extra": {
                "laravel": {
                    "dont-discover": [],
                },
            },
        }, indent=2)

    def _package_json(self) -> str:
        """Fake package.json."""
        import json
        return json.dumps({
            "name": "myapp-frontend",
            "version": "1.0.0",
            "description": "My App Frontend",
            "main": "index.js",
            "scripts": {
                "dev": "vite",
                "build": "vite build",
                "preview": "vite preview",
                "test": "jest",
                "lint": "eslint .",
            },
            "dependencies": {
                "react": "^18.2.0",
                "react-dom": "^18.2.0",
                "react-router-dom": "^6.14.0",
                "axios": "^1.4.0",
                "zustand": "^4.3.0",
                "tailwindcss": "^3.3.0",
                "lucide-react": "^0.263.0",
                "@tanstack/react-query": "^4.32.0",
                "react-hook-form": "^7.45.0",
                "yup": "^1.2.0",
            },
            "devDependencies": {
                "@types/react": "^18.2.0",
                "@types/react-dom": "^18.2.0",
                "@vitejs/plugin-react": "^4.0.0",
                "autoprefixer": "^10.4.0",
                "eslint": "^8.45.0",
                "jest": "^29.6.0",
                "postcss": "^8.4.0",
                "typescript": "^5.1.0",
                "vite": "^4.4.0",
            },
        }, indent=2)

    def _backup_sql(self) -> str:
        """Fake SQL backup dump."""
        return r"""-- MySQL dump 10.13  Distrib 8.0.35
-- Host: localhost    Database: myapp_db
-- Server version	8.0.35-0ubuntu0.22.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

-- Table structure for `users`
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(50) DEFAULT 'user',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dumping data for table `users`
INSERT INTO `users` VALUES (1,'Admin','admin@example.com','$2b$12$LJ3m4ys3Lg0Fm8YvGqK1RuF5vX8pQ2zW7oN1eR6tY9uI0pA3sD5fG','admin','2024-01-01 00:00:00','2024-01-01 00:00:00');
INSERT INTO `users` VALUES (2,'John Doe','john@example.com','$2b$12$KlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj','user','2024-01-02 00:00:00','2024-01-02 00:00:00');
INSERT INTO `users` VALUES (3,'Jane Smith','jane@example.com','$2b$12$AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz','user','2024-01-03 00:00:00','2024-01-03 00:00:00');

-- Table structure for `sessions`
DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
  `id` varchar(255) NOT NULL,
  `user_id` int DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text,
  `payload` text NOT NULL,
  `last_activity` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sessions_user_id_index` (`user_id`),
  KEY `sessions_last_activity_index` (`last_activity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for `api_keys`
DROP TABLE IF EXISTS `api_keys`;
CREATE TABLE `api_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `key` varchar(255) NOT NULL,
  `secret` varchar(255) NOT NULL,
  `permissions` varchar(255) DEFAULT 'read,write',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `api_keys` VALUES (1,1,'ak_live_1234567890abcdef','sk_live_0987654321fedcba','admin','2024-01-01 00:00:00');
INSERT INTO `api_keys` VALUES (2,2,'ak_test_abcdef1234567890','sk_test_fedcba0987654321','read','2024-01-02 00:00:00');

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40014 SET UNIQUE_CHECKS=IFNULL(@OLD_UNIQUE_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
"""

    def _db_directory(self) -> str:
        """Fake database directory listing."""
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /database</title>
 </head>
 <body>
<h1>Index of /database</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a>       </td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="backup.sql">backup.sql</a>                </td><td align="right">2024-01-15 10:30  </td><td align="right">  45K </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="dump.sql">dump.sql</a>                  </td><td align="right">2024-01-15 10:30  </td><td align="right">  128K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="database.sql">database.sql</a>              </td><td align="right">2024-01-10 08:15  </td><td align="right">  256K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="config.php">config.php</a>                </td><td align="right">2024-01-10 08:15  </td><td align="right">  2.1K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href=".htaccess">.htaccess</a>                 </td><td align="right">2024-01-10 08:15  </td><td align="right">  512 </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.57 (Ubuntu) Server at example.com Port 80</address>
</body>
</html>"""

    def _extract_method(self, raw_request: str) -> str:
        """Extract HTTP method from raw request."""
        parts = raw_request.split()
        if parts and len(parts) >= 1:
            return parts[0].upper()
        return "GET"

    def _build_http_response(self, body: str | bytes, status_code: int = 200, status_text: str = "OK", headers: dict | None = None) -> bytes:
        """Build a complete HTTP response."""
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body
        
        now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        
        resp_headers = {
            "Server": "Apache/2.4.57 (Ubuntu)",
            "Date": now,
            "Connection": "close",
        }
        if headers:
            resp_headers.update(headers)
        
        header_lines = []
        for key, value in resp_headers.items():
            header_lines.append(f"{key}: {value}")
        
        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            + "\r\n".join(header_lines) + "\r\n"
            + "\r\n"
        )
        
        return response.encode("iso-8859-1") + body_bytes

    def __repr__(self) -> str:
        return f"ConfigDisclosureHandler(domain={self.domain!r})"
