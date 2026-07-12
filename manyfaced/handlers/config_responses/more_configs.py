"""Additional configuration-file responses for ConfigDisclosureHandler.

These builders cover artifact types referenced by routes_config_disclosure.py
that had no bespoke fake body before (e.g. Gemfile, postgresql.conf, redis.conf,
.git/index, generic PHP/YAML/INI files). Each returns realistic-but-fake
content appropriate to its artifact type so a scanner receives a plausible
disclosure body instead of a mismatched wp-config.php page.
"""

from __future__ import annotations


def fake_gemfile() -> str:
    """Fake Ruby Gemfile."""
    return r"""source "https://rubygems.org"

ruby "3.2.2"

gem "rails", "7.1.2"
gem "pg", "~> 1.5"
gem "puma", "~> 6.4"
gem "redis", "~> 5.0"
gem "sidekiq", "~> 7.1"
gem "devise", "~> 4.9"
gem "jbuilder"

group :development, :test do
  gem "rspec-rails"
  gem "pry-byebug"
end

group :development do
  gem "letter_opener"
end"""


def fake_gemfile_lock() -> str:
    """Fake Gemfile.lock."""
    return r"""GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.2)
    actionmailbox (7.1.2)
    actionmailer (7.1.2)
    actionpack (7.1.2)
    actiontext (7.1.2)
    actionview (7.1.2)
    activejob (7.1.2)
    activemodel (7.1.2)
    activerecord (7.1.2)
    railties (7.1.2)
    rails (7.1.2)

PLATFORMS
  ruby

DEPENDENCIES
  pg (~> 1.5)
  puma (~> 6.4)
  rails (= 7.1.2)
  redis (~> 5.0)

BUNDLED WITH
   2.5.9"""


def fake_postgresql_conf() -> str:
    """Fake postgresql.conf."""
    return r"""# PostgreSQL configuration file - manyfaced honeypot
# This is a fake artifact for security research only.

listen_addresses = 'localhost'
port = 5432
max_connections = 100
shared_buffers = 128MB
effective_cache_size = 4GB
work_mem = 4MB
maintenance_work_mem = 64MB
wal_level = replica
synchronous_commit = on
checkpoint_timeout = 5min
random_page_cost = 1.1

# Logging
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_min_duration_statement = 1000

# Auth
password_encryption = scram-sha-256
"""


def fake_redis_conf() -> str:
    """Fake redis.conf."""
    return r"""# Redis configuration file - manyfaced honeypot
# This is a fake artifact for security research only.

bind 127.0.0.1 -::1
protected-mode yes
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300
daemonize no
pidfile /var/run/redis/redis-server.pid
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
rdbcompression yes
dir /var/lib/redis
requirepass R3d1sP@ss!2024
maxmemory 256mb
maxmemory-policy allkeys-lru
"""


def fake_pip_conf() -> str:
    """Fake pip.conf."""
    return r"""[global]
index-url = https://pypi.internal.example.com/simple
trusted-host = pypi.internal.example.com
timeout = 60

[install]
cert = /etc/ssl/certs/internal-ca.pem
"""


def fake_requirements_txt() -> str:
    """Fake requirements.txt (Python)."""
    return r"""Django==4.2.7
djangorestframework==3.14.0
gunicorn==21.2.0
psycopg2-binary==2.9.9
redis==5.0.1
celery==5.3.4
requests==2.31.0
pillow==10.1.0
python-dotenv==1.0.0
"""


def fake_setup_cfg() -> str:
    """Fake setup.cfg (Python setuptools)."""
    return r"""[metadata]
name = myfaced-app
version = 1.0.0
description = Application configuration - honeypot artifact
author = Example Corp
license = MIT

[options]
packages = find:
python_requires = >=3.10

[options.packages.find]
exclude =
    tests
    docs
"""


def fake_tox_ini() -> str:
    """Fake tox.ini."""
    return r"""[tox]
envlist = py310, py311, lint
skipsdist = True

[testenv]
deps = pytest
commands = pytest {posargs}

[testenv:lint]
deps = ruff
commands = ruff check .
"""


def fake_makefile() -> str:
    """Fake Makefile."""
    return r""".PHONY: build test lint deploy

build:
\tpython -m build

test:
\tpytest -q

lint:
\truth check .

deploy:
\tscp -r dist/* deploy@host:/srv/app/
"""


def fake_apache_conf() -> str:
    """Fake apache2.conf / apache.conf."""
    return r"""# Apache configuration - manyfaced honeypot
ServerRoot "/etc/apache2"
Listen 80
Listen 443

LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule ssl_module modules/mod_ssl.so

User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn

<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    DocumentRoot /var/www/html
</VirtualHost>
"""


def fake_httpd_conf() -> str:
    """Fake httpd.conf (RHEL-style Apache)."""
    return r"""# httpd.conf - manyfaced honeypot
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin admin@example.com
ServerName localhost:80
DocumentRoot "/var/www/html"
ErrorLog "logs/error_log"
LogLevel warn
CustomLog "logs/access_log" combined
"""


def fake_application_ini() -> str:
    """Fake application.ini (Zend/dotNet style config)."""
    return r"""[production]
phpSettings.display_errors = 0
phpSettings.date.timezone = "UTC"
bootstrap.path = APPLICATION_PATH "/Bootstrap.php"
bootstrap.class = "Bootstrap"
appnamespace = "Application"
resources.frontController.params.displayExceptions = 0

[staging : production]
phpSettings.display_errors = 1

[development : production]
phpSettings.display_errors = 1
phpSettings.error_reporting = E_ALL
"""


def fake_app_config() -> str:
    """Fake app.config (.NET)."""
    return r"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection"
         connectionString="Data Source=localhost;Initial Catalog=appdb;User Id=app_user;Password=AppP@ss!2024;"
         providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="Environment" value="Production" />
    <add key="SecretKey" value="base64:fakeappsecretkey0000000000000000=" />
  </appSettings>
</configuration>
"""


def fake_appsettings_json() -> str:
    """Fake appsettings.json (.NET)."""
    return r"""{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=appdb;User Id=app_user;Password=AppP@ss!2024;"
  },
  "Jwt": {
    "Key": "fake-jwt-signing-key-0000000000000000000000",
    "Issuer": "example.com"
  }
}"""


def fake_parameters_yml() -> str:
    """Fake parameters.yml (Symfony)."""
    return r"""parameters:
    database_host: 127.0.0.1
    database_port: 3306
    database_name: symfony_db
    database_user: symfony_user
    database_password: SymfonyP@ss!2024
    mailer_transport: smtp
    mailer_host: 127.0.0.1
    mailer_user: null
    mailer_password: null
    secret: fakeappsecretkey0000000000000000000000
"""


def fake_parameters_yml_dist() -> str:
    """Fake parameters.yml.dist (Symfony distribution template)."""
    return r"""parameters:
    database_host: 127.0.0.1
    database_port: '3306'
    database_name: symfony
    database_user: root
    database_password: null
    mailer_transport: smtp
    secret: ThisTokenIsNotSoSecretChangeIt
"""


def fake_service_yml() -> str:
    """Fake services.yml (Symfony)."""
    return r"""services:
    _defaults:
        autowire: true
        autoconfigure: true
        public: false

    App\:
        resource: '../src/*'
        exclude: '../src/{DependencyInjection,Entity,Migrations,Tests}'

    App\Controller\:
        resource: '../src/Controller'
        tags: ['controller.service_arguments']
"""


def fake_doctrine_yml() -> str:
    """Fake doctrine.yml (Symfony ORM)."""
    return r"""doctrine:
    dbal:
        driver: pdo_mysql
        host: '%database_host%'
        port: '%database_port%'
        dbname: '%database_name%'
        user: '%database_user%'
        password: '%database_password%'
        charset: utf8mb4
    orm:
        auto_generate_proxy_classes: '%kernel.debug%'
        naming_strategy: doctrine.orm.naming_strategy.underscore
"""


def fake_routing_yml() -> str:
    """Fake routing.yml (Symfony)."""
    return r"""app_homepage:
    path: /
    controller: App\Controller\HomeController::index

app_health:
    path: /health
    controller: App\Controller\HealthController::check
"""


def fake_security_yml() -> str:
    """Fake security.yml (Symfony)."""
    return r"""security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
    providers:
        app_users:
            entity:
                class: App\Entity\User
                property: username
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_users
            form_login:
                login_path: app_login
                check_path: app_login
"""


def fake_git_index() -> str:
    """Fake .git/index (binary-ish directory cache header shown as text)."""
    return r"""DIRC
# Fake git index - manyfaced honeypot
# This is a placeholder; a real .git/index is a binary packfile.
# 100644 blob 8a3203f7e61e6f6e3b0f4a9c2f3b7e5c1d2a3b4c	README.md
# 100644 blob 1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d	src/app.py
# 100644 blob a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0	requirements.txt
"""


def fake_generic_php() -> str:
    """Fake generic PHP config file (config.php / db.php / local.php etc.)."""
    return r"""<?php
/**
 * Application configuration - manyfaced honeypot (fake artifact).
 */

define('DB_HOST', 'localhost');
define('DB_NAME', 'app_db');
define('DB_USER', 'app_user');
define('DB_PASS', 'AppPhpP@ss!2024');

$config = array(
    'debug' => false,
    'secret_key' => 'base64:fakephpsecretkey0000000000000000000000=',
    'timezone' => 'UTC',
);
"""


def fake_generic_ini() -> str:
    """Fake generic INI config file (application.ini etc.)."""
    return r"""; Application configuration - manyfaced honeypot (fake artifact)
[database]
host = localhost
port = 3306
name = app_db
user = app_user
password = IniP@ss!2024

[app]
debug = 0
secret = fakeinisecretkey00000000000000000000
timezone = UTC
"""


def fake_generic_json() -> str:
    """Fake generic JSON config file (config.json / composer.json / package.json)."""
    return r"""{
  "name": "myfaced-honeypot-app",
  "version": "1.0.0",
  "description": "Application configuration - honeypot artifact",
  "database": {
    "host": "localhost",
    "port": 3306,
    "name": "app_db",
    "user": "app_user",
    "password": "Js0nP@ss!2024"
  }
}"""


def fake_generic_yaml() -> str:
    """Fake generic YAML config file (service.yml etc.)."""
    return r"""# Service configuration - manyfaced honeypot (fake artifact)
database:
  host: localhost
  port: 3306
  name: app_db
  user: app_user
  password: YamlP@ss!2024

app:
  debug: false
  secret: fakeyamlsecretkey0000000000000000000
"""


def fake_generic_text() -> str:
    """Generic but plausible plaintext config body for unknown artifacts."""
    return r"""# manyfaced honeypot - disclosure probe captured
# This is a decoy configuration artifact. No real secrets are present.
#
# Path requested matched a known sensitive-file disclosure route.
# The request was recorded as a config-disclosure exploit/IOC signal.
"""


def fake_sql_dump() -> str:
    """Fake SQL dump (backup.sql / dump.sql / database.sql / db.sql)."""
    return r"""-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
-- Host: localhost    Database: app_db

DROP TABLE IF EXISTS `config`;
CREATE TABLE `config` (
  `id` int NOT NULL AUTO_INCREMENT,
  `key` varchar(255) NOT NULL,
  `value` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `config` VALUES (1,'db_host','localhost');
INSERT INTO `config` VALUES (2,'db_user','app_user');
INSERT INTO `config` VALUES (3,'db_pass','SqlDumpP@ss!2024');

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
`id` int NOT NULL AUTO_INCREMENT,
`username` varchar(64) NOT NULL,
`password_hash` varchar(255) NOT NULL,
`email` varchar(128) DEFAULT NULL,
PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` VALUES (1,'admin','$2y$10$fakehash0000000000000000000000000000000000000000','admin@example.com');
"""
