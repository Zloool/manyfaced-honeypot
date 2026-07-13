"""Environment and security configuration responses for ConfigDisclosureHandler."""

from __future__ import annotations


def fake_env_file() -> str:
    """Fake .env file."""
    return r"""# Environment Configuration - manyfaced honeypot
APP_NAME="MyApp"
APP_ENV=production
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890ABCD=
APP_DEBUG=false
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=db.internal
DB_PORT=3306
DB_DATABASE=myapp_production
DB_USERNAME=deploy_user
DB_PASSWORD=D3pl0yP@ss!2024

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

REDIS_HOST=cache.internal
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=mail.internal
MAIL_PORT=587
MAIL_USERNAME=noreply@example.com
MAIL_PASSWORD=M@ilP@ss!2024"""


def fake_backup_sql() -> str:
    """Fake backup SQL dump."""
    return r"""-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
-- Host: localhost    Database: myapp_production
-- Server version	8.0.36

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;

-- Table structure for table `users`
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dumping data for table `users`
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','admin@example.com','$2b$12$LJ3m4ys3Lg8MqE7xK5pY6eRzNwQvBcDfGhIjKlMnOpQrStUvWxYz',1,now(),now());
INSERT INTO `users` VALUES (2,'webmaster','web@example.com','$2b$12$AbCdEfGhIjKlMnOpQrStUvWxYz1234567890aBcDeFgHiJkLmNoPqRs',1,now(),now());
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;"""


def fake_db_directory() -> str:
    """Fake .db directory listing."""
    return r"""drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 ./
drwxr-xr-x 8 www-data www-data 4096 Jan 15 10:30 ../
-rw-r--r-- 1 www-data www-data  220 Jan 15 10:30 .htaccess
-rw-r--r-- 1 www-data www-data 8192 Jan 15 10:30 app.db
-rw-r--r-- 1 www-data www-data 4096 Jan 15 10:30 cache.db
-rw-r--r-- 1 www-data www-data 2048 Jan 15 10:30 sessions.db"""


def fake_git_config() -> str:
    """Fake .git/config."""
    return r"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@github.com:company/myapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main"""


def fake_git_head() -> str:
    """Fake .git/HEAD."""
    return r"""ref: refs/heads/main"""


def fake_security_txt() -> str:
    """Fake security.txt with a future-dated Expires.

    The Expires value is computed dynamically (one year out) so the contact
    file never reads as stale/abandoned to scanners (issue #479). A real
    security.txt with an already-past Expires is itself a fingerprint of an
    unmaintained deployment.
    """
    from datetime import datetime, timedelta, timezone

    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    return (
        f'Contact: mailto:security@example.com\n'
        f'Expires: {expires}\n'
        f'Encryption: https://example.com/.well-known/security.txt.asc\n'
        f'Preferred-Languages: en, de\n'
        f'Policy: https://example.com/security-policy\n'
        f'Hiring: https://example.com/careers'
    )
