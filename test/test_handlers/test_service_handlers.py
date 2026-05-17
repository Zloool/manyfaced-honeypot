"""Tests for service-specific HTTP handlers."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure the project root is in sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from manyfaced.handlers import (
    WordPressHandler,
    PhpMyAdminHandler,
    JenkinsHandler,
    TomcatHandler,
    DrupalHandler,
    CPanelHandler,
    BitrixHandler,
    WebDAVHandler,
    ConfigDisclosureHandler,
)


class TestWordPressHandler(unittest.TestCase):
    """Test WordPressHandler responses."""

    def setUp(self):
        self.handler = WordPressHandler()

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/wp-login.php',
            'GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'WordPress', response)
        self.assertIn(b'wp-login.php', response)
        self.assertIn(b'Log In', response)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, detected = self.handler.generate_response(
            '/wp-login.php',
            'POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nlog=admin&pwd=secret123',
            '1.2.3.4',
        )
        # Should return login failed response (encourages brute force)
        self.assertIn(b'ERROR', response)
        self.assertIn(b'Invalid username', response)

    def test_admin_redirect(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/wp-admin/',
            'GET /wp-admin/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'wp-login.php', response)

    def test_xmlrpc_response(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/xmlrpc.php',
            'POST /xmlrpc.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'XML-RPC', response)


class TestPhpMyAdminHandler(unittest.TestCase):
    """Test PhpMyAdminHandler responses."""

    def setUp(self):
        self.handler = PhpMyAdminHandler()

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/phpmyadmin/',
            'GET /phpmyadmin/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'phpMyAdmin', response)
        self.assertIn(b'pma_username', response)
        self.assertIn(b'pma_password', response)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/phpmyadmin/index.php',
            'POST /phpmyadmin/index.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nserver=0&pma_username=root&pma_password=admin',
            '1.2.3.4',
        )
        self.assertIn(b'Access denied', response)


class TestJenkinsHandler(unittest.TestCase):
    """Test JenkinsHandler responses."""

    def setUp(self):
        self.handler = JenkinsHandler()

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/jenkins/login',
            'GET /jenkins/login HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Jenkins', response)
        self.assertIn(b'j_username', response)
        self.assertIn(b'j_password', response)

    def test_main_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/jenkins/',
            'GET /jenkins/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Jenkins', response)
        self.assertIn(b'build-app', response)


class TestTomcatHandler(unittest.TestCase):
    """Test TomcatHandler responses."""

    def setUp(self):
        self.handler = TomcatHandler()

    def test_manager_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/manager/html',
            'GET /manager/html HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Tomcat', response)
        self.assertIn(b'Manager', response)


class TestDrupalHandler(unittest.TestCase):
    """Test DrupalHandler responses."""

    def setUp(self):
        self.handler = DrupalHandler()

    def test_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/user/login',
            'GET /user/login HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Drupal', response)
        self.assertIn(b'edit-name', response)
        self.assertIn(b'edit-pass', response)


class TestBitrixHandler(unittest.TestCase):
    """Test BitrixHandler responses."""

    def setUp(self):
        self.handler = BitrixHandler()

    def test_admin_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/bitrix/admin/',
            'GET /bitrix/admin/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Bitrix', response)
        self.assertIn(b'Administrative Panel', response)
        self.assertIn(b'USER_LOGIN', response)
        self.assertIn(b'USER_PASSWORD', response)

    def test_auth_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/bitrix/auth/',
            'GET /bitrix/auth/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Bitrix', response)
        self.assertIn(b'USER_LOGIN', response)

    def test_setup_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/bitrix/setup/',
            'GET /bitrix/setup/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Bitrix', response)
        self.assertIn(b'Installation Wizard', response)

    def test_login_post_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/bitrix/admin/',
            'POST /bitrix/admin/ HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nUSER_LOGIN=admin&USER_PASSWORD=secret123',
            '1.2.3.4',
        )
        self.assertIn(b'Authorization Error', response)
        self.assertIn(b'Invalid login or password', response)


class TestWebDAVHandler(unittest.TestCase):
    """Test WebDAVHandler responses."""

    def setUp(self):
        self.handler = WebDAVHandler()

    def test_directory_listing(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/webdav/',
            'GET /webdav/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Index of', response)
        self.assertIn(b'webdav', response)
        self.assertIn(b'documents/', response)
        self.assertIn(b'uploads/', response)

    def test_propfind_response(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/webdav/',
            'PROPFIND /webdav/ HTTP/1.1\r\nHost: example.com\r\nDepth: 0\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'multistatus', response)
        self.assertIn(b'DAV:', response)
        self.assertIn(b'207', response)

    def test_options_response(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/webdav/',
            'OPTIONS /webdav/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'DAV', response)
        self.assertIn(b'PROPFIND', response)

    def test_basic_auth_captures_credentials(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        import base64

        auth = base64.b64encode(b'admin:secretpass').decode()
        response, _ = self.handler.generate_response(
            '/webdav/',
            'GET /webdav/ HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic '
            + auth
            + '\r\n\r\n',
            '1.2.3.4',
        )
        # WebDAV returns directory listing (honeypot doesn't enforce auth)
        self.assertIn(b'HTTP/1.1 200', response)
        self.assertIn(b'webdav', response.lower())

    def test_put_upload(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/webdav/upload.php',
            "PUT /webdav/malicious.php HTTP/1.1\r\nHost: example.com\r\n\r\n<?php system('id'); ?>",
            '1.2.3.4',
        )
        self.assertEqual(response.split()[1], b'201')

    def test_forbidden_sensitive_files(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/webdav/.htaccess',
            'GET /webdav/.htaccess HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'403', response)
        self.assertIn(b'Forbidden', response)


class TestConfigDisclosureHandler(unittest.TestCase):
    """Test ConfigDisclosureHandler responses."""

    def setUp(self):
        self.handler = ConfigDisclosureHandler()

    def test_wp_config_php(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/wp-config.php',
            'GET /wp-config.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'DB_NAME', response)
        self.assertIn(b'DB_USER', response)
        self.assertIn(b'DB_PASSWORD', response)
        self.assertIn(b'wpdb', response)

    def test_env_file(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/.env',
            'GET /.env HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'DB_CONNECTION', response)
        self.assertIn(b'DB_PASSWORD', response)
        self.assertIn(b'AWS_ACCESS_KEY_ID', response)

    def test_htaccess_file(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/.htaccess',
            'GET /.htaccess HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Options -Indexes', response)
        self.assertIn(b'X-Content-Type-Options', response)

    def test_htpasswd_file(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/.htpasswd',
            'GET /.htpasswd HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'$apr1$', response)
        self.assertIn(b'admin', response)

    def test_config_json(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/config.json',
            'GET /config.json HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'database', response)
        self.assertIn(b'password', response)
        self.assertIn(b'redis', response.lower())

    def test_database_yml(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/database.yml',
            'GET /database.yml HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'mysql2', response)
        self.assertIn(b'password', response)

    def test_settings_py(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/settings.py',
            'GET /settings.py HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'SECRET_KEY', response)
        self.assertIn(b'DATABASES', response)
        self.assertIn(b'password', response)

    def test_backup_sql(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/backup.sql',
            'GET /backup.sql HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'CREATE TABLE', response)
        self.assertIn(b'INSERT INTO', response)
        self.assertIn(b'users', response)

    def test_phpinfo(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/phpinfo.php',
            'GET /phpinfo.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'phpinfo', response)

    def test_docker_compose(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/docker-compose.yml',
            'GET /docker-compose.yml HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'mysql', response)
        self.assertIn(b'redis', response)
        self.assertIn(b'PASSWORD', response)

    def test_xmlrpc_php(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/xmlrpc.php',
            'GET /xmlrpc.php HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'XML-RPC', response)

    def test_git_config(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/.git/config',
            'GET /.git/config HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'[remote "origin"]', response)
        self.assertIn(b'git@github.com', response)
        self.assertIn(b'company/myapp', response)

    def test_git_head(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/.git/HEAD',
            'GET /.git/HEAD HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'ref: refs/heads/main', response)

    def test_security_txt(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/security.txt',
            'GET /security.txt HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Contact:', response)
        self.assertIn(b'mailto:security@example.com', response)
        self.assertIn(b'Expires:', response)

    def test_well_known_security_txt(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/.well-known/security.txt',
            'GET /.well-known/security.txt HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Contact:', response)
        self.assertIn(b'mailto:security@example.com', response)


class TestCPanelHandler(unittest.TestCase):
    """Test CPanelHandler responses."""

    def setUp(self):
        self.handler = CPanelHandler()

    def test_cpanel_login_page(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/cpanel/',
            'GET /cpanel/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'cPanel', response)
        self.assertIn(b'Login', response)

    def test_whm_login(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/whm/',
            'GET /whm/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'WHM', response)

    def test_webmail_login(self):
        profile = MagicMock()
        self.handler.bot_profiles = {'1.2.3.4': profile}
        response, _ = self.handler.generate_response(
            '/webmail/',
            'GET /webmail/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
            '1.2.3.4',
        )
        self.assertIn(b'Webmail', response)


if __name__ == '__main__':
    unittest.main()
