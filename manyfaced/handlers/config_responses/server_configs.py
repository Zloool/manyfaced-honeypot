"""Server and web server configuration responses for ConfigDisclosureHandler."""

from __future__ import annotations


def fake_htaccess_file() -> str:
    """Fake .htaccess file."""
    return r"""# Apache Configuration - manyfaced honeypot
# Generated for security research purposes only

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    
    # Block access to sensitive files
    <FilesMatch "^\.">
        Order allow,deny
        Deny from all
    </FilesMatch>
    
    # Protect wp-config.php
    <Files wp-config.php>
        Order deny,allow
        Deny from all
    </Files>
    
    # Prevent directory listing
    Options -Indexes
    
    # Set default charset
    AddDefaultCharset UTF-8
    
    # Enable GZIP compression
    <IfModule mod_deflate.c>
        AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript
    </IfModule>
</IfModule>

# Security headers
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-XSS-Protection "1; mode=block"
</IfModule>"""


def fake_htpasswd_file() -> str:
    """Fake .htpasswd file."""
    return r"""# Apache htpasswd file - manyfaced honeypot
admin:$apr1$xyz$K8sL2mN9pQ4rT6vW8xY0zA
webmaster:$apr1$abc$B7tM3nO5qR8uV0wX2yZ4aC
deploy:$apr1$def$C9uN4oP6sS0vW2xY4zA6bD"""


def fake_web_config() -> str:
    """Fake web.config (IIS)."""
    return r"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <directoryBrowse enabled="false" />
    <security>
      <requestFiltering>
        <hiddenSegments>
          <add segment="web.config" />
          <add segment="app_data" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
  <connectionStrings>
    <add name="DefaultConnection" 
         connectionString="Data Source=localhost;Initial Catalog=webdb;User ID=admin;Password=W3bDb!2024;" 
         providerName="System.Data.SqlClient" />
  </connectionStrings>
</configuration>"""


def fake_my_cnf() -> str:
    """Fake my.cnf (MySQL configuration)."""
    return r"""[mysqld]
port = 3306
socket = /var/run/mysqld/mysqld.sock
datadir = /var/lib/mysql
pid-file = /var/run/mysqld/mysqld.pid

# Security settings
skip-symbolic-links
local-infile = 0

# Performance settings
max_connections = 200
key_buffer_size = 256M
innodb_buffer_pool_size = 1G
query_cache_size = 64M

# Logging
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

[client]
port = 3306
socket = /var/run/mysqld/mysqld.sock
default-character-set = utf8mb4"""


def fake_nginx_conf() -> str:
    """Fake nginx.conf."""
    return r"""user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml;

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;
        
        server_name _;
        
        location / {
            try_files $uri $uri/ =404;
        }
        
        # Deny access to hidden files
        location ~ /\. {
            deny all;
        }
    }
}"""
