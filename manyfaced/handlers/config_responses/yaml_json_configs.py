"""YAML and JSON configuration responses for ConfigDisclosureHandler."""

from __future__ import annotations


def fake_database_yml() -> str:
    """Fake database.yml (Ruby on Rails)."""
    return r"""# Database configuration for manyfaced honeypot
default: &default
  adapter: mysql2
  encoding: unicode
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  host: localhost

development:
  <<: *default
  database: myapp_development
  username: root
  password: d3vP@ss!

test:
  <<: *default
  database: myapp_test
  username: root
  password: t3stP@ss!

production:
  <<: *default
  database: myapp_production
  username: deploy_user
  password: Pr0d$ecure2024!
  host: db.production.internal"""


def fake_config_json() -> str:
    """Fake config.json (Node.js application)."""
    return r"""{
  "name": "myfaced-honeypot-app",
  "version": "1.0.0",
  "description": "Application configuration - honeypot artifact",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mysql2": "^3.6.0",
    "dotenv": "^16.3.1"
  },
  "database": {
    "host": "localhost",
    "port": 3306,
    "name": "app_production",
    "user": "app_user",
    "password": "Db_P@ssw0rd!2024"
  },
  "redis": {
    "host": "127.0.0.1",
    "port": 6379,
    "password": null
  }
}"""


def fake_docker_compose_yml() -> str:
    """Fake docker-compose.yml."""
    return r"""version: '3.8'

services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./html:/usr/share/nginx/html
      - ./nginx/conf.d:/etc/nginx/conf.d
    depends_on:
      - app

  app:
    build: .
    environment:
      - DATABASE_URL=mysql://root:r00tP@ss!@db:3306/myapp
      - REDIS_URL=redis://cache:6379/0
      - SECRET_KEY=mysupersecretkey123456789
    depends_on:
      - db
      - cache

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: r00tP@ss!
      MYSQL_DATABASE: myapp
      MYSQL_USER: app_user
      MYSQL_PASSWORD: AppUs3rP@ss!
    volumes:
      - db_data:/var/lib/mysql

  cache:
    image: redis:7-alpine

volumes:
  db_data:"""


def fake_dockerfile() -> str:
    """Fake Dockerfile."""
    return r"""FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DATABASE_URL=mysql://root:r00tP@ss!@db:3306/myapp
ENV SECRET_KEY=mysupersecretkey123456789

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]"""


def fake_composer_json() -> str:
    """Fake composer.json (PHP)."""
    return r"""{
    "name": "vendor/myfaced-honeypot-app",
    "description": "Application configuration - honeypot artifact",
    "type": "project",
    "require": {
        "php": "^8.2",
        "laravel/framework": "^10.0",
        "guzzlehttp/guzzle": "^7.8"
    },
    "config": {
        "optimize-autoloader": true,
        "preferred-install": "dist",
        "sort-packages": true
    },
    "extra": {
        "laravel": {
            "dont-discover": []
        }
    }
}"""


def fake_package_json() -> str:
    """Fake package.json (Node.js)."""
    return r"""{
  "name": "myfaced-honeypot-frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "next": "^14.0.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  }
}"""
