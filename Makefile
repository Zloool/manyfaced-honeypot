# Manyfaced Honeypot — Makefile
#
# Development targets:
#   make install    — set up Python venv and install deps
#   make run        — run both client and server
#   make test       — run test suite
#   make lint       — run linter
#   make help       — show this help text
#
# Maintenance (run as root on target server):
#   make logrotate-install — install logrotate config
#   make backup-cron     — install database backup cron

PYTHON  := python3
VENV    := .venv
BIN     := $(VENV)/bin
PKG     := manyfaced

SERVER_PORT ?= 8080
CLIENT_PORT ?= 8081
LOGROTATE   := systemd/manyfaced.logrotate
BACKUP_SCRIPT := scripts/backup-db.sh
DEPLOY_USER   := honeypot

.DEFAULT_GOAL := help

# ──────────────────────────────────────────────────────────────────────────────
# Development
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: help venv install run test lint format clean \
        run-server run-client test-file

help:
	@echo "Manyfaced Honeypot — Makefile targets"
	@echo ""
	@echo "Development:"
	@echo "  make install      — set up venv and install deps"
	@echo "  make run          — run client + server"
	@echo "  make run-server   — run server only (SERVER_PORT=8080)"
	@echo "  make run-client   — run client only (CLIENT_PORT=8081)"
	@echo "  make test         — run test suite"
	@echo "  make test-file    — run a single test file (TEST_FILE=path)"
	@echo "  make lint         — run ruff check + format-check"
	@echo "  make format       — run ruff format"
	@echo "  make clean        — remove caches, venv, build artifacts"
	@echo ""
	@echo "Maintenance (run as root on droplet):"
	@echo "  make logrotate-install  — install logrotate config"
	@echo "  make backup-cron        — install DB backup cron"

venv:
	@$(PYTHON) -m venv $(VENV)
	@$(BIN)/pip install --upgrade pip setuptools wheel
	@$(BIN)/pip install -e ".[dev]"

install: venv
	@echo "Installed. Activate with: source $(VENV)/bin/activate"

run-server:
	@$(BIN)/$(PKG) --server $(SERVER_PORT)

run-client:
	@$(BIN)/$(PKG) --client $(CLIENT_PORT)

run:
	@$(BIN)/$(PKG) --server $(SERVER_PORT) --client $(CLIENT_PORT)

format:
	@$(BIN)/ruff format .

test:
	@$(BIN)/pytest -v $(TEST)

test-file:
	@$(BIN)/pytest $(TEST_FILE) -v

lint:
	@$(BIN)/ruff check .
	@$(BIN)/ruff format --check .

clean:
	@echo "Cleaning..."
	@find . -type d -name __pycache__ -exec rm -rf {} + || true
	@find . -type d -name '*.pyc' -exec rm -rf {} + || true
	@find . -type f -name '*.pyc' -delete || true
	@find . -type f -name '*.pyo' -delete || true
	@find . -type f -name '*.pyd' -delete || true
	@find . -type f -name '*.so' -delete || true
	@rm -rf $(VENV) .pytest_cache .ruff_cache build dist *.egg-info
	@echo "Clean complete."

# ──────────────────────────────────────────────────────────────────────────────
# Maintenance (run as root on target server)
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: logrotate-install backup-cron

logrotate-install:
	@echo "Installing logrotate config..."
	@if [ -f $(LOGROTATE) ]; then \
		cp $(LOGROTATE) /etc/logrotate.d/manyfaced; \
		echo "  Installed to /etc/logrotate.d/manyfaced"; \
	else \
		echo "  Template not found: $(LOGROTATE)"; \
	fi

backup-cron:
	@echo "Installing database backup cron..."
	@mkdir -p /opt/manyfaced/scripts
	@if [ -f $(BACKUP_SCRIPT) ]; then \
		cp $(BACKUP_SCRIPT) /opt/manyfaced/scripts/backup-db.sh; \
		chmod +x /opt/manyfaced/scripts/backup-db.sh; \
		(crontab -u $(DEPLOY_USER) -l 2>/dev/null | \
		 grep -v 'backup-db.sh' ; \
		 echo "0 3 * * * /opt/manyfaced/scripts/backup-db.sh" \
		) | crontab -u $(DEPLOY_USER) -; \
		echo "  Cron installed: daily at 3:00 AM"; \
	else \
		echo "  Backup script not found: $(BACKUP_SCRIPT)"; \
	fi

# ──────────────────────────────────────────────────────────────────────────────
# Database migration (run on target server after deploy / before restart)
# ──────────────────────────────────────────────────────────────────────────────

MIGRATE_SCRIPT := scripts/migrate_db.py
DB_PATH        ?= /opt/manyfaced/bots/honeypot.sqlite

.PHONY: migrate

migrate:
	@echo "Migrating SQLite schema at $(DB_PATH)..."
	@/opt/manyfaced/venv/bin/python3 $(MIGRATE_SCRIPT) --db $(DB_PATH)
