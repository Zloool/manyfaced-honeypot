# Manyfaced Honeypot — Makefile
#
# Development targets:
#   make install    — set up Python venv and install deps
#   make run        — run both client and server
#   make test       — run test suite
#   make lint       — run linter
#
# Systemd management (run as root on target server):
#   make systemd-install  — install systemd service
#   make logrotate-install — install logrotate config
#   make backup-cron     — install database backup cron

PYTHON  := python3
VENV    := .venv
BIN     := $(VENV)/bin
PKG     := manyfaced

SYSTEMD_UNIT  := systemd/manyfaced.service
LOGROTATE     := systemd/manyfaced.logrotate
BACKUP_SCRIPT := scripts/backup-db.sh
DEPLOY_USER   := honeypot

# ──────────────────────────────────────────────────────────────────────────────
# Development
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: venv install run dev test lint format clean

venv:
	@$(PYTHON) -m venv $(VENV)
	@$(BIN)/pip install --upgrade pip setuptools wheel
	@$(BIN)/pip install -e ".[dev]"

install: venv
	@echo "Installed. Activate with: source $(VENV)/bin/activate"

run-server:
	@$(BIN)/$(PKG) --server 8080

run-client:
	@$(BIN)/$(PKG) --client 8081

run:
	@$(BIN)/$(PKG) --server 8080 --client 8081

dev:
	@echo "Running linter and tests..."
	@$(BIN)/ruff check .
	@$(BIN)/ruff format --check .
	@$(BIN)/pytest -v

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
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name '*.pyc' -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@find . -type f -name '*.pyo' -delete 2>/dev/null || true
	@find . -type f -name '*.pyd' -delete 2>/dev/null || true
	@find . -type f -name '*.so' -delete 2>/dev/null || true
	@rm -rf $(VENV) .pytest_cache .ruff_cache build dist *.egg-info
	@rm -f bots/honeypot.sqlite
	@echo "Clean complete."

# ──────────────────────────────────────────────────────────────────────────────
# Systemd management (run as root on target server)
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: systemd-install systemd-start systemd-stop systemd-restart \
        systemd-enable systemd-disable systemd-status systemd-logs \
        systemd-uninstall

systemd-install:
	@echo "Installing systemd service..."
	@cp $(SYSTEMD_UNIT) /etc/systemd/system/manyfaced.service
	@systemctl daemon-reload
	@echo "Service installed. Enable with: systemctl enable manyfaced"
	@echo "Start with: systemctl start manyfaced"

systemd-start:
	@systemctl start manyfaced

systemd-stop:
	@systemctl stop manyfaced

systemd-restart:
	@systemctl restart manyfaced

systemd-enable:
	@systemctl enable manyfaced

systemd-disable:
	@systemctl disable manyfaced

systemd-status:
	@systemctl status manyfaced

systemd-logs:
	@journalctl -u manyfaced -f --no-pager

systemd-uninstall:
	@systemctl stop manyfaced 2>/dev/null || true
	@systemctl disable manyfaced 2>/dev/null || true
	@rm -f /etc/systemd/system/manyfaced.service
	@systemctl daemon-reload
	@echo "Service removed."

# ──────────────────────────────────────────────────────────────────────────────
# Maintenance
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
		echo "0 3 * * * /opt/manyfaced/scripts/backup-db.sh" | \
			crontab -u $(DEPLOY_USER) -; \
		echo "  Cron installed: daily at 3:00 AM"; \
	else \
		echo "  Backup script not found: $(BACKUP_SCRIPT)"; \
	fi
