# Manyfaced Honeypot — Makefile
#
# Development targets:
#   make install    — set up Python venv and install deps
#   make run        — run both client and server
#   make test       — run test suite
#   make lint       — run linter
#
# Deployment targets (run as root on target server):
#   make deploy     — full one-command deployment
#   make systemd-install  — install systemd service
#   make logrotate-install — install logrotate config
#   make backup-cron     — install database backup cron
#
# Server management:
#   make start / stop / restart / status / logs

PYTHON  := python3
VENV    := .venv
BIN     := $(VENV)/bin
PKG     := manyfaced

# Deployment paths
DEPLOY_DIR  := /opt/manyfaced
DEPLOY_USER := honeypot
SYSTEMD_UNIT := systemd/manyfaced.service
LOGROTATE    := systemd/manyfaced.logrotate
ENV_TEMPLATE := systemd/honeypot.env.example
BACKUP_SCRIPT := scripts/backup-db.sh

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
# Deployment (server setup)
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: deploy deploy-install deploy-configure deploy-start

# Full deployment: install system deps, create user, clone, configure, start
deploy: deploy-install deploy-configure deploy-start
	@echo ""
	@echo "=== Deployment complete ==="
	@echo "  SSH:        ssh -p $$SSH_PORT root@<server>"
	@echo "  Client:     http://<server>:$$HONEYPORT"
	@echo "  Server:     TCP $$HIVEPORT (encrypted)"
	@echo "  Logs:       journalctl -u manyfaced -f"
	@echo "  Config:     $(DEPLOY_DIR)/honeypot.env"
	@echo ""
	@echo "⚠  Don't forget to open ports in your cloud firewall:"
	@echo "    - TCP $$SSH_PORT   (SSH access)"
	@echo "    - TCP 80         (bot traffic → redirected to $$HONEYPORT)"
	@echo "    - TCP $$HIVEPORT (server data collection)"

# Install system packages, create user, clone repo, install deps
deploy-install:
	@echo "=== Installing system packages..."
	@apt-get update -qq
	@apt-get install -y -qq python3.12-venv git iptables-persistent
	@echo "=== Creating honeypot user..."
	@if id $(DEPLOY_USER) &>/dev/null; then \
		echo "  $(DEPLOY_USER) user already exists"; \
	else \
		useradd -m -s /bin/bash $(DEPLOY_USER); \
	fi
	@mkdir -p $(DEPLOY_DIR)
	@chown $(DEPLOY_USER):$(DEPLOY_USER) $(DEPLOY_DIR)
	@echo "=== Cloning repository..."
	@su - $(DEPLOY_USER) -c "\
		cd $(DEPLOY_DIR) && \
		if [ -d .git ]; then git fetch --all && git pull; \
		else git clone https://github.com/Zloool/manyfaced-honeypot.git .; fi && \
		python3 -m venv venv && \
		source venv/bin/activate && \
		pip install --upgrade pip -q && \
		pip install -e . -q"
	@echo "=== Installing prerequisites..."
	@apt-get install -y -qq iptables-persistent

# Configure: generate config, set up systemd, iptables, start service
deploy-configure:
	@echo "=== Generating configuration..."
	@mkdir -p $(DEPLOY_DIR)/bots
	@chown $(DEPLOY_USER):$(DEPLOY_USER) $(DEPLOY_DIR)/bots
	@HIVEPASS=$$(python3 -c "import secrets; print(secrets.token_hex(32))"); \
	cat > $(DEPLOY_DIR)/honeypot.env <<EOF
# manyfaced honeypot configuration
HONEY_HONEYPORT=$(HONEYPORT)
HONEY_PORT_MODE=$(PORT_MODE)
HONEY_HIVEHOST=127.0.0.1
HONEY_HIVEPORT=$(HIVEPORT)
HONEY_HIVELOGIN=$$(hostname -s | tr '[:lower:]' '[:upper:]')
HONEY_HIVEPASS=$$HIVEPASS
HONEY_DB_BACKEND=sqlite
HONEY_DB_PATH=$(DEPLOY_DIR)/bots/honeypot.sqlite
HONEY_LOG_FILE=$(DEPLOY_DIR)/bots/honeypot.log
HONEY_AUTHORISEDBEARS=""
EOF
	@chown $(DEPLOY_USER):$(DEPLOY_USER) $(DEPLOY_DIR)/honeypot.env
	@chmod 600 $(DEPLOY_DIR)/honeypot.env
	@echo "  HIVEPASS generated. Save this:"
	@echo "    HONEY_HIVEPASS=$$HIVEPASS"
	@echo "=== Installing systemd service..."
	@cp $(SYSTEMD_UNIT) /etc/systemd/system/manyfaced.service
	@systemctl daemon-reload
	@systemctl enable manyfaced
	@echo "=== Setting up logrotate..."
	@if [ -f $(LOGROTATE) ]; then \
		cp $(LOGROTATE) /etc/logrotate.d/manyfaced; \
		echo "  Logrotate installed"; \
	else \
		echo "  Logrotate template not found: $(LOGROTATE)"; \
	fi
	@echo "=== Setting up iptables redirect (80 → $$HONEYPORT)..."
	@iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port $(HONEYPORT)
	@iptables-save > /etc/iptables/rules.v4
	@echo "  iptables redirect: 80 → $(HONEYPORT)"

# Start the service
deploy-start:
	@echo "=== Starting manyfaced honeypot..."
	@systemctl start manyfaced
	@sleep 2
	@if systemctl is-active --quiet manyfaced; then \
		echo "✓ manyfaced is running!"; \
		echo "  Client: port $(HONEYPORT)"; \
		echo "  Server: port $(HIVEPORT)"; \
	else \
		echo "⚠ Service failed to start. Check: systemctl status manyfaced"; \
		journalctl -u manyfaced --no-pager -n 20; \
	fi

# ──────────────────────────────────────────────────────────────────────────────
# Systemd management
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: systemd-install systemd-start systemd-stop systemd-restart \
        systemd-enable systemd-disable systemd-status systemd-logs \
        systemd-uninstall

SYSTEMD_UNIT := systemd/manyfaced.service

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

# ──────────────────────────────────────────────────────────────────────────────
# Docker
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: docker-build docker-run docker-stop docker-clean

docker-build:
	@docker build -t manyfaced-honeypot .

docker-run:
	@docker-compose up -d

docker-stop:
	@docker-compose down

docker-clean:
	@docker-compose down --volumes --remove-orphans
	@docker system prune -f
