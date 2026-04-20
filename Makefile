.PHONY: run dev test clean install lint

PYTHON := python3
VENV   := .venv
BIN    := $(VENV)/bin
PKG    := manyfaced

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

.PHONY: venv
venv:
	@$(PYTHON) -m venv $(VENV)
	@$(BIN)/pip install --upgrade pip setuptools wheel
	@$(BIN)/pip install -e ".[dev]"

# ---------------------------------------------------------------------------
# Install / setup
# ---------------------------------------------------------------------------

.PHONY: install
install: venv
	@echo "Installed. Activate with: source $(VENV)/bin/activate"

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

run-server:
	@$(BIN)/$(PKG) --server 8080

run-client:
	@$(BIN)/$(PKG) --client 8081

# Run both server and client in a single process
run:
	@$(BIN)/$(PKG) --server 8080 --client 8081

# ---------------------------------------------------------------------------
# Dev helpers
# ---------------------------------------------------------------------------

dev:
	@echo "Running linter and tests..."
	@$(BIN)/ruff check .
	@$(BIN)/ruff format --check .
	@$(BIN)/pytest -v

# Format code
format:
	@$(BIN)/ruff format .

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test:
	@$(BIN)/pytest -v $(TEST)

# Run a specific test file
test-file:
	@$(BIN)/pytest $(TEST_FILE) -v

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Systemd
# ---------------------------------------------------------------------------

SYSTEMD_UNIT := systemd/manyfaced.service
SYSTEMD_DIR  := /etc/systemd/system

systemd-install:
	@echo "Installing systemd service..."
	@cp $(SYSTEMD_UNIT) $(SYSTEMD_DIR)/manyfaced.service
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
	@rm -f $(SYSTEMD_DIR)/manyfaced.service
	@systemctl daemon-reload
	@echo "Service removed."
