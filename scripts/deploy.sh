#!/usr/bin/env bash
# deploy.sh — One-command deployment of manyfaced honeypot on a fresh Ubuntu 24.04 droplet.
#
# Usage:
#   bash scripts/deploy.sh [--port PORT] [--server-port PORT] [--ssh-port PORT] [--port-mode MODE]
#
# This script automates the full deployment:
#   1. Installs Python venv and git
#   2. Creates a 'honeypot' user
#   3. Clones the repo, installs deps
#   4. Generates a config from env vars or defaults
#   5. Installs the systemd service
#   6. Sets up logrotate
#   7. Configures iptables redirect
#   8. Starts the honeypot
#
# Example:
#   bash scripts/deploy.sh --port 8080 --server-port 8888 --ssh-port 22222

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
HONEYPORT=8080
HIVEPORT=8888
SSH_PORT=22222
PORT_MODE="top"
GITHUB_REPO="https://github.com/Zloool/manyfaced-honeypot.git"
INSTALL_DIR="/opt/manyfaced"
DB_PATH="${INSTALL_DIR}/bots/honeypot.sqlite"
LOG_FILE="${INSTALL_DIR}/bots/honeypot.log"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)      HONEYPORT="$2";      shift 2 ;;
        --server-port) HIVEPORT="$2";     shift 2 ;;
        --ssh-port)  SSH_PORT="$2";       shift 2 ;;
        --port-mode) PORT_MODE="$2";      shift 2 ;;
        --repo)      GITHUB_REPO="$2";    shift 2 ;;
        *)           echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Color helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()    { echo -e "${GREEN}[+]${NC} $*"; }
info()   { echo -e "${CYAN}[i]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
err()    { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || err "This script must run as root."

log "=== manyfaced honeypot deployment ==="
log "Client port:    $HONEYPORT"
log "Server port:    $HIVEPORT"
log "SSH port:       $SSH_PORT"
log "Port mode:      $PORT_MODE"
log "Install dir:    $INSTALL_DIR"

# ── 1. Install prerequisites ─────────────────────────────────────────────────
log "Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq python3.12-venv git iptables-persistent curl > /dev/null

# ── 2. Create honeypot user ──────────────────────────────────────────────────
log "Creating 'honeypot' user..."
if id honeypot &>/dev/null; then
    warn "'honeypot' user already exists"
else
    useradd -m -s /bin/bash honeypot
fi

# ── 3. Clone and install ─────────────────────────────────────────────────────
log "Cloning repository..."
mkdir -p "$INSTALL_DIR"
chown honeypot:honeypot "$INSTALL_DIR"

su - honeypot -c "
    cd $INSTALL_DIR
    if [ -d .git ]; then
        git fetch --all && git pull
    else
        git clone $GITHUB_REPO .
    fi
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip -q
    pip install -e . -q
"

# ── 4. Generate config ───────────────────────────────────────────────────────
log "Generating configuration..."
mkdir -p /opt/manyfaced/bots
chown honeypot:honeypot /opt/manyfaced/bots

HIVEPASS=$(python3 -c "import secrets; print(secrets.token_hex(32))")

cat > /opt/manyfaced/honeypot.env <<EOF
# manyfaced honeypot configuration
# Environment variables (HONEY_* prefix) control all settings.

# Client — port to impersonate services on
HONEY_HONEYPORT=${HONEYPORT}

# Client — port mode: single, top, all
HONEY_PORT_MODE=${PORT_MODE}

# Server (hive) settings
HONEY_HIVEHOST=127.0.0.1
HONEY_HIVEPORT=${HIVEPORT}
HONEY_HIVELOGIN=$(hostname -s | tr '[:lower:]' '[:upper:]')
HONEY_HIVEPASS=${HIVEPASS}

# Database
HONEY_DB_BACKEND=sqlite
HONEY_DB_PATH=${DB_PATH}

# Logging
HONEY_LOG_FILE=${LOG_FILE}

# Security
HONEY_AUTHORISEDBEARS=""
EOF

chown honeypot:honeypot /opt/manyfaced/honeypot.env
chmod 600 /opt/manyfaced/honeypot.env

log "HIVEPASS generated. Save this for server authentication:"
echo -e "  ${CYAN}HONEY_HIVEPASS=${HIVEPASS}${NC}"

# ── 5. Install systemd service ───────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/manyfaced.service <<EOF
[Unit]
Description=Manyfaced Honeypot - Multi-faced honeypot for detecting bot activity
Documentation=https://github.com/Zloool/manyfaced-honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=honeypot
Group=honeypot
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/honeypot.env
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m manyfaced.mfh
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${INSTALL_DIR}/bots

StandardOutput=journal
StandardError=journal
SyslogIdentifier=manyfaced

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable manyfaced

# ── 6. Install logrotate ─────────────────────────────────────────────────────
log "Installing logrotate config..."
cat > /etc/logrotate.d/manyfaced <<EOF
/opt/manyfaced/bots/honeypot.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 honeypot honeypot
    dateext
    dateformat -%Y%m%d
}
EOF
log "  Logrotate installed to /etc/logrotate.d/manyfaced"

# ── 7. Set up iptables redirect (optional) ───────────────────────────────────
if [[ $HONEYPORT -ne 80 ]]; then
    log "Setting up iptables redirect: 80 → $HONEYPORT"
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port $HONEYPORT
    iptables-save > /etc/iptables/rules.v4
fi

# ── 8. Start the honeypot ────────────────────────────────────────────────────
log "Starting manyfaced honeypot..."
systemctl start manyfaced
sleep 2

if systemctl is-active --quiet manyfaced; then
    log "✓ manyfaced is running!"
    log "  Client listening on port: $HONEYPORT"
    log "  Server listening on port: $HIVEPORT"
else
    warn "Service failed to start. Check: systemctl status manyfaced"
    journalctl -u manyfaced --no-pager -n 20
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
log "=== Deployment complete ==="
echo ""
echo -e "  ${CYAN}SSH:${NC}        ssh -p $SSH_PORT root@<your-server>"
echo -e "  ${CYAN}Client:${NC}     http://<your-server>:$HONEYPORT"
echo -e "  ${CYAN}Server:${NC}     TCP $HIVEPORT (encrypted)"
echo -e "  ${CYAN}Logs:${NC}       journalctl -u manyfaced -f"
echo -e "  ${CYAN}Config:${NC}     $INSTALL_DIR/honeypot.env"
echo -e "  ${CYAN}Service:${NC}    systemctl status manyfaced"
echo ""
echo -e "${YELLOW}⚠ Don't forget to open ports in your cloud firewall:${NC}"
echo "    - TCP $SSH_PORT   (SSH access)"
echo "    - TCP 80         (bot traffic → redirected to $HONEYPORT)"
echo "    - TCP $HIVEPORT (server data collection)"
echo ""
