#!/usr/bin/env bash
# deploy.sh — One-command deployment of manyfaced honeypot on a fresh Ubuntu 24.04 droplet.
# Usage: bash deploy.sh [--port CLIENT_PORT] [--server-port SERVER_PORT] [--ssh-port SSH_PORT]
#
# This script:
#   1. Installs Python venv and git
#   2. Creates a 'honeypot' user
#   3. Clones the repo, installs deps
#   4. Generates a config from env vars or defaults
#   5. Installs the systemd service
#   6. Starts the honeypot

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
CLIENT_PORT=8080
SERVER_PORT=8888
SSH_PORT=22222
HONEY_PORT_MODE="top"
GITHUB_REPO="https://github.com/Zloool/manyfaced-honeypot.git"
INSTALL_DIR="/opt/manyfaced"
DB_PATH="${INSTALL_DIR}/bots/honeypot.sqlite"
LOG_FILE="${INSTALL_DIR}/bots/honeypot.log"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)      CLIENT_PORT="$2";      shift 2 ;;
        --server-port) SERVER_PORT="$2";    shift 2 ;;
        --ssh-port)  SSH_PORT="$2";         shift 2 ;;
        --port-mode) HONEY_PORT_MODE="$2";  shift 2 ;;
        --repo)      GITHUB_REPO="$2";      shift 2 ;;
        *)           echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Color helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
err()    { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || err "This script must run as root."

log "=== manyfaced honeypot deployment ==="
log "Client port:    $CLIENT_PORT"
log "Server port:    $SERVER_PORT"
log "SSH port:       $SSH_PORT"
log "Port mode:      $HONEY_PORT_MODE"
log "Install dir:    $INSTALL_DIR"

# ── 1. Install prerequisites ─────────────────────────────────────────────────
log "Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq python3.12-venv git iptables-persistent > /dev/null

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
HONEY_HONEYPORT=${CLIENT_PORT}

# Client — port mode: single, top, all
HONEY_PORT_MODE=${HONEY_PORT_MODE}

# Hive (server) settings
HONEY_HIVEHOST=127.0.0.1
HONEY_HIVEPORT=${SERVER_PORT}
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

log "HIVEPASS generated. Save this for server authentication:"
echo "  HONEY_HIVEPASS=${HIVEPASS}"

# ── 5. Install systemd service ───────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/manyfaced.service <<EOF
[Unit]
Description=Manyfaced Honeypot - Multi-faced honeypot for detecting bot activity
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

# ── 6. Start the honeypot ────────────────────────────────────────────────────
log "Starting manyfaced honeypot..."
systemctl start manyfaced
sleep 2

if systemctl is-active --quiet manyfaced; then
    log "✓ manyfaced is running!"
    log "  Client listening on port: $CLIENT_PORT"
    log "  Server listening on port: $SERVER_PORT"
else
    warn "Service failed to start. Check: systemctl status manyfaced"
    journalctl -u manyfaced --no-pager -n 20
fi

# ── 7. Set up iptables redirect (optional) ───────────────────────────────────
if [[ $CLIENT_PORT -ne 80 ]]; then
    log "Setting up iptables redirect: 80 → $CLIENT_PORT"
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port $CLIENT_PORT
    iptables-save > /etc/iptables/rules.v4
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
log "=== Deployment complete ==="
echo ""
echo "  SSH:        ssh -p $SSH_PORT root@<your-server>"
echo "  Client:     http://<your-server>:$CLIENT_PORT"
echo "  Server:     TCP $SERVER_PORT (encrypted)"
echo "  Logs:       journalctl -u manyfaced -f"
echo "  Config:     $INSTALL_DIR/honeypot.env"
echo "  Service:    systemctl status manyfaced"
echo ""
echo "⚠  Don't forget to open ports in your cloud firewall:"
echo "    - TCP $SSH_PORT   (SSH access)"
echo "    - TCP 80         (bot traffic → redirected to $CLIENT_PORT)"
echo "    - TCP $SERVER_PORT (server data collection)"
echo ""
