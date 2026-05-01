#!/usr/bin/env bash
# setup-iptables-privileged-ports.sh
# Set up iptables REDIRECT rules for privileged ports → high ports.
# Run as root on the honeypot server.
#
# Privileged ports (<1024) cannot be bound by non-root users.
# This script redirects them to high ports that the honeypot binds to.
#
# Mapping:
#   80   → 8080   (HTTP)
#   443  → 8443   (HTTPS)
#   21   → 10021  (FTP)
#   22   → 10022  (SSH)
#   23   → 10023  (Telnet)
#   25   → 10025  (SMTP)
#   53   → 10053  (DNS)
#   110  → 10110  (POP3)
#   135  → 10135  (MSRPC)
#   139  → 10139  (NetBIOS)
#   143  → 10143  (IMAP)
#   445  → 10445  (SMB)
#   993  → 10993  (IMAPS)
#   995  → 10995  (POP3S)
#
# Prerequisites:
#   - honeypot must be listening on all the high ports above
#   - iptables-persistent package for rule saving
#   - DO firewall must allow the privileged ports

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 1; }

log "Setting up iptables REDIRECT rules for privileged ports..."

declare -A MAPPING=(
    [80]=8080
    [443]=8443
    [21]=10021
    [22]=10022
    [23]=10023
    [25]=10025
    [53]=10053
    [110]=10110
    [135]=10135
    [139]=10139
    [143]=10143
    [445]=10445
    [993]=10993
    [995]=10995
)

for priv_port in "${!MAPPING[@]}"; do
    high_port=${MAPPING[$priv_port]}
    iptables -t nat -C PREROUTING -p tcp --dport "$priv_port" -j REDIRECT --to-ports "$high_port" 2>/dev/null && \
        log "  $priv_port → $high_port (already exists)" || \
        { iptables -t nat -A PREROUTING -p tcp --dport "$priv_port" -j REDIRECT --to-ports "$high_port"; log "  $priv_port → $high_port (added)"; }
done

# Save rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
log "Rules saved to /etc/iptables/rules.v4"

# Ensure iptables-persistent is installed (auto-loads on boot)
if ! dpkg -l iptables-persistent 2>/dev/null | grep -q ii; then
    warn "iptables-persistent not installed. Rules won't survive reboot."
    warn "Install with: apt-get install -y iptables-persistent"
else
    log "iptables-persistent is installed — rules will load on boot"
fi

echo ""
log "=== Setup complete ==="
echo ""
echo "Verify with: iptables -t nat -L PREROUTING -n"
echo ""
echo "⚠  Don't forget to open these ports in your cloud firewall (DO/AWS/GCP):"
echo "    TCP 80,443,21,22,23,25,53,110,135,139,143,445,993,995"
