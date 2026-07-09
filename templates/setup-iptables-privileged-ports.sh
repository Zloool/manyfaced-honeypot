#!/usr/bin/env bash
# setup-iptables-privileged-ports.sh
# Set up iptables REDIRECT rules for privileged ports → high ports.
# Run as root on the honeypot server.
#
# Privileged ports (<1024) cannot be bound by non-root users.
# This script redirects them to high ports that the honeypot binds to.
#
# Mapping:
#   The canonical redirect table lives in manyfaced/common/ports.py
#   (PRIVILEGED_PORT_REDIRECTS). This script DERIVES its rules from that same
#   source so the three copies (python dashboard, this script, and the saved
#   rules.v4) can never drift apart. To change a port mapping, edit
#   manyfaced/common/ports.py and re-run this script — do NOT edit the list
#   below by hand.
#
# Prerequisites:
#   - manyfaced python package importable (pip install .)
#   - honeypot must be listening on all the high ports above
#   - iptables-persistent package for rule saving
#   - DO firewall must allow the privileged ports

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 1; }

log "Setting up iptables REDIRECT rules for privileged ports..."

# Derive the mapping from the single source of truth in manyfaced/common/ports.py
# so this script can't drift from the dashboard's view of port identity.
# Emits a bash associative-array literal: declare -A MAPPING=( [80]=8080 ... )
if command -v python3 >/dev/null 2>&1; then
    # shellcheck disable=SC2209
    MAPPING_SRC=$(python3 -c '
from manyfaced.common.ports import PRIVILEGED_PORT_REDIRECTS as M
print(" ".join("[%d]=%d" % (p, h) for p, h in sorted(M.items())))
' 2>/dev/null || true)
fi
if [ -z "${MAPPING_SRC:-}" ]; then
    warn "Could not import manyfaced.common.ports — falling back to an inline copy."
    warn "If you change the redirect table, update BOTH this fallback and ports.py."
    MAPPING_SRC="[80]=8080 [443]=8443 [21]=10021 [22]=10022 [23]=10023 [25]=10025 [53]=10053 [110]=10110 [135]=10135 [139]=10139 [143]=10143 [445]=10445 [993]=10993 [995]=10995"
fi
# shellcheck disable=SC2162,SC1083
declare -A MAPPING=( ${MAPPING_SRC} )

for priv_port in "${!MAPPING[@]}"; do
    high_port=${MAPPING[$priv_port]}
    iptables -t nat -C PREROUTING -p tcp --dport "$priv_port" -j REDIRECT --to-ports "$high_port" 2>/dev/null && \
        log "  $priv_port → $high_port (already exists)" || \
        { iptables -t nat -A PREROUTING -p tcp --dport "$priv_port" -j REDIRECT --to-ports "$high_port"; log "  $priv_port → $high_port (added)"; }
done

# CRITICAL: Do NOT add OUTPUT chain rules.
# OUTPUT rules redirect the honeypot's own outbound traffic back to itself,
# breaking pip, curl, and any HTTPS client. Only PREROUTING is needed to
# catch incoming attacker traffic.
# See: https://serverfault.com/questions/iptables-prerouting-vs-output
log ""
log "NOTE: OUTPUT chain is intentionally left empty."
log "  PREROUTING handles incoming attacker traffic."
log "  OUTPUT must be clean so the honeypot can reach the internet."

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
