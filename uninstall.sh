#!/bin/bash
# DSIPS Uninstaller

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

spin() {
    local msg="$1"; local cmd="$2"
    echo -ne "  ${BLUE}•${NC}  ${msg}... "
    eval "$cmd" &>/dev/null &
    local PID=$! i=0 SPINNER="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    while kill -0 $PID 2>/dev/null; do
        echo -ne "${CYAN}${SPINNER:$((i % ${#SPINNER})):1}${NC}\b"
        sleep 0.1
        ((i++))
    done
    wait $PID 2>/dev/null || true
    echo -e "\r  ${GREEN}✓${NC}  ${msg}        "
}

[[ $EUID -ne 0 ]] && echo -e "${RED}Run as root${NC}" && exit 1

echo ""
echo -e "  ${YELLOW}This will remove DSIPS agent from this server.${NC}"
echo -e "  Config in /etc/dsips will be preserved."
echo ""
read -rp "  Continue? [y/N] " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo "  Aborted." && exit 0
echo ""

# Stop and disable service
spin "Service to'xtatilmoqda"   "systemctl stop dsips 2>/dev/null; systemctl disable dsips --quiet 2>/dev/null"
spin "Systemd service o'chirilmoqda" "rm -f /etc/systemd/system/dsips.service && systemctl daemon-reload"
spin "/opt/dsips o'chirilmoqda"  "rm -rf /opt/dsips"

# ipset rules
if command -v ipset &>/dev/null; then
    spin "ipset qoidalari tozalanmoqda" \
        "iptables -D INPUT -m set --match-set dsips_blocked src -j DROP 2>/dev/null; ipset destroy dsips_blocked 2>/dev/null"
fi

echo ""
echo -e "  ${GREEN}✓  DSIPS o'chirildi.${NC}"
echo -e "  Config saqlandi : /etc/dsips/config.json"
echo -e "  Loglar saqlandi : /var/log/dsips/"
echo ""