#!/usr/bin/env bash
# SecProbe Uninstaller
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Run as root: sudo ./uninstall.sh${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Removing SecProbe...${NC}"

systemctl stop secprobe-api 2>/dev/null || true
systemctl disable secprobe-api 2>/dev/null || true
rm -f /etc/systemd/system/secprobe-api.service
systemctl daemon-reload 2>/dev/null || true

rm -f /usr/local/bin/secprobe
rm -f /usr/local/bin/secprobe-api
rm -rf /opt/secprobe

echo -e "${GREEN}[✓] SecProbe uninstalled successfully.${NC}"
