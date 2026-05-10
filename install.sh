#!/usr/bin/env bash
# ============================================================
# SecProbe - Kali Linux Installation Script
# Author: Aman Kumar Panda
# ============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/secprobe"
BIN_PATH="/usr/local/bin/secprobe"
API_BIN="/usr/local/bin/secprobe-api"
API_SERVICE="/etc/systemd/system/secprobe-api.service"

banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║         SecProbe Installer v1.0.0                ║"
    echo "  ║       AI-Assisted Web Security Scanner           ║"
    echo "  ║         Author:Aman Kumar Panda                  ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Run as root: sudo ./install.sh${NC}"
        exit 1
    fi
}

check_kali() {
    if ! grep -qi "kali" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}[!] Warning: Optimized for Kali Linux.${NC}"
        read -rp "    Continue anyway? (y/N): " ans
        [[ "${ans,,}" == "y" ]] || exit 1
    fi
}

install_system_deps() {
    echo -e "${CYAN}[*] Updating packages...${NC}"
    apt-get update -qq
    echo -e "${CYAN}[*] Installing system dependencies...${NC}"
    apt-get install -y -qq python3 python3-pip python3-venv nmap openssl curl git
    echo -e "${GREEN}[✓] System dependencies installed${NC}"
}

setup_venv() {
    echo -e "${CYAN}[*] Installing to ${INSTALL_DIR}...${NC}"
    mkdir -p "$INSTALL_DIR"
    cp -r . "$INSTALL_DIR/"
    python3 -m venv "$INSTALL_DIR/venv"
    echo -e "${CYAN}[*] Installing Python packages...${NC}"
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    "$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR" -q
    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
}

create_cli_wrapper() {
    cat > "$BIN_PATH" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/opt/secprobe"
# Auto-load .env if present
[ -f /opt/secprobe/.env ] && export $(grep -v '^#' /opt/secprobe/.env | xargs)
exec /opt/secprobe/venv/bin/secprobe "$@"
EOF
    chmod +x "$BIN_PATH"
    echo -e "${GREEN}[✓] CLI installed: secprobe${NC}"
}

create_api_wrapper() {
    cat > "$API_BIN" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/opt/secprobe"
[ -f /opt/secprobe/.env ] && export $(grep -v '^#' /opt/secprobe/.env | xargs)
cd /opt/secprobe
exec /opt/secprobe/venv/bin/python -m secprobe.api "$@"
EOF
    chmod +x "$API_BIN"
    echo -e "${GREEN}[✓] API server script: secprobe-api${NC}"
}

create_systemd_service() {
    cat > "$API_SERVICE" << 'EOF'
[Unit]
Description=SecProbe REST API Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/secprobe
EnvironmentFile=-/opt/secprobe/.env
ExecStart=/opt/secprobe/venv/bin/gunicorn \
    --workers 2 \
    --bind 0.0.0.0:5000 \
    --timeout 120 \
    "secprobe.api:app"
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "${GREEN}[✓] Systemd service created: secprobe-api${NC}"
}

setup_env() {
    if [ ! -f "$INSTALL_DIR/.env" ]; then
        cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
        echo -e "${GREEN}[✓] Created config file: ${INSTALL_DIR}/.env${NC}"
    fi
}

print_success() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗"
    echo -e "║       ✓  SecProbe Installation Complete!             ║"
    echo -e "╚══════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}  ── CLI Usage ────────────────────────────────────────${NC}"
    echo -e "  secprobe example.com                    # basic scan"
    echo -e "  secprobe example.com --ai               # AI offline (no key!)"
    echo -e "  secprobe example.com --ai --verbose     # full details"
    echo -e "  secprobe example.com --ports --ai       # with port scan"
    echo -e "  secprobe example.com --output out.json  # save report"
    echo
    echo -e "${CYAN}  ── Free AI Setup (optional, takes 30 seconds) ───────${NC}"
    echo -e "  ${YELLOW}Gemini (free):${NC} https://aistudio.google.com/app/apikey"
    echo -e "    → nano /opt/secprobe/.env  → set GEMINI_API_KEY=..."
    echo
    echo -e "  ${YELLOW}Groq (free):${NC}   https://console.groq.com/keys"
    echo -e "    → nano /opt/secprobe/.env  → set GROQ_API_KEY=..."
    echo
    echo -e "  ${YELLOW}No key at all:${NC} AI still works using offline engine!"
    echo
    echo -e "${CYAN}  ── API Server ────────────────────────────────────────${NC}"
    echo -e "  secprobe-api                            # start API"
    echo -e "  systemctl start secprobe-api            # start as service"
    echo -e "  systemctl enable secprobe-api           # auto-start on boot"
    echo -e "  curl -X POST http://localhost:5000/scan \\"
    echo -e "    -H 'Content-Type: application/json' \\"
    echo -e "    -d '{\"target\":\"example.com\",\"use_ai\":true}'"
    echo
}

banner
check_root
check_kali
install_system_deps
setup_venv
create_cli_wrapper
create_api_wrapper
create_systemd_service
setup_env
print_success
