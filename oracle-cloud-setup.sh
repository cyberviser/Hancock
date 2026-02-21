#!/bin/bash
# Oracle Cloud Always-Free VM — Hancock Full Setup Script
# VM specs: 1 OCPU, 1GB RAM (Micro) or up to 4 OCPU/24GB (Ampere ARM) — always free
# OS: Ubuntu 22.04 LTS
#
# Usage (run on your Oracle VM after SSH in):
#   curl -sO https://raw.githubusercontent.com/cyberviser/Hancock/main/oracle-cloud-setup.sh
#   chmod +x oracle-cloud-setup.sh && ./oracle-cloud-setup.sh

set -e
GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}=== Hancock — Oracle Cloud Free Tier Setup ===${NC}"
PUBLIC_IP=$(curl -s ifconfig.me)

# ── 1. System update ───────────────────────────────────────────
echo -e "${GREEN}[1/6] Updating system...${NC}"
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl gnupg git nginx certbot python3-certbot-nginx ufw

# ── 2. Install Docker ──────────────────────────────────────────
echo -e "${GREEN}[2/6] Installing Docker...${NC}"
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER

# ── 3. Firewall ────────────────────────────────────────────────
echo -e "${GREEN}[3/6] Configuring firewall...${NC}"
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5000/tcp
sudo ufw --force enable
# Oracle iptables rule (required in addition to VCN Security List)
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5000 -j ACCEPT
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# ── 4. Clone & configure Hancock ──────────────────────────────
echo -e "${GREEN}[4/6] Cloning Hancock...${NC}"
[ -d "$HOME/Hancock" ] && echo "Already cloned, pulling latest..." && git -C "$HOME/Hancock" pull || git clone https://github.com/cyberviser/Hancock.git "$HOME/Hancock"
cd "$HOME/Hancock"

if [ ! -f .env ]; then
  cp .env.example .env
  # Prompt for secrets
  echo ""
  read -p "  Enter your NVIDIA NIM API key (https://build.nvidia.com): " NVIDIA_KEY
  HANCOCK_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  sed -i "s|nvapi-your-key-here|${NVIDIA_KEY}|g" .env
  sed -i "s|^HANCOCK_API_KEY=.*|HANCOCK_API_KEY=${HANCOCK_KEY}|g" .env
  echo ""
  echo -e "${CYAN}  Generated HANCOCK_API_KEY: ${HANCOCK_KEY}${NC}"
  echo "  >>> SAVE THIS KEY — you need it to call the API <<<"
  echo ""
fi

# ── 5. Nginx reverse proxy ─────────────────────────────────────
echo -e "${GREEN}[5/6] Configuring Nginx reverse proxy...${NC}"
sudo tee /etc/nginx/sites-available/hancock > /dev/null <<EOF
server {
    listen 80;
    server_name ${PUBLIC_IP} _;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
EOF
sudo ln -sf /etc/nginx/sites-available/hancock /etc/nginx/sites-enabled/hancock
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# ── 6. Start Hancock ───────────────────────────────────────────
echo -e "${GREEN}[6/7] Launching Hancock with Docker...${NC}"
cd "$HOME/Hancock"
sudo docker compose pull 2>/dev/null || true
sudo docker compose up -d --build

# ── 7. Systemd service for auto-restart on reboot ─────────────
echo -e "${GREEN}[7/7] Installing systemd service (auto-start on reboot)...${NC}"
COMPOSE_PATH=$(which docker)
sudo tee /etc/systemd/system/hancock.service > /dev/null <<EOF
[Unit]
Description=Hancock AI Security Agent
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${HOME}/Hancock
ExecStart=${COMPOSE_PATH} compose up -d --build
ExecStop=${COMPOSE_PATH} compose down
ExecReload=${COMPOSE_PATH} compose pull && ${COMPOSE_PATH} compose up -d --build
TimeoutStartSec=300
User=${USER}

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable hancock.service
echo -e "${GREEN}  ✅ hancock.service enabled (will auto-start on reboot)${NC}"

# ── Done ───────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Hancock is LIVE!${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo ""
echo "  API (via Nginx):  http://${PUBLIC_IP}"
echo "  API (direct):     http://${PUBLIC_IP}:5000"
echo "  Health check:     http://${PUBLIC_IP}/health"
echo ""
echo "  Test it:"
echo "  curl http://${PUBLIC_IP}/health"
echo ""
echo "  POST /v1/triage   — SOC alert triage"
echo "  POST /v1/pentest  — Pentest recon/CVE"
echo "  POST /v1/chat     — Chat (mode: pentest|soc|auto|code|ciso)"
echo ""
echo -e "${CYAN}  IMPORTANT — Open these ports in Oracle VCN Security List:${NC}"
echo "  Oracle Console → Networking → VCN → Security Lists → Add Ingress:"
echo "    TCP port 80   (HTTP)"
echo "    TCP port 443  (HTTPS)"
echo "    TCP port 5000 (Direct API)"
echo ""
echo "  Manage:"
echo "    sudo docker compose -f ~/Hancock/docker-compose.yml logs -f"
echo "    sudo docker compose -f ~/Hancock/docker-compose.yml restart"
echo "    sudo systemctl status hancock       # auto-start service status"
echo "    sudo systemctl restart hancock      # restart + pull latest"
