#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberViser — Burp Suite ↔ Brave Auto-Setup
# Installs Burp CA cert into Brave's NSS trust store and configures proxy.
# Run once: ./setup-burp-brave.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

BURP_HOST="127.0.0.1"
BURP_PORT="8080"
BURP_PROXY="${BURP_HOST}:${BURP_PORT}"
CERT_DIR="$HOME/.burp"
CERT_DER="${CERT_DIR}/burp_ca.der"
CERT_PEM="${CERT_DIR}/burp_ca.crt"
NSS_DB="$HOME/.pki/nssdb"
CERT_NICKNAME="BurpSuite CyberViser CA"
BRAVE_BIN="/usr/bin/brave-browser"
BRAVE_PROFILE="/tmp/brave-burp"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   CyberViser — Burp Suite ↔ Brave Auto-Setup        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Check Burp is running ─────────────────────────────────────────
info "Step 1/6 — Checking Burp Suite proxy..."
if ! nc -z "$BURP_HOST" "$BURP_PORT" 2>/dev/null; then
    warn "Burp Suite is NOT running on ${BURP_PROXY}"
    echo ""
    echo "  Please start Burp Suite first:"
    echo "  1. Open Burp Suite"
    echo "  2. Go to Proxy → Options → confirm listener is on 127.0.0.1:8080"
    echo "  3. Re-run this script"
    echo ""
    # Offer to launch Burp if available
    if which burpsuite &>/dev/null; then
        read -rp "  Launch Burp Suite now? [y/N] " launch
        if [[ "$launch" =~ ^[Yy]$ ]]; then
            burpsuite &>/dev/null &
            echo ""
            warn "Burp Suite is loading — complete the startup wizard in the GUI:"
            warn "  → Choose 'Temporary project' → 'Use Burp defaults' → Start"
            warn "  → Confirm Proxy listener is on 127.0.0.1:8080"
            echo ""
            info "Waiting up to 60s for Burp proxy to become ready..."
            for i in $(seq 1 12); do
                sleep 5
                if nc -z "$BURP_HOST" "$BURP_PORT" 2>/dev/null; then
                    break
                fi
                echo -n "  ${i}/12 waiting..."$'\r'
            done
            if ! nc -z "$BURP_HOST" "$BURP_PORT" 2>/dev/null; then
                fail "Burp proxy not ready on ${BURP_PROXY}. Complete the startup wizard, then re-run."
            fi
        else
            fail "Burp not running — aborting."
        fi
    else
        fail "Start Burp Suite manually then re-run this script."
    fi
fi
success "Burp proxy is live on ${BURP_PROXY}"

# ── Step 2: Install libnss3-tools (certutil) ─────────────────────────────
info "Step 2/6 — Checking for certutil (libnss3-tools)..."
if ! which certutil &>/dev/null; then
    warn "certutil not found — installing libnss3-tools (requires sudo)..."
    sudo apt-get install -y --no-install-recommends libnss3-tools
fi
success "certutil: $(which certutil)"

# ── Step 3: Download Burp CA cert ─────────────────────────────────────────
info "Step 3/6 — Downloading Burp CA certificate..."
mkdir -p "$CERT_DIR"
curl -sf "http://${BURP_PROXY}/cert" -o "$CERT_DER" || fail "Could not download cert from Burp. Is intercept enabled?"
openssl x509 -inform DER -in "$CERT_DER" -out "$CERT_PEM"
CERT_SUBJECT=$(openssl x509 -inform PEM -in "$CERT_PEM" -noout -subject 2>/dev/null)
success "Downloaded: $CERT_SUBJECT"

# ── Step 4: Import into NSS trust store (used by Brave) ───────────────────
info "Step 4/6 — Installing CA cert into Brave's NSS trust store..."

# Create user NSS db if it doesn't exist
mkdir -p "$NSS_DB"
if [ ! -f "${NSS_DB}/cert9.db" ]; then
    certutil -d "sql:${NSS_DB}" -N --empty-password
    info "Created new NSS database"
fi

# Remove old cert if present (avoid duplicates)
certutil -d "sql:${NSS_DB}" -D -n "${CERT_NICKNAME}" 2>/dev/null && \
    info "Removed existing cert '${CERT_NICKNAME}'" || true

# Import cert — CT,c, = trust: client TLS, server TLS
certutil -d "sql:${NSS_DB}" -A -n "${CERT_NICKNAME}" -t "CT,C,C" -i "$CERT_PEM"
success "CA cert installed: '${CERT_NICKNAME}'"

# Verify
certutil -d "sql:${NSS_DB}" -L -n "${CERT_NICKNAME}" &>/dev/null && \
    success "Verified cert is in NSS store" || warn "Cert install may have failed"

# ── Step 5: Set system proxy (gsettings) ──────────────────────────────────
info "Step 5/6 — Configuring system proxy → ${BURP_PROXY}..."
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.http  host "$BURP_HOST"
gsettings set org.gnome.system.proxy.http  port "$BURP_PORT"
gsettings set org.gnome.system.proxy.https host "$BURP_HOST"
gsettings set org.gnome.system.proxy.https port "$BURP_PORT"
gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']"
success "System proxy set to ${BURP_PROXY}"

# ── Step 6: Test — curl through Burp ─────────────────────────────────────
info "Step 6/6 — Testing proxy with curl..."
HTTP_RESULT=$(curl -sf --proxy "http://${BURP_PROXY}" \
    --cacert "$CERT_PEM" \
    --connect-timeout 8 \
    http://httpbin.org/ip 2>&1 || true)

if echo "$HTTP_RESULT" | grep -q "origin"; then
    DETECTED_IP=$(echo "$HTTP_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['origin'])" 2>/dev/null || echo "unknown")
    success "HTTP test PASSED — traffic flowing through Burp (origin IP: ${DETECTED_IP})"
else
    warn "HTTP test inconclusive (httpbin.org may be unreachable)"
    # Fallback test against local target
    LOCAL_RESULT=$(curl -sf --proxy "http://${BURP_PROXY}" --connect-timeout 5 http://127.0.0.1/ 2>&1 || true)
    warn "Check Burp's HTTP History tab — a request should appear there"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  CA Cert  : ${CERT_PEM}"
echo "  NSS DB   : ${NSS_DB}"
echo "  Proxy    : http://${BURP_PROXY}"
echo ""
echo -e "${CYAN}  Launch Brave (proxied):${NC}"
echo "    brave-browser --proxy-server='http://${BURP_PROXY}'"
echo ""
echo -e "${CYAN}  Or use the launcher:${NC}"
echo "    ./burp-brave.sh [url]"
echo ""
echo -e "${YELLOW}  To DISABLE proxy when done:${NC}"
echo "    gsettings set org.gnome.system.proxy mode 'none'"
echo ""
echo -e "${CYAN}  Burp intercept check:${NC}"
echo "    Open Burp → Proxy → HTTP History — you should see requests"
echo ""
