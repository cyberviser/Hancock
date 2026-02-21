#!/bin/bash
# Launch Brave routed through Burp Suite
BURP_PROXY="127.0.0.1:8080"
URL="${1:-http://burpsuite}"

if ! nc -z 127.0.0.1 8080 2>/dev/null; then
    echo "[!] Burp Suite is not running on 8080 — start it first"
    exit 1
fi

brave-browser \
    --proxy-server="http://${BURP_PROXY}" \
    --user-data-dir="$HOME/.config/BraveSoftware/Brave-Browser" \
    "$URL" 2>/dev/null &

echo "[+] Brave launched through Burp proxy: ${BURP_PROXY}"
echo "[+] Check Burp → Proxy → HTTP History for captured requests"
