#!/bin/sh
# cloudflared-setup.sh — Convert a Cloudflare tunnel token into a local
# credentials.json + config.yml with noTLSVerify=true so that cloudflared can
# proxy to the local HTTPS server (self-signed cert) without TLS errors.
#
# Run as ExecStartPre in cloudflared.service — idempotent (skips if already done).

CONF_DIR=/etc/cloudflared
CONFIG="$CONF_DIR/config.yml"
CREDS="$CONF_DIR/credentials.json"

# Already configured on a previous boot — nothing to do
if [ -f "$CREDS" ] && [ -f "$CONFIG" ]; then
    exit 0
fi

# Source the environment to get CLOUDFLARE_TUNNEL_TOKEN
# shellcheck disable=SC1091
. "$CONF_DIR/env"

if [ -z "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
    echo "[cloudflared-setup] ERROR: CLOUDFLARE_TUNNEL_TOKEN not set in $CONF_DIR/env" >&2
    exit 1
fi

# Read the public domain (skip comment lines, strip whitespace)
DOMAIN=$(grep -v '^#' "$CONF_DIR/domain" | head -n 1 | tr -d '[:space:]')
if [ -z "$DOMAIN" ]; then
    echo "[cloudflared-setup] ERROR: No domain configured in $CONF_DIR/domain" >&2
    exit 1
fi
echo "[cloudflared-setup] Domain: $DOMAIN"

# ── Decode the base64 tunnel token to JSON ──────────────────────────────────
# Strip any whitespace / carriage-returns that may appear in the env file.
TOKEN=$(printf '%s' "$CLOUDFLARE_TUNNEL_TOKEN" | tr -d '[:space:]')

echo "[cloudflared-setup] DEBUG: token='$TOKEN'"


# The token may lack base64 padding — add it if needed.
MOD=$(( ${#TOKEN} % 4 ))
if [ "$MOD" -ne 0 ]; then
    PAD=$(( 4 - MOD ))
    i=0; PADDING=""
    while [ $i -lt $PAD ]; do PADDING="${PADDING}="; i=$(( i + 1 )); done
    TOKEN="${TOKEN}${PADDING}"
fi

# Try native base64 first; fall back to openssl (more reliable on BusyBox).
TOKEN_JSON=$(printf '%s\n' "$TOKEN" | base64 -d 2>/dev/null)
if [ -z "$TOKEN_JSON" ] && command -v openssl >/dev/null 2>&1; then
    TOKEN_JSON=$(printf '%s\n' "$TOKEN" | openssl base64 -d -A 2>/dev/null)
fi
if [ -z "$TOKEN_JSON" ]; then
    echo "[cloudflared-setup] ERROR: Failed to base64-decode the tunnel token" >&2
    echo "[cloudflared-setup] DEBUG: base64 available=$(command -v base64 2>/dev/null || echo no)" >&2
    echo "[cloudflared-setup] DEBUG: token length=${#TOKEN}" >&2
    exit 1
fi

# ── Extract fields from the compact JSON: {"a":"...","t":"...","s":"..."} ───
ACCOUNT=$(printf '%s' "$TOKEN_JSON" | sed 's/.*"a":"\([^"]*\)".*/\1/')
UUID=$(printf '%s'    "$TOKEN_JSON" | sed 's/.*"t":"\([^"]*\)".*/\1/')
SECRET=$(printf '%s'  "$TOKEN_JSON" | sed 's/.*"s":"\([^"]*\)".*/\1/')

if [ -z "$ACCOUNT" ] || [ -z "$UUID" ] || [ -z "$SECRET" ]; then
    echo "[cloudflared-setup] ERROR: Could not parse token fields (a/t/s)" >&2
    echo "[cloudflared-setup] Raw JSON: $TOKEN_JSON" >&2
    exit 1
fi

# ── Write credentials.json ───────────────────────────────────────────────────
cat > "$CREDS" <<EOF
{
  "AccountTag":   "$ACCOUNT",
  "TunnelSecret": "$SECRET",
  "TunnelID":     "$UUID"
}
EOF
chmod 600 "$CREDS"

# ── Write config.yml ─────────────────────────────────────────────────────────
# noTLSVerify=true lets cloudflared connect to the local HTTPS server even
# though it uses a self-signed certificate.
cat > "$CONFIG" <<EOF
tunnel: $UUID
credentials-file: $CREDS

ingress:
  - hostname: $DOMAIN
    service: https://localhost:8443
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
chmod 600 "$CONFIG"

echo "[cloudflared-setup] Configured: $DOMAIN -> https://localhost:8443 (noTLSVerify=true)"
echo "[cloudflared-setup] Tunnel UUID: $UUID"
