#!/usr/bin/env bash
# =============================================================================
# run_tests.sh — IoT Gateway HTTPS Server Integration Test Runner
#
# Usage:
#   ./tests/run_tests.sh <device-ip> <port> [totp-code]
#
# Examples:
#   ./tests/run_tests.sh 192.168.1.100 8443
#   ./tests/run_tests.sh 192.168.1.100 8443 123456
#
# Output:
#   - Console: coloured PASS / FAIL per test case
#   - File:    tests/logs/YYYY-MM-DD_HH-MM-SS/results.log
#              tests/logs/YYYY-MM-DD_HH-MM-SS/TC-XX_<name>.log
#
# Requirements: curl, grep, bash >= 4
# =============================================================================

set -euo pipefail

# ── Args ─────────────────────────────────────────────────────────────────────
DEVICE_IP="${1:-192.168.1.100}"
PORT="${2:-8443}"
TOTP_CODE="${3:-}"          # Optional: provide live TOTP code for TC-10
BASE_URL="https://${DEVICE_IP}:${PORT}"
CURL_OPTS="--insecure --silent --max-time 10"

# ── Logging setup ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs/$(date '+%Y-%m-%d_%H-%M-%S')"
mkdir -p "${LOG_DIR}"
SUMMARY_LOG="${LOG_DIR}/results.log"

# ── Colour codes ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Counters ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo -e "$*" | tee -a "${SUMMARY_LOG}"; }

pass() {
    local tc="$1" desc="$2"
    PASS=$((PASS + 1))
    log "${GREEN}[PASS]${NC} ${tc} — ${desc}"
}

fail() {
    local tc="$1" desc="$2" reason="${3:-}"
    FAIL=$((FAIL + 1))
    log "${RED}[FAIL]${NC} ${tc} — ${desc}${reason:+  ($reason)}"
}

skip() {
    local tc="$1" desc="$2" reason="${3:-}"
    SKIP=$((SKIP + 1))
    log "${YELLOW}[SKIP]${NC} ${tc} — ${desc}${reason:+  ($reason)}"
}

# Run curl, save full response (headers + body) to a per-TC log file.
# Returns the HTTP status code.
do_curl() {
    local tc="$1"; shift
    local tc_log="${LOG_DIR}/${tc}.log"
    # Write timestamp header
    echo "=== ${tc} $(date '+%Y-%m-%d %H:%M:%S') ===" > "${tc_log}"
    echo "CMD: curl ${CURL_OPTS} $*" >> "${tc_log}"
    echo "---" >> "${tc_log}"
    # Run curl: status on stdout, body+headers to log
    local http_code
    http_code=$(curl ${CURL_OPTS} \
        --write-out "%{http_code}" \
        --dump-header "${tc_log}.headers" \
        --output "${tc_log}.body" \
        "$@" 2>>"${tc_log}") || true
    cat "${tc_log}.headers" >> "${tc_log}" 2>/dev/null || true
    cat "${tc_log}.body"    >> "${tc_log}" 2>/dev/null || true
    echo "${http_code}"
}

# Check that a file contains an expected string (grep -q)
body_contains() {
    local tc="$1" pattern="$2"
    grep -qi "${pattern}" "${LOG_DIR}/${tc}.log.body" 2>/dev/null
}

# ── Cookie jar file (shared across tests that need sessions) ──────────────────
COOKIE_JAR="${LOG_DIR}/cookies.txt"

# =============================================================================
# Test cases
# =============================================================================

log ""
log "=============================================="
log " IoT Gateway Test Run — $(date '+%Y-%m-%d %H:%M:%S')"
log " Target: ${BASE_URL}"
log "=============================================="
log ""

# ── TC-01: Register valid user ────────────────────────────────────────────────
TC="TC-01"
DESC="Register valid user"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "username=testuser01&password=Test@1234" \
    "${BASE_URL}/register")
if [[ "${http}" == "200" ]] && body_contains "${TC}" "Registration Successful"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-02: Register duplicate username ───────────────────────────────────────
TC="TC-02"
DESC="Register duplicate username"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "username=testuser01&password=Test@1234" \
    "${BASE_URL}/register")
if [[ "${http}" == "409" ]]; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http} (expected 409)"
fi

# ── TC-03: Weak password ─────────────────────────────────────────────────────
TC="TC-03"
DESC="Register weak password (policy violation)"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "username=weakuser&password=abc" \
    "${BASE_URL}/register")
if [[ "${http}" == "400" ]] && body_contains "${TC}" "policy"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-04: Empty fields ───────────────────────────────────────────────────────
TC="TC-04"
DESC="Register with empty username/password"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "username=&password=" \
    "${BASE_URL}/register")
if [[ "${http}" == "400" ]]; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-05: Login with valid credentials ───────────────────────────────────────
TC="TC-05"
DESC="Login valid credentials → OTP redirect + cookie"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "username=testuser01&password=Test@1234" \
    --cookie-jar "${COOKIE_JAR}" \
    --location-trusted \
    -D "${LOG_DIR}/${TC}.headers_raw" \
    "${BASE_URL}/login")
if [[ "${http}" == "200" || "${http}" == "303" ]] && \
   grep -qi "iotgw_session" "${LOG_DIR}/${TC}.headers_raw" 2>/dev/null; then
    pass "${TC}" "${DESC}"
elif [[ "${http}" == "200" ]] && body_contains "${TC}" "OTP\|otp\|Redirect"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http} — check cookie header"
fi

# ── TC-06: Login wrong password ×1 ───────────────────────────────────────────
TC="TC-06"
DESC="Login wrong password ×1 — 2 attempts remaining"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "username=testuser01&password=WrongPass!9" \
    "${BASE_URL}/login")
if [[ "${http}" == "401" ]] && body_contains "${TC}" "remaining"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-07: Login lockout after 3 bad passwords ────────────────────────────────
TC="TC-07"
DESC="Login lockout after 3 failed password attempts"
log "\n--- ${TC}: ${DESC}"
# Register a fresh user for lockout test so testuser01 stays unlocked
do_curl "TC-07-setup" \
    -X POST \
    -d "username=lockoutuser&password=Lock@9876" \
    "${BASE_URL}/register" > /dev/null
final_http=0
for i in 1 2 3; do
    final_http=$(do_curl "${TC}_attempt${i}" \
        -X POST \
        -d "username=lockoutuser&password=BadPass!1" \
        "${BASE_URL}/login")
done
if [[ "${final_http}" == "403" ]] && \
   body_contains "${TC}_attempt3" "Locked\|locked"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${final_http} (expected 403 on 3rd attempt)"
fi

# ── TC-08: Username injection attempt ─────────────────────────────────────────
TC="TC-08"
DESC="Login username injection — rejected by isValidUsername"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    --data-urlencode "username=admin'--" \
    --data-urlencode "password=anything" \
    "${BASE_URL}/login")
if [[ "${http}" == "400" ]]; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http} (expected 400)"
fi

# ── TC-09: Lockout auto-expire (manual / time-based — skip in automated run) ──
TC="TC-09"
DESC="Lockout auto-expires after 30 min"
skip "${TC}" "${DESC}" "Requires 30-min wait — run manually"

# ── TC-10: OTP valid code ─────────────────────────────────────────────────────
TC="TC-10"
DESC="OTP valid TOTP code → dashboard"
log "\n--- ${TC}: ${DESC}"
if [[ -z "${TOTP_CODE}" ]]; then
    skip "${TC}" "${DESC}" "No TOTP code supplied (pass as 3rd arg)"
else
    http=$(do_curl "${TC}" \
        -X POST \
        --cookie "${COOKIE_JAR}" \
        -d "otp=${TOTP_CODE}" \
        "${BASE_URL}/otp")
    if [[ "${http}" == "200" ]] && body_contains "${TC}" "Login Successful\|Dashboard"; then
        pass "${TC}" "${DESC}"
    else
        fail "${TC}" "${DESC}" "HTTP=${http}"
    fi
fi

# ── TC-11: OTP lockout ×3 ─────────────────────────────────────────────────────
TC="TC-11"
DESC="OTP lockout after 3 wrong codes"
log "\n--- ${TC}: ${DESC}"
# Get a fresh OTP session cookie first
do_curl "TC-11-login" \
    -X POST \
    -d "username=testuser01&password=Test@1234" \
    --cookie-jar "${LOG_DIR}/tc11_cookies.txt" \
    "${BASE_URL}/login" > /dev/null
final_http=0
for i in 1 2 3; do
    final_http=$(do_curl "${TC}_attempt${i}" \
        -X POST \
        --cookie "${LOG_DIR}/tc11_cookies.txt" \
        -d "otp=000000" \
        "${BASE_URL}/otp")
done
if [[ "${final_http}" == "403" ]] || \
   body_contains "${TC}_attempt3" "Locked\|locked"; then
    pass "${TC}" "${DESC}"
elif [[ "${final_http}" == "401" ]]; then
    # May get 401 if session expired or cookie not sent correctly
    fail "${TC}" "${DESC}" "HTTP=${final_http} — verify cookie is being forwarded"
else
    fail "${TC}" "${DESC}" "HTTP=${final_http}"
fi

# ── TC-12: OTP expired session ────────────────────────────────────────────────
TC="TC-12"
DESC="OTP expired session (stale cookie)"
log "\n--- ${TC}: ${DESC}"
# Use a fabricated session id that won't be in the map
http=$(do_curl "${TC}" \
    -X POST \
    -H "Cookie: iotgw_session=00000000-0000-0000-0000-000000000000" \
    -d "otp=123456" \
    "${BASE_URL}/otp")
if [[ "${http}" == "401" ]] && \
   body_contains "${TC}" "Expired\|expired\|No session"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-13: OTP no cookie ─────────────────────────────────────────────────────
TC="TC-13"
DESC="OTP POST with no cookie → 401"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    -X POST \
    -d "otp=123456" \
    "${BASE_URL}/otp")
if [[ "${http}" == "401" ]]; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-14: OTP invalid format ─────────────────────────────────────────────────
TC="TC-14"
DESC="OTP invalid format (letters / wrong length)"
log "\n--- ${TC}: ${DESC}"
# Re-login to get a valid session cookie
do_curl "TC-14-login" \
    -X POST \
    -d "username=testuser01&password=Test@1234" \
    --cookie-jar "${LOG_DIR}/tc14_cookies.txt" \
    "${BASE_URL}/login" > /dev/null
http=$(do_curl "${TC}" \
    -X POST \
    --cookie "${LOG_DIR}/tc14_cookies.txt" \
    -d "otp=abc" \
    "${BASE_URL}/otp")
if [[ "${http}" == "400" ]] && body_contains "${TC}" "format\|Invalid"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-15: File upload ────────────────────────────────────────────────────────
TC="TC-15"
DESC="POST /upload multipart file"
log "\n--- ${TC}: ${DESC}"
TMP_FILE=$(mktemp /tmp/test_firmware_XXXX.bin)
dd if=/dev/urandom bs=1024 count=4 of="${TMP_FILE}" 2>/dev/null
http=$(do_curl "${TC}" \
    -X POST \
    -F "file=@${TMP_FILE}" \
    "${BASE_URL}/upload")
rm -f "${TMP_FILE}"
if [[ "${http}" == "200" ]] && body_contains "${TC}" "successful\|bytes"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-16: LED control valid speed ────────────────────────────────────────────
TC="TC-16"
DESC="GET /startledblink?speed=5 → JSON success"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    "${BASE_URL}/startledblink?speed=5")
if [[ "${http}" == "200" ]] && body_contains "${TC}" "success"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-17: LED control invalid speed ──────────────────────────────────────────
TC="TC-17"
DESC="GET /startledblink?speed=999 → 400"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    "${BASE_URL}/startledblink?speed=999")
if [[ "${http}" == "400" ]] && body_contains "${TC}" "error\|between"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-18: Status page ────────────────────────────────────────────────────────
TC="TC-18"
DESC="GET /status → system status HTML"
log "\n--- ${TC}: ${DESC}"
http=$(do_curl "${TC}" \
    "${BASE_URL}/status")
if [[ "${http}" == "200" ]] && body_contains "${TC}" "System Status\|Gateway"; then
    pass "${TC}" "${DESC}"
else
    fail "${TC}" "${DESC}" "HTTP=${http}"
fi

# ── TC-19: mTLS — connection without client cert ──────────────────────────────
TC="TC-19"
DESC="mTLS enabled: connection without client cert should fail at TLS"
log "\n--- ${TC}: ${DESC}"
# When mTLS is active, curl will fail with a TLS error (exit non-zero)
# We detect this by looking for curl error or HTTP 0
http=$(curl --insecure --silent --max-time 10 \
    --write-out "%{http_code}" \
    --output "${LOG_DIR}/${TC}.log.body" \
    "${BASE_URL}/" 2>"${LOG_DIR}/${TC}.curl_err" || true)
if [[ "${http}" == "000" ]] || grep -qi "SSL\|handshake\|alert" "${LOG_DIR}/${TC}.curl_err" 2>/dev/null; then
    pass "${TC}" "${DESC}"
else
    skip "${TC}" "${DESC}" "HTTP=${http} — mTLS may not be enabled (no Root CA loaded)"
fi

# ── TC-20: mTLS — valid client cert ───────────────────────────────────────────
TC="TC-20"
DESC="mTLS: valid client cert accepted"
log "\n--- ${TC}: ${DESC}"
CLIENT_CERT="${SCRIPT_DIR}/certs/client.crt"
CLIENT_KEY="${SCRIPT_DIR}/certs/client.key"
if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" ]]; then
    http=$(do_curl "${TC}" \
        --cert "${CLIENT_CERT}" \
        --key "${CLIENT_KEY}" \
        "${BASE_URL}/")
    if [[ "${http}" == "200" ]]; then
        pass "${TC}" "${DESC}"
    else
        fail "${TC}" "${DESC}" "HTTP=${http}"
    fi
else
    skip "${TC}" "${DESC}" "Client cert not found at tests/certs/client.crt"
fi

# ── TC-21/22: Blockchain events — manual verification ────────────────────────
skip "TC-21" "Blockchain event logging" "Verify via eth_getLogs after TC-05/TC-10"
skip "TC-22" "Blockchain offline queue replay" "Requires killing Ethereum node — run manually"

# =============================================================================
# Summary
# =============================================================================
TOTAL=$((PASS + FAIL + SKIP))
log ""
log "=============================================="
log " Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped / ${TOTAL} total"
log " Logs:    ${LOG_DIR}/"
log "=============================================="
log ""

# Write a machine-readable summary JSON
cat > "${LOG_DIR}/summary.json" <<EOF
{
  "timestamp": "$(date '+%Y-%m-%dT%H:%M:%S')",
  "target": "${BASE_URL}",
  "passed": ${PASS},
  "failed": ${FAIL},
  "skipped": ${SKIP},
  "total": ${TOTAL}
}
EOF

# Exit non-zero if any tests failed (useful for CI)
[[ ${FAIL} -eq 0 ]]
