# IoT Gateway HTTPS Server — Test Plan

> **Repo:** `meta-userapp-package`  
> **Component:** `iot-gateway` HTTPS server (`https_server.cpp`)  
> **How to run:** `./tests/run_tests.sh <device-ip> <port>`  
> **Logs stored in:** `tests/logs/YYYY-MM-DD_HH-MM-SS/`

---

## Environment Setup

| Item | Value |
|------|-------|
| Target device | Raspberry Pi / QEMU (Yocto image) |
| Server port | 8443 (default) |
| Test tool | `curl` with `--insecure` (self-signed cert) |
| mTLS test tool | `curl` with `--cert` / `--cacert` |

---

## Test Cases

### TC-01 — Registration: Valid User

**Objective:** Register a new user with a policy-compliant password and confirm TOTP QR is shown.

| Field | Value |
|-------|-------|
| Endpoint | `POST /register` |
| Method | `curl -X POST -d "username=testuser&password=Test@1234"` |
| Expected HTTP | `200 OK` |
| Expected body | Contains "Registration Successful" and TOTP QR image |
| Pass/Fail | |
| Notes | |

---

### TC-02 — Registration: Duplicate Username

**Objective:** Registering the same username twice should fail.

| Field | Value |
|-------|-------|
| Prerequisite | TC-01 passed |
| Endpoint | `POST /register` |
| Input | Same username as TC-01 |
| Expected HTTP | `409 Conflict` |
| Expected body | "Username already exists" |
| Pass/Fail | |
| Notes | |

---

### TC-03 — Registration: Weak Password (Policy Violation)

**Objective:** Password failing policy rules should be rejected before DB write.

| Field | Value |
|-------|-------|
| Endpoint | `POST /register` |
| Input | `username=weakuser&password=abc` |
| Expected HTTP | `400 Bad Request` |
| Expected body | Lists all policy requirements |
| Pass/Fail | |
| Notes | |

---

### TC-04 — Registration: Empty Fields

**Objective:** Empty username or password should return 400, not crash.

| Field | Value |
|-------|-------|
| Endpoint | `POST /register` |
| Input | `username=&password=` |
| Expected HTTP | `400 Bad Request` |
| Expected body | "Username and password are required" |
| Pass/Fail | |
| Notes | |

---

### TC-05 — Login: Valid Credentials

**Objective:** Correct credentials redirect to OTP page and set `iotgw_session` cookie.

| Field | Value |
|-------|-------|
| Prerequisite | TC-01 passed |
| Endpoint | `POST /login` |
| Input | `username=testuser&password=Test@1234` |
| Expected HTTP | `303 See Other` |
| Expected header | `Location: /otp` |
| Expected cookie | `iotgw_session=<uuid>; HttpOnly; Secure; SameSite=Strict` |
| Pass/Fail | |
| Notes | |

---

### TC-06 — Login: Wrong Password (1st attempt)

**Objective:** Single wrong password returns 401 with remaining-attempt count.

| Field | Value |
|-------|-------|
| Endpoint | `POST /login` |
| Input | `username=testuser&password=WrongPass!1` |
| Expected HTTP | `401 Unauthorized` |
| Expected body | "2 attempt(s) remaining" |
| Pass/Fail | |
| Notes | |

---

### TC-07 — Login: Wrong Password (3rd attempt — lockout trigger)

**Objective:** Third failed password attempt locks account for 30 minutes.

| Field | Value |
|-------|-------|
| Endpoint | `POST /login` × 3 |
| Input | Bad password each time |
| Expected HTTP last call | `403 Forbidden` |
| Expected body | Countdown modal / "Account Locked" |
| Blockchain event | Single `LOCKOUT` event emitted (not per-attempt) |
| Pass/Fail | |
| Notes | |

---

### TC-08 — Login: Username Injection Attempt

**Objective:** Malformed username (SQL-like / path chars) rejected before DB I/O.

| Field | Value |
|-------|-------|
| Endpoint | `POST /login` |
| Input | `username=admin'--&password=any` |
| Expected HTTP | `400 Bad Request` |
| Expected body | "Invalid username or password" |
| Pass/Fail | |
| Notes | `isValidUsername()` enforces `[a-zA-Z0-9_-]` ≤64 chars |

---

### TC-09 — Login: Lockout Auto-Expires After 30 Minutes

**Objective:** After lockout TTL, account auto-unlocks without admin intervention.

| Field | Value |
|-------|-------|
| Prerequisite | TC-07 passed |
| Action | Wait 30 min (or mock `lock_time` in test) |
| Endpoint | `POST /login` with correct password |
| Expected HTTP | `303 See Other` (OTP redirect) |
| Pass/Fail | |
| Notes | |

---

### TC-10 — OTP: Valid TOTP Code

**Objective:** Correct TOTP code grants session and clears OTP cookie.

| Field | Value |
|-------|-------|
| Prerequisite | TC-05 session cookie in hand + TOTP app seeded |
| Endpoint | `POST /otp` with cookie + correct `otp=XXXXXX` |
| Expected HTTP | `200 OK` |
| Expected body | "Login Successful" dashboard |
| Expected cookie | `iotgw_session=; Max-Age=0` (cookie cleared) |
| Blockchain event | `OTP_SUCCESS` |
| Pass/Fail | |
| Notes | |

---

### TC-11 — OTP: Wrong Code (up to 3 times — lockout)

**Objective:** Three wrong OTP attempts lock the account with blockchain `LOCKOUT` event.

| Field | Value |
|-------|-------|
| Endpoint | `POST /otp` × 3 with wrong code |
| Expected HTTP (3rd) | `403 Forbidden` |
| Expected body | Countdown lockout modal |
| Blockchain events | `OTP_FAIL` × 3, then `LOCKOUT` |
| Pass/Fail | |
| Notes | |

---

### TC-12 — OTP: Expired Session (> 120 s)

**Objective:** OTP session cookie older than TTL is rejected.

| Field | Value |
|-------|-------|
| Action | Wait >120 s after TC-05 |
| Endpoint | `POST /otp` with stale cookie |
| Expected HTTP | `401 Unauthorized` |
| Expected body | "Session Expired" |
| Pass/Fail | |
| Notes | |

---

### TC-13 — OTP: No Cookie / Missing Session

**Objective:** Request to `/otp` without cookie returns 401.

| Field | Value |
|-------|-------|
| Endpoint | `POST /otp` (no cookie header) |
| Expected HTTP | `401 Unauthorized` |
| Expected body | "No session found" |
| Pass/Fail | |
| Notes | |

---

### TC-14 — OTP: Invalid Format (non-numeric / wrong length)

**Objective:** Malformed OTP (letters, wrong length) rejected before TOTP check.

| Field | Value |
|-------|-------|
| Endpoint | `POST /otp` with `otp=abc` or `otp=1234` |
| Expected HTTP | `400 Bad Request` |
| Expected body | "Invalid OTP format" |
| Pass/Fail | |
| Notes | |

---

### TC-15 — File Upload: POST /upload

**Objective:** Authenticated user can upload a binary file.

| Field | Value |
|-------|-------|
| Endpoint | `POST /upload` |
| Input | Multipart file (e.g. `firmware.bin`) |
| Expected HTTP | `200 OK` |
| Expected body | "Upload successful! Received X bytes" |
| Pass/Fail | |
| Notes | |

---

### TC-16 — LED Control: Set Speed

**Objective:** `GET /startledblink?speed=5` updates blink speed.

| Field | Value |
|-------|-------|
| Endpoint | `GET /startledblink?speed=5` |
| Expected HTTP | `200 OK` |
| Expected body | JSON `{"status":"success","speed":5}` |
| Pass/Fail | |
| Notes | |

---

### TC-17 — LED Control: Invalid Speed

**Objective:** Out-of-range speed (e.g. `speed=999`) returns 400.

| Field | Value |
|-------|-------|
| Endpoint | `GET /startledblink?speed=999` |
| Expected HTTP | `400 Bad Request` |
| Expected body | "Speed must be between 1 and 60 seconds" |
| Pass/Fail | |
| Notes | |

---

### TC-18 — Status Page

**Objective:** `/status` shows HTTPS + blockchain status and activity log.

| Field | Value |
|-------|-------|
| Endpoint | `GET /status` |
| Expected HTTP | `200 OK` |
| Expected body | "IoT Gateway System Status", Ethereum node reachability |
| Pass/Fail | |
| Notes | Auto-refreshes every 15 s |

---

### TC-19 — mTLS: Connection Without Client Certificate

**Objective:** When mTLS is enabled, a plain browser connection (no client cert) is rejected at TLS handshake.

| Field | Value |
|-------|-------|
| Prerequisite | Server started with Root CA (mTLS enabled) |
| Action | `curl --insecure https://<ip>:8443/` (no `--cert`) |
| Expected | TLS handshake failure — connection refused/reset |
| Pass/Fail | |
| Notes | No HTTP response should be returned |

---

### TC-20 — mTLS: Connection With Valid Client Certificate

**Objective:** cloudflared-signed client cert is accepted; request reaches server.

| Field | Value |
|-------|-------|
| Prerequisite | Valid client cert signed by Root CA |
| Action | `curl --insecure --cert client.crt --key client.key https://<ip>:8443/` |
| Expected HTTP | `200 OK` |
| Pass/Fail | |
| Notes | |

---

### TC-21 — Blockchain: Event Logging on Login Success

**Objective:** Successful login submits `LOGIN_ATTEMPT` event to Ethereum node.

| Field | Value |
|-------|-------|
| Prerequisite | Ethereum node reachable |
| Action | Perform TC-05 + TC-10 |
| Verify | Check blockchain transaction log / `eth_getLogs` |
| Expected events | `LOGIN_ATTEMPT`, `OTP_SENT`, `OTP_SUCCESS` |
| Pass/Fail | |
| Notes | |

---

### TC-22 — Blockchain: Offline Queue and Replay

**Objective:** Events queued when blockchain unreachable are replayed when it returns.

| Field | Value |
|-------|-------|
| Action | Kill Ethereum node, perform login, restore node |
| Expected | Events appear in blockchain after node restores |
| Pass/Fail | |
| Notes | |

---

## Test Result Summary Table

| TC | Description | Expected HTTP | Result | Log File |
|----|-------------|---------------|--------|----------|
| TC-01 | Register valid user | 200 | | |
| TC-02 | Register duplicate | 409 | | |
| TC-03 | Weak password | 400 | | |
| TC-04 | Empty fields | 400 | | |
| TC-05 | Login valid | 303 | | |
| TC-06 | Login wrong pw ×1 | 401 | | |
| TC-07 | Login lockout ×3 | 403 | | |
| TC-08 | Username injection | 400 | | |
| TC-09 | Lockout auto-expire | 303 | | |
| TC-10 | OTP valid | 200 | | |
| TC-11 | OTP lockout ×3 | 403 | | |
| TC-12 | OTP expired | 401 | | |
| TC-13 | OTP no cookie | 401 | | |
| TC-14 | OTP bad format | 400 | | |
| TC-15 | File upload | 200 | | |
| TC-16 | LED set speed | 200 | | |
| TC-17 | LED invalid speed | 400 | | |
| TC-18 | Status page | 200 | | |
| TC-19 | mTLS no cert | TLS fail | | |
| TC-20 | mTLS valid cert | 200 | | |
| TC-21 | Blockchain events | on-chain | | |
| TC-22 | Blockchain offline queue | on-chain | | |
