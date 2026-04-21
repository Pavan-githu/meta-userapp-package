# Cloudflare Tunnel Setup — Raspberry Pi 3 / Yocto Kirkstone

## Overview

This document describes the complete end-to-end setup of a Cloudflare Tunnel that
exposes the IoT Gateway HTTPS server (running on `localhost:8443` on the RPi3) to the
public internet via the domain `raceiotdevice.cc`, without any router port-forwarding.

```
Internet
   │
   ▼
Cloudflare Edge  (anycast — bom, blr PoPs)
   │  (encrypted QUIC / HTTP2)
   ▼
cloudflared daemon  [RPi3 — 192.168.1.9]
   │  (HTTPS, noTLSVerify=true)
   ▼
iot-gateway  →  localhost:8443  (self-signed TLS)
```

---

## Part 1 — Cloudflare Dashboard Configuration

### 1.1 Prerequisites

- A domain registered and added to Cloudflare (DNS managed by Cloudflare).
  In this project: **`raceiotdevice.cc`**
- A Cloudflare account with Zero Trust enabled (free plan is sufficient).

### 1.2 Create a Tunnel

1. Log in to [https://dash.cloudflare.com](https://dash.cloudflare.com).
2. Select your account → **Zero Trust** (left sidebar).
3. Navigate to **Networks** → **Tunnels**.
4. Click **Create a tunnel**.
5. Choose connector type: **Cloudflared** → click **Next**.
6. Enter a tunnel name, e.g. `rpi3-iot-gateway` → click **Save tunnel**.

### 1.3 Install Connector & Copy the Token

After saving, Cloudflare shows an "Install connector" page:

1. Select environment: **Linux → ARM → 32-bit**.
2. Cloudflare displays an install command similar to:
   ```
   cloudflared service install eyJhIjoiYWMyY...
   ```
3. **Copy only the token** (the long base64 string after `install`). This is the
   `CLOUDFLARE_TUNNEL_TOKEN` used throughout this project.

   Token in this project:
   ```
   eyJhIjoiYWMyYzdkOTI0MWE4NTEwMTUwY2Q0MTg0NjA5MjdmNjYiLCJ0IjoiMTMxMDhkNGQtZGY4Yy00NTA2LWFhMWUtZGM2OTI0MTc1YThjIiwicyI6IlpEZ3hZVFZqTm1FdE9EWTFOUzAwTkRZNExUZzVNVGN0Tm1GaE5tUTJZekUwWXpWbSJ9
   ```

   The token is a base64-encoded JSON object containing:
   | Field | Meaning |
   |---|---|
   | `a` | Cloudflare Account Tag (AccountTag) |
   | `t` | Tunnel UUID (TunnelID) |
   | `s` | Tunnel Secret (TunnelSecret) |

   Decoded value:
   ```json
   {
     "a": "ac2c7d9241a8510150cd41846092 7f66",
     "t": "13108d4d-df8c-4506-aa1e-dc6924175a8c",
     "s": "ZDgxYTVjNmEtODY1NS00NDY4LTg5MTctNmFhNmQ2YzE0YzVm"
   }
   ```

4. Click **Next** — do **not** run the Cloudflare install command on the Pi. This
   project packages cloudflared as a Yocto recipe; the token is baked into the image.

### 1.4 Configure Public Hostname (Domain / Subdomain)

On the **Public Hostname** tab:

| Field | Value |
|---|---|
| **Subdomain** | *(leave blank for apex domain, or e.g. `iot`)* |
| **Domain** | `raceiotdevice.cc` |
| **Type** | HTTPS |
| **URL** | `localhost:8443` |

> **Important — use `localhost` not the IP address.**
> Using the IP address (e.g. `192.168.1.9:8443`) causes a TLS error:
> `x509: cannot validate certificate for 192.168.1.9 because it doesn't contain any IP SANs`
> because the self-signed certificate is issued for `localhost`, not an IP.

### 1.5 Enable No TLS Verify

The IoT Gateway uses a **self-signed certificate**. Cloudflare must be told to skip
verification of the origin certificate:

1. On the same Public Hostname edit page, scroll to **Additional application settings**.
2. Expand the **TLS** section.
3. Toggle **No TLS Verify** → **ON**.
4. Click **Save hostname**.

### 1.6 Resulting Tunnel Configuration (as shown in cloudflared logs)

After saving, Cloudflare pushes this remote configuration to the cloudflared daemon:

```json
{
  "ingress": [
    {
      "hostname": "raceiotdevice.cc",
      "service":  "https://localhost:8443",
      "originRequest": { "noTLSVerify": true }
    },
    { "service": "http_status:404" }
  ],
  "warp-routing": { "enabled": false }
}
```

### 1.7 Verify Tunnel Status in Dashboard

Once the Pi is running and connected:
- **Zero Trust → Networks → Tunnels**
- Tunnel status should show **HEALTHY** (green dot)
- Connector count: **1 active connector**, 4 connections (one per Cloudflare PoP)

---

## Part 2 — Build Host Preparation

All steps below are performed on the **Ubuntu build host** before building the Yocto image.

### 2.1 Download the cloudflared ARM Binary

Cloudflare does not publish source for cloudflared in a Yocto-compatible form.
The recipe uses a pre-built ARM 32-bit binary. A helper script handles the download:

```bash
cd /home/ubuntu/rpi3project
bash scripts/download-cloudflared.sh
```

**What the script does:**
1. Queries the GitHub API for the latest cloudflared release tag.
2. Downloads `cloudflared-linux-arm` from:
   `https://github.com/cloudflare/cloudflared/releases/download/<tag>/cloudflared-linux-arm`
3. Saves it to:
   `sources/meta-userapp-package/recipes-apps/cloudflared/files/cloudflared`
4. Sets the file executable (`chmod +x`).
5. Prints the SHA256 checksum for verification.

Version baked into this image: **2026.3.0**

### 2.2 Set the Tunnel Token

Edit the env file with the token copied from the Cloudflare dashboard (Step 1.3):

**File:** `sources/meta-userapp-package/recipes-apps/cloudflared/files/cloudflared-env`

```
CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoiYWMyYzdkOTI0MWE4NTEwMTUwY2Q0MTg0NjA5MjdmNjYiLCJ0IjoiMTMxMDhkNGQtZGY4Yy00NTA2LWFhMWUtZGM2OTI0MTc1YThjIiwicyI6IlpEZ3hZVFZqTm1FdE9EWTFOUzAwTkRZNExUZzVNVGN0Tm1GaE5tUTJZekUwWXpWbSJ9
```

- No quotes around the value.
- The file is installed on the device as `/etc/cloudflared/env` with mode `0600`
  (readable only by root).

### 2.3 Set the Public Domain

Edit the domain file:

**File:** `sources/meta-userapp-package/recipes-apps/cloudflared/files/cloudflared-domain`

```
raceiotdevice.cc
```

- One line, plain hostname, no `https://` prefix, no trailing slash.
- Installed on the device as `/etc/cloudflared/domain` with mode `0644`.
- Read by both `cloudflared-setup.sh` (to write `config.yml`) and the `iot-gateway`
  application (to log the public URL at startup).

### 2.4 Build the Yocto Image

```bash
cd /home/ubuntu/rpi3project
source sources/poky/oe-init-build-env build
bitbake rpi-basic-image
```

The `cloudflared` recipe (`cloudflared_1.0.bb`) is included via:

```
IMAGE_INSTALL:append = " cloudflared"
```

in `build/conf/local.conf`.

---

## Part 3 — Yocto Recipe Details (`cloudflared_1.0.bb`)

### 3.1 Recipe Location

```
sources/meta-userapp-package/recipes-apps/cloudflared/cloudflared_1.0.bb
```

### 3.2 Source Files Packaged

| File in `files/` | Installed path on device | Mode |
|---|---|---|
| `cloudflared` | `/usr/bin/cloudflared` | `0755` |
| `cloudflared.service` | `/lib/systemd/system/cloudflared.service` | `0644` |
| `cloudflared-env` | `/etc/cloudflared/env` | `0600` |
| `cloudflared-domain` | `/etc/cloudflared/domain` | `0644` |
| `cloudflared-setup.sh` | `/etc/cloudflared/cloudflared-setup.sh` | `0755` |

### 3.3 Key Recipe Decisions

- `do_configure[noexec] = "1"` — no source to configure (binary only).
- `do_compile[noexec] = "1"` — no compilation step.
- `inherit systemd` + `SYSTEMD_SERVICE:${PN} = "cloudflared.service"` — registers the
  service with the systemd bbclass.
- `SYSTEMD_AUTO_ENABLE = "enable"` — pre-enables the service.
- An explicit `ln -sf` symlink is created in `multi-user.target.wants/` inside
  `do_install()` to guarantee the service is enabled even if the bbclass symlink
  creation is skipped (learned from the `systemd-networkd` issue in this project).

### 3.4 Layer Configuration

**File:** `sources/meta-userapp-package/conf/layer.conf`

```bitbake
BBFILE_PRIORITY_meta-userapp-package = "6"
LAYERSERIES_COMPAT_meta-userapp-package = "kirkstone"
```

---

## Part 4 — systemd Service (`cloudflared.service`)

```ini
[Unit]
Description=Cloudflare Tunnel
After=network.target network-online.target
Wants=network-online.target
Requires=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/cloudflared/env
ExecStartPre=/etc/cloudflared/cloudflared-setup.sh
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate \
          --config /etc/cloudflared/config.yml run
Restart=on-failure
RestartSec=15
StartLimitIntervalSec=120
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
```

**Key points:**

- `Requires=network-online.target` — waits for the network to be fully up before
  starting. Critical on Wi-Fi where DHCP may take several seconds.
- `EnvironmentFile=/etc/cloudflared/env` — makes `CLOUDFLARE_TUNNEL_TOKEN` available
  to the shell environment when `ExecStartPre` runs.
- `ExecStartPre` runs `cloudflared-setup.sh` — decodes the token and generates the
  config files on first boot.
- `--no-autoupdate` — prevents cloudflared from attempting a self-update (not possible
  in a read-only / embedded image).
- `Restart=on-failure` with `RestartSec=15` and burst limit — handles transient network
  failures gracefully without a rapid restart loop.

---

## Part 5 — First-Boot Token Decoding (`cloudflared-setup.sh`)

**Script location on device:** `/etc/cloudflared/cloudflared-setup.sh`

Run as `ExecStartPre` every boot, but **exits immediately if already configured**
(idempotent — skips if both `credentials.json` and `config.yml` exist).

### Step-by-step execution on first boot

**Step 1 — Check if already configured**
```sh
if [ -f "$CREDS" ] && [ -f "$CONFIG" ]; then exit 0; fi
```

**Step 2 — Load the tunnel token from env**
```sh
. /etc/cloudflared/env
# CLOUDFLARE_TUNNEL_TOKEN is now available
```

**Step 3 — Read the public domain**
```sh
DOMAIN=$(grep -v '^#' /etc/cloudflared/domain | head -n 1 | tr -d '[:space:]')
# DOMAIN = "raceiotdevice.cc"
```

**Step 4 — Fix base64 padding**
The token may be missing `=` padding characters. The script calculates and appends
the correct padding before decoding:
```sh
MOD=$(( ${#TOKEN} % 4 ))
# Appends 0, 1, 2, or 3 '=' characters as needed
```

**Step 5 — Base64-decode the token**
```sh
TOKEN_JSON=$(printf '%s\n' "$TOKEN" | base64 -d 2>/dev/null)
# Falls back to: openssl base64 -d -A  (for BusyBox compatibility)
```

Decoded JSON:
```json
{"a":"ac2c7d9241a8510150cd418460927f66",
 "t":"13108d4d-df8c-4506-aa1e-dc6924175a8c",
 "s":"ZDgxYTVjNmEtODY1NS00NDY4LTg5MTctNmFhNmQ2YzE0YzVm"}
```

**Step 6 — Extract fields using `sed`**
```sh
ACCOUNT=$(printf '%s' "$TOKEN_JSON" | sed 's/.*"a":"\([^"]*\)".*/\1/')
UUID=$(printf '%s'    "$TOKEN_JSON" | sed 's/.*"t":"\([^"]*\)".*/\1/')
SECRET=$(printf '%s'  "$TOKEN_JSON" | sed 's/.*"s":"\([^"]*\)".*/\1/')
```

**Step 7 — Write `/etc/cloudflared/credentials.json`** (mode 0600)
```json
{
  "AccountTag":   "ac2c7d9241a8510150cd418460927f66",
  "TunnelSecret": "ZDgxYTVjNmEtODY1NS00NDY4LTg5MTctNmFhNmQ2YzE0YzVm",
  "TunnelID":     "13108d4d-df8c-4506-aa1e-dc6924175a8c"
}
```

**Step 8 — Write `/etc/cloudflared/config.yml`** (mode 0600)
```yaml
tunnel: 13108d4d-df8c-4506-aa1e-dc6924175a8c
credentials-file: /etc/cloudflared/credentials.json

ingress:
  - hostname: raceiotdevice.cc
    service: https://localhost:8443
    originRequest:
      noTLSVerify: true
  - service: http_status:404
```

`noTLSVerify: true` allows cloudflared to connect to the IoT Gateway's self-signed
TLS certificate without failure.

---

## Part 6 — Files on Device After First Boot

```
/usr/bin/cloudflared                        ← daemon binary
/etc/cloudflared/
    env                                     ← tunnel token (0600, baked at build time)
    domain                                  ← public domain (0644, baked at build time)
    cloudflared-setup.sh                    ← setup script (0755, baked at build time)
    credentials.json                        ← generated on first boot (0600)
    config.yml                              ← generated on first boot (0600)
/lib/systemd/system/cloudflared.service     ← service unit
/etc/systemd/system/multi-user.target.wants/cloudflared.service  ← enable symlink
```

---

## Part 7 — Verification Commands (on the Pi)

### Check service status
```bash
systemctl status cloudflared
```

Expected output:
```
Active: active (running) since ...
Process: ExecStartPre=/etc/cloudflared/cloudflared-setup.sh (code=exited, status=0/SUCCESS)
Main PID: ... (cloudflared)
```

### Watch live logs
```bash
journalctl -u cloudflared -f
```

### Expected healthy log lines
```
INF Starting tunnel tunnelID=13108d4d-df8c-4506-aa1e-dc6924175a8c
INF Version 2026.3.0
INF Registered tunnel connection connIndex=0 ... location=bom10 protocol=http2
INF Registered tunnel connection connIndex=1 ... location=blr02 protocol=http2
INF Registered tunnel connection connIndex=2 ... location=bom09 protocol=http2
INF Registered tunnel connection connIndex=3 ... location=blr02 protocol=http2
INF Updated to new configuration config="...noTLSVerify:true..."
```
Four connections (connIndex 0–3) are registered across Cloudflare PoPs
(bom = Mumbai, blr = Bangalore in this deployment).

### Verify config files generated
```bash
cat /etc/cloudflared/config.yml
cat /etc/cloudflared/credentials.json
```

### Test local origin is reachable
```bash
curl -k https://localhost:8443
```

### Test public URL
```bash
curl https://raceiotdevice.cc
```

---

## Part 8 — Troubleshooting

### Issue: `x509: cannot validate certificate for 192.168.1.9 because it doesn't contain any IP SANs`

**Cause:** The Cloudflare dashboard remote config was set to `https://192.168.1.9:8443`
(IP address as origin). The self-signed certificate is issued for `localhost` (a
hostname), not for the IP address `192.168.1.9`. TLS verification fails because
the IP has no Subject Alternative Name (SAN) in the certificate.

Additionally, the remote config did not have `noTLSVerify` set, so it overrode the
local `config.yml` (which did have `noTLSVerify: true`).

**Fix applied:**
1. Changed origin in Cloudflare dashboard from `https://192.168.1.9:8443` → `https://localhost:8443`
2. Enabled **No TLS Verify** in the dashboard (Zero Trust → Tunnels → Edit → Public Hostname → TLS → No TLS Verify ON)

**Why remote config overrides local config:**
When cloudflared is managed via the Cloudflare dashboard (as opposed to `cloudflared tunnel create` CLI), it pulls a versioned remote configuration from Cloudflare's management API at startup and on config changes. The `INF Updated to new configuration ... version=N` log line confirms this. The remote config fully replaces the local `ingress:` section of `config.yml`.

---

### Issue: `flag provided but not defined: -management-diagnostics`

**Cause:** The `--management-diagnostics` flag does not exist in cloudflared v2026.x.

**Resolution:** Not needed — the correct fix was updating the Cloudflare dashboard config
(Part 1, Steps 1.4 and 1.5).

---

## Part 9 — Quick-Reference: Changing Token or Domain After Build

If the tunnel token or domain needs to change after the image is flashed:

**On the Pi directly:**
```bash
# 1. Stop the service
systemctl stop cloudflared

# 2. Edit the token
vi /etc/cloudflared/env

# 3. Edit the domain (if needed)
vi /etc/cloudflared/domain

# 4. Remove generated files so setup script re-runs
rm /etc/cloudflared/credentials.json /etc/cloudflared/config.yml

# 5. Restart
systemctl start cloudflared
journalctl -u cloudflared -f
```

**For a new image build**, update the source files before building:
- `recipes-apps/cloudflared/files/cloudflared-env` — new token
- `recipes-apps/cloudflared/files/cloudflared-domain` — new domain

---

## Summary

| Step | Where | What |
|---|---|---|
| Create tunnel | Cloudflare dashboard | Generates tunnel token + UUID |
| Set public hostname | Cloudflare dashboard | `raceiotdevice.cc` → `https://localhost:8443` |
| Enable No TLS Verify | Cloudflare dashboard | Allows self-signed cert on origin |
| Download binary | Build host | `bash scripts/download-cloudflared.sh` |
| Set token | `files/cloudflared-env` | Paste `CLOUDFLARE_TUNNEL_TOKEN=` |
| Set domain | `files/cloudflared-domain` | `raceiotdevice.cc` |
| Build image | Build host | `bitbake rpi-basic-image` |
| Flash & boot | Pi | Service auto-starts, setup script decodes token |
| First boot | Pi | `credentials.json` + `config.yml` generated |
| Running | Pi | 4 connections to Cloudflare edge, tunnel HEALTHY |
