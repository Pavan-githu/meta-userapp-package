# Step-by-Step Guide: Making HTTPS Server Publicly Accessible

## Overview
This guide walks you through making your IoT Gateway HTTPS server accessible from the public internet.

## Architecture
```
Internet → [ISP] → [Modem] → [Router] → [Raspberry Pi with HTTPS Server]
                                ↓
                         Port Forwarding
                         (8443 → 192.168.x.x:8443)
```

---

## ✅ Step 1: Server Code Configuration (COMPLETED)

The server now:
- ✅ Binds to `0.0.0.0` (all network interfaces)
- ✅ Displays local network IP automatically
- ✅ Shows access instructions on startup

**What was changed:**
- Added `bind_address` parameter (default: "0.0.0.0")
- Added `getLocalIPAddress()` function to detect network IP
- Enhanced startup messages with detailed access information

---

## 📋 Step 2: Find Your Raspberry Pi's Local IP Address

### On Raspberry Pi, run:
```bash
hostname -I
# or
ip addr show eth0
# or for WiFi
ip addr show wlan0
```

**Example output:** `192.168.1.100`

**Note this IP - you'll need it for port forwarding!**

---

## 🔧 Step 3: Set Static IP on Raspberry Pi

### Why?
Your router assigns dynamic IPs which can change. Port forwarding needs a fixed IP.

### Option A: Router DHCP Reservation (Recommended)
1. Login to router admin (usually `192.168.1.1` or `192.168.0.1`)
2. Find DHCP settings
3. Add reservation for Raspberry Pi's MAC address
4. Assign: `192.168.1.100` (or your preferred IP)

### Option B: Configure Static IP on Pi
Edit `/etc/network/interfaces` or use `nmcli`:
```bash
sudo nmcli con mod "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 192.168.1.100/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns "8.8.8.8,8.8.4.4"
sudo nmcli con up "Wired connection 1"
```

---

## 🌐 Step 4: Configure Router Port Forwarding

### Steps (varies by router model):

1. **Access Router Admin Panel**
   - Open browser: `http://192.168.1.1` (or `192.168.0.1`)
   - Login with admin credentials

2. **Navigate to Port Forwarding**
   - Look for: "Port Forwarding", "Virtual Server", "NAT", or "Firewall"
   - Common locations:
     - TP-Link: Advanced → NAT Forwarding → Virtual Servers
     - Netgear: Advanced → Advanced Setup → Port Forwarding
     - Asus: WAN → Virtual Server / Port Forwarding
     - Linksys: Security → Apps and Gaming → Single Port Forwarding

3. **Add Port Forwarding Rule**
   ```
   Service Name:     HTTPS-IoT-Gateway
   External Port:    8443
   Internal IP:      192.168.1.100  (your Pi's IP)
   Internal Port:    8443
   Protocol:         TCP
   Status:           Enabled
   ```

4. **Save and Apply** settings

### Example Screenshots (Generic):
```
┌──────────────────────────────────────────┐
│ Port Forwarding Configuration            │
├──────────────────────────────────────────┤
│ Service Name: HTTPS-IoT-Gateway          │
│ External Port: 8443                      │
│ Internal IP:   192.168.1.100             │
│ Internal Port: 8443                      │
│ Protocol:      TCP                       │
│ Enabled:       ☑                         │
└──────────────────────────────────────────┘
```

---

## 🔍 Step 5: Find Your Public IP Address

### Method 1: On Raspberry Pi
```bash
curl ifconfig.me
# or
curl icanhazip.com
# or
wget -qO- ifconfig.me
```

### Method 2: On any device
Visit: https://whatismyipaddress.com/

**Example:** `203.0.113.45`

---

## 🧪 Step 6: Test Local Network Access

### From another device on same network:
```bash
# Test from computer/phone on same WiFi
curl -k https://192.168.1.100:8443

# Upload test file
curl -k -X POST -F "file=@test.txt" https://192.168.1.100:8443/upload
```

**Expected:** HTML response or "Upload successful!"

---

## 🌍 Step 7: Test Public Internet Access

### From external network (use mobile data or ask friend):
```bash
# Replace with YOUR public IP
curl -k https://203.0.113.45:8443

# Upload test
curl -k -X POST -F "file=@test.txt" https://203.0.113.45:8443/upload
```

### Using browser:
Open: `https://YOUR_PUBLIC_IP:8443`

**Note:** You'll see certificate warning (expected with self-signed cert)

---

## 🔐 Step 8: Setup Dynamic DNS (Optional but Recommended)

### Why?
Most home internet has dynamic IPs that change periodically.

### Popular Services:
- **DuckDNS** (Free): https://www.duckdns.org/
- **No-IP** (Free): https://www.noip.com/
- **Dynu** (Free): https://www.dynu.com/

### Example: DuckDNS Setup

1. **Register at DuckDNS**
   - Get subdomain: `myiotgateway.duckdns.org`
   - Get token: `12345678-1234-1234-1234-123456789012`

2. **Install DuckDNS client on Pi:**
```bash
mkdir ~/duckdns
cd ~/duckdns
echo 'echo url="https://www.duckdns.org/update?domains=myiotgateway&token=YOUR_TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -' > duck.sh
chmod 700 duck.sh
```

3. **Add to cron (updates every 5 minutes):**
```bash
crontab -e
# Add line:
*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1
```

4. **Access via domain:**
```
https://myiotgateway.duckdns.org:8443
```

---

## 🔒 Step 9: Get Valid SSL Certificate (Recommended)

### Why?
Self-signed certificates show browser warnings. Let's Encrypt provides free valid certificates.

### Using Certbot:
```bash
sudo apt install certbot

# Get certificate (requires domain name from step 8)
sudo certbot certonly --standalone -d myiotgateway.duckdns.org

# Certificates will be in:
# /etc/letsencrypt/live/myiotgateway.duckdns.org/fullchain.pem
# /etc/letsencrypt/live/myiotgateway.duckdns.org/privkey.pem
```

### Update your application:
Modify `/etc/https-server/` to use Let's Encrypt certs or create symlinks:
```bash
sudo ln -sf /etc/letsencrypt/live/myiotgateway.duckdns.org/fullchain.pem /etc/https-server/server.crt
sudo ln -sf /etc/letsencrypt/live/myiotgateway.duckdns.org/privkey.pem /etc/https-server/server.key
```

### Auto-renewal:
```bash
sudo certbot renew --dry-run
# Add to cron:
0 0 * * * certbot renew --quiet && systemctl restart iot-gateway
```

---

## 🛡️ Step 10: Security Hardening

### A. Enable Firewall
```bash
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8443/tcp  # HTTPS
sudo ufw enable
```

### B. Add Authentication
Consider adding:
- Basic HTTP authentication
- API key validation
- IP whitelisting for critical operations

### C. Rate Limiting
Implement rate limiting to prevent abuse:
- Max uploads per IP per hour
- Connection throttling

### D. Monitoring
```bash
# Monitor server logs
journalctl -u iot-gateway -f

# Monitor connections
sudo netstat -tunap | grep 8443
```

---

## 🧪 Testing Checklist

- [ ] Server starts and shows local IP
- [ ] Local access works (`https://192.168.1.100:8443`)
- [ ] Port forwarding configured on router
- [ ] Public IP access works (`https://YOUR_PUBLIC_IP:8443`)
- [ ] Dynamic DNS setup (optional)
- [ ] Valid SSL certificate (optional)
- [ ] Firewall configured
- [ ] Upload functionality tested
- [ ] LED blink still working

---

## 🔧 Troubleshooting

### Can't access from public internet:

1. **Check port forwarding:**
   ```bash
   # Test if port is open (from external network)
   telnet YOUR_PUBLIC_IP 8443
   ```

2. **Check router firewall:**
   - Some routers have separate firewall rules
   - Ensure incoming traffic on 8443 is allowed

3. **ISP blocking:**
   - Some ISPs block common ports
   - Try different port (e.g., 8444)

4. **CGNAT (Carrier-Grade NAT):**
   - Some ISPs use CGNAT (no direct public IP)
   - Contact ISP or use VPN/tunnel service

### Certificate errors:

- Self-signed certs will always show warnings
- Use Let's Encrypt for valid certificates
- Or use `-k` flag with curl to skip verification

---

## 📊 Current Implementation Status

| Step | Status | Notes |
|------|--------|-------|
| 1. Server binds to 0.0.0.0 | ✅ Done | In code |
| 2. Local IP detection | ✅ Done | In code |
| 3. Static IP setup | ⏳ Manual | On Raspberry Pi |
| 4. Port forwarding | ⏳ Manual | On router |
| 5. Public IP | ℹ️ Info | ISP provided |
| 6. Local testing | ⏳ Test | After deployment |
| 7. Public testing | ⏳ Test | After port forwarding |
| 8. Dynamic DNS | 🔄 Optional | For changing IPs |
| 9. Valid SSL cert | 🔄 Optional | For production |
| 10. Security hardening | 🔄 Recommended | For production |

---

## 🎯 Quick Start Commands

### On Raspberry Pi:
```bash
# Find your local IP
hostname -I

# Find your public IP
curl ifconfig.me

# Check if server is listening
sudo netstat -tlnp | grep 8443

# Test locally
curl -k https://localhost:8443
```

### From external network:
```bash
# Test public access (replace with your public IP)
curl -k https://YOUR_PUBLIC_IP:8443
```

---

## 📞 Support & Resources

- **Router Port Forwarding Guides:** https://portforward.com/
- **DuckDNS:** https://www.duckdns.org/
- **Let's Encrypt:** https://letsencrypt.org/
- **UFW Firewall:** https://help.ubuntu.com/community/UFW

---

## ⚠️ Important Security Warnings

1. **Exposing IoT devices to internet has risks**
2. **Always use strong authentication**
3. **Keep system updated**: `sudo apt update && sudo apt upgrade`
4. **Monitor access logs regularly**
5. **Use VPN for sensitive operations**
6. **Consider using reverse proxy (Nginx/Caddy) for additional security**

---

**Next Recommended Steps:**
1. Set static IP on Raspberry Pi
2. Configure port forwarding on router
3. Test public access
4. Setup Dynamic DNS if needed
5. Get valid SSL certificate
6. Implement security hardening
