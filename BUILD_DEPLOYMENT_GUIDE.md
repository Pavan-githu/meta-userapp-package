# IoT Security Gateway - Build and Deployment Guide

## Build Instructions

### 1. Update Local Configuration

Edit your `build/conf/local.conf` file to include the IoT Security Gateway:

```bash
# Add to your local.conf
IMAGE_INSTALL:append = " iot-security-gateway"

# Optional: Add development tools
EXTRA_IMAGE_FEATURES:append = " tools-debug tools-sdk dev-pkgs"

# Security features
DISTRO_FEATURES:append = " pam systemd"
```

### 2. Add Layer to Build

```bash
cd /home/pg3930/capstone1/raspberrypi3/poky
source oe-init-build-env build

# Add meta-blink layer if not already added
bitbake-layers add-layer ../build/meta-blink

# Verify layer is added
bitbake-layers show-layers
```

### 3. Build the Image

```bash
# Build for Raspberry Pi 3
MACHINE=raspberrypi3 bitbake core-image-minimal

# Or build with more features
MACHINE=raspberrypi3 bitbake core-image-base
```

## Deployment Steps

### 1. Flash Image to SD Card

```bash
# After successful build
cd tmp/deploy/images/raspberrypi3/

# Flash to SD card (replace /dev/sdX with your SD card device)
sudo dd if=core-image-minimal-raspberrypi3.wic of=/dev/sdX bs=4M status=progress
sync
```

### 2. First Boot Setup

1. Insert SD card into Raspberry Pi 3
2. Connect Ethernet cable
3. Power on the device
4. SSH into the device (default user: root, no password)

```bash
# Find the device IP
nmap -sn 192.168.1.0/24

# SSH to the device
ssh root@<device-ip>
```

### 3. Initialize Gateway

```bash
# Run the initialization script
gateway-init

# This will:
# - Create necessary directories
# - Generate SSL certificates
# - Configure networking
# - Set up services
```

### 4. Configure the Gateway

```bash
# Edit main configuration
nano /opt/iot-gateway/config/iot-gateway.conf

# Important: Change default passwords and secrets!
# Update network interface names if needed
# Configure cloud endpoints if required
```

### 5. Start Services

```bash
# Start the IoT Gateway
systemctl start iot-gateway

# Enable auto-start on boot
systemctl enable iot-gateway

# Check status
systemctl status iot-gateway

# View logs
journalctl -u iot-gateway -f
```

## Testing the Gateway

### 1. Verify Services

```bash
# Check all services
systemctl status iot-gateway
systemctl status mosquitto
systemctl status openvpn@server

# Check network configuration
ip addr show
iptables -L -n
```

### 2. Test MQTT Functionality

```bash
# Test local MQTT broker
mosquitto_pub -h localhost -t "test/topic" -m "Hello Gateway"
mosquitto_sub -h localhost -t "test/topic" &

# Test device authentication (after setting up certificates)
# This would require proper device certificates
```

### 3. Test VPN Access

```bash
# Check VPN server status
systemctl status openvpn@server

# View VPN logs
tail -f /var/log/openvpn.log

# Check VPN network interface
ip addr show tun0
```

### 4. Test Firewall Rules

```bash
# View current iptables rules
iptables -L -n -v

# Check custom chains
iptables -L IOT_GATEWAY_INPUT -n -v

# Test port scanning detection (from another machine)
# nmap -p 1-1000 <gateway-ip>
# Check logs: tail -f /var/log/iot-gateway.log
```

## Performance Optimization

### 1. System Tuning

```bash
# Optimize for IoT workload
echo 'vm.swappiness=1' >> /etc/sysctl.conf
echo 'net.core.rmem_max=16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max=16777216' >> /etc/sysctl.conf

# Apply changes
sysctl -p
```

### 2. Service Optimization

```bash
# Adjust service priorities
systemctl edit iot-gateway
```

Add the following:
```ini
[Service]
Nice=-5
IOSchedulingClass=1
IOSchedulingPriority=4
```

## Monitoring and Maintenance

### 1. Log Locations

```bash
# Gateway logs
tail -f /opt/iot-gateway/logs/gateway.log

# System logs
journalctl -u iot-gateway -f

# MQTT logs
tail -f /var/log/mosquitto/mosquitto.log

# VPN logs
tail -f /var/log/openvpn.log

# Security events
tail -f /var/log/iot-gateway-security.log
```

### 2. Database Maintenance

```bash
# Backup database
sqlite3 /var/lib/iot-gateway/gateway.db ".backup /tmp/gateway_backup.db"

# Check database size
ls -lh /var/lib/iot-gateway/gateway.db

# Vacuum database (optimize)
sqlite3 /var/lib/iot-gateway/gateway.db "VACUUM;"
```

### 3. Certificate Management

```bash
# Check certificate expiry
openssl x509 -in /opt/iot-gateway/certs/gateway-cert.pem -noout -dates

# Generate new client certificate
# (Would implement proper PKI management)
```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
```bash
# Check detailed logs
journalctl -u iot-gateway -n 50

# Check configuration syntax
python3 -c "import json; json.load(open('/opt/iot-gateway/config/iot-gateway.conf'))"

# Check permissions
ls -la /opt/iot-gateway/
```

2. **Network Issues**
```bash
# Check interfaces
ip addr show
ip route show

# Test connectivity
ping -c 3 8.8.8.8

# Check iptables rules
iptables -L -n | grep DROP
```

3. **Certificate Issues**
```bash
# Verify certificates
openssl x509 -in /opt/iot-gateway/certs/ca.pem -noout -text
openssl verify -CAfile /opt/iot-gateway/certs/ca.pem /opt/iot-gateway/certs/gateway-cert.pem

# Regenerate if needed
cd /opt/iot-gateway/certs
rm *.pem *.key
gateway-init --certificates-only
```

4. **Performance Issues**
```bash
# Check system resources
htop
iotop
nethogs

# Check database performance
sqlite3 /var/lib/iot-gateway/gateway.db "ANALYZE;"
```

## Security Hardening

### 1. System Security

```bash
# Disable unnecessary services
systemctl disable bluetooth
systemctl disable avahi-daemon

# Update packages regularly
opkg update && opkg upgrade

# Configure fail2ban (if available)
# Set up log monitoring
```

### 2. Network Security

```bash
# Disable unused network interfaces
# Configure proper firewall rules for your environment
# Set up network segmentation
# Enable logging for security events
```

### 3. Application Security

```bash
# Change default passwords in config
# Set up proper certificate validation
# Configure rate limiting appropriately
# Enable encryption for all communications
```

## Production Deployment Checklist

- [ ] Change all default passwords and secrets
- [ ] Configure proper SSL/TLS certificates
- [ ] Set up network segmentation
- [ ] Configure monitoring and alerting
- [ ] Set up log aggregation
- [ ] Configure backup procedures
- [ ] Test disaster recovery procedures
- [ ] Document network topology
- [ ] Configure access controls
- [ ] Set up regular security updates
- [ ] Perform security audit
- [ ] Test all IoT device integrations
- [ ] Configure cloud service connections
- [ ] Set up VPN client access
- [ ] Test failover scenarios

## API Documentation

The gateway provides REST APIs for management:

```bash
# Get system status
curl http://localhost:8080/api/v1/status

# Get device list
curl http://localhost:8080/api/v1/devices

# Get metrics
curl http://localhost:8080/api/v1/metrics

# Get alerts
curl http://localhost:8080/api/v1/alerts
```

Note: API implementation would be part of the management interface (future enhancement).

## Contributing

To extend the gateway functionality:

1. Add new recipes in `recipes-apps/` directory
2. Follow Yocto naming conventions
3. Update dependencies in BitBake recipes
4. Test thoroughly before deployment
5. Document all changes