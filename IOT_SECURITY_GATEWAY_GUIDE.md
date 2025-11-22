# IoT Security Gateway - Implementation Guide

## Project Overview

This document provides a comprehensive step-by-step guide to implement an IoT Security Gateway using Raspberry Pi 3 Model B with Yocto/OpenEmbedded framework.

### Project Objectives
- Create a secure gateway for IoT devices using RPi3
- Implement protocol translation, traffic filtering, and device authentication
- Build custom firewall rules and VPN capabilities
- Monitor and secure communication between IoT devices and cloud services

### System Architecture

```
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│   IoT Devices   │───▶│  IoT Security       │───▶│  Cloud Services │
│ (MQTT, CoAP,    │    │  Gateway (RPi3)     │    │ (AWS, Azure,    │
│  HTTP, etc.)    │    │                     │    │  Google Cloud)  │
└─────────────────┘    └─────────────────────┘    └─────────────────┘
                              │
                              │
                       ┌─────────────┐
                       │ Management  │
                       │ Dashboard   │
                       └─────────────┘
```

## Table of Contents

1. [Hardware Requirements](#hardware-requirements)
2. [Software Requirements](#software-requirements)
3. [System Architecture Design](#system-architecture-design)
4. [Development Environment Setup](#development-environment-setup)
5. [Core Components Implementation](#core-components-implementation)
6. [Security Features Implementation](#security-features-implementation)
7. [Testing and Validation](#testing-and-validation)
8. [Deployment and Monitoring](#deployment-and-monitoring)
9. [Troubleshooting](#troubleshooting)

---

## 1. Hardware Requirements

### Primary Hardware
- **Raspberry Pi 3 Model B** (1GB RAM, ARM Cortex-A53 quad-core)
- **MicroSD Card** (32GB Class 10 or higher)
- **Power Supply** (5V, 2.5A micro-USB)
- **Ethernet Cable** (for initial setup)

### Optional Hardware
- **USB Wi-Fi Adapter** (for dual-network setup)
- **USB-to-Serial Adapter** (for debugging)
- **Case with cooling** (for continuous operation)
- **External USB Storage** (for logs and data)

### Specifications Verification
```bash
# Check RPi3 specifications
cat /proc/cpuinfo
cat /proc/meminfo
lscpu
```

---

## 2. Software Requirements

### Base Operating System
- **Yocto Linux** (Kirkstone or newer)
- **Custom meta-blink layer** (for IoT gateway recipes)

### Core Software Components
- **Linux Kernel** 5.15+ with networking and security modules
- **OpenSSL** 3.0+ for cryptographic operations
- **iptables/netfilter** for firewall functionality
- **OpenVPN** or **WireGuard** for VPN capabilities
- **Node.js** or **Python** for application layer
- **SQLite** for local data storage
- **Mosquitto MQTT Broker** for IoT protocol support

### Development Tools
- **Yocto Project** build system
- **BitBake** for recipe management
- **Git** for version control
- **Docker** (optional, for containerized services)

---

## 3. System Architecture Design

### 3.1 Network Architecture

```
Internet ←→ [WAN Interface] ← RPi3 Gateway → [LAN Interface] ←→ IoT Devices
                                   ↓
                            [Management Interface]
                                   ↓
                            [Admin Dashboard]
```

### 3.2 Software Architecture

#### Layer 1: Hardware Abstraction Layer (HAL)
- GPIO control for status indicators
- Network interface management
- Hardware security module integration

#### Layer 2: Network Layer
- **Traffic Filtering Engine**
  - Deep packet inspection
  - Protocol validation
  - Rate limiting

- **Protocol Translation Service**
  - MQTT ↔ HTTP/HTTPS
  - CoAP ↔ HTTP/HTTPS
  - Custom protocol adapters

#### Layer 3: Security Layer
- **Authentication Service**
  - Device certificate validation
  - Token-based authentication
  - Multi-factor authentication support

- **Encryption Service**
  - End-to-end encryption
  - Key management
  - Certificate authority integration

#### Layer 4: Application Layer
- **Gateway Management API**
- **Device Management Service**
- **Monitoring and Logging Service**
- **Configuration Management**

### 3.3 Data Flow Architecture

```
IoT Device → Authentication → Protocol Translation → Security Filtering → Cloud Service
     ↓              ↓                ↓                     ↓              ↓
   Logging    Access Control    Format Conversion    Threat Detection   Response
```

---

## 4. Development Environment Setup

### 4.1 Yocto Environment Preparation

```bash
# Navigate to your existing Yocto environment
cd /home/pg3930/capstone1/raspberrypi3/poky

# Source the build environment
source oe-init-build-env build

# Add meta-blink layer if not already added
bitbake-layers add-layer ../build/meta-blink
```

### 4.2 Configure Build for IoT Gateway

Create custom configuration files:

#### 4.2.1 Local Configuration
```bash
# Edit build/conf/local.conf
MACHINE = "raspberrypi3"
DISTRO = "poky"

# Add IoT gateway specific features
DISTRO_FEATURES:append = " wifi bluetooth"
IMAGE_FEATURES:append = " ssh-server-openssh"

# Security hardening
EXTRA_IMAGE_FEATURES:append = " read-only-rootfs"

# Add custom packages
IMAGE_INSTALL:append = " \
    iot-security-gateway \
    mosquitto \
    openvpn \
    iptables \
    python3 \
    python3-pip \
    nodejs \
    sqlite3 \
    openssl \
    curl \
    wget \
    nano \
    htop \
"
```

### 4.3 Create Custom Image Recipe

```bash
# Create recipes-core/images directory in meta-blink
mkdir -p /home/pg3930/capstone1/raspberrypi3/poky/build/meta-blink/recipes-core/images
```

---

## 5. Core Components Implementation

### 5.1 Gateway Core Service Architecture

The gateway consists of several microservices:

1. **Device Authentication Service**
2. **Protocol Translation Service** 
3. **Traffic Filtering Service**
4. **VPN Service**
5. **Monitoring Service**
6. **Management API Service**

### 5.2 Implementation Technologies

#### Primary Language: Python 3.9+
- **Advantages**: Rich ecosystem, rapid development, excellent networking libraries
- **Key Libraries**: 
  - `asyncio` for concurrent operations
  - `cryptography` for security operations
  - `paho-mqtt` for MQTT protocol
  - `flask` or `fastapi` for REST API
  - `sqlalchemy` for database operations

#### Alternative: Node.js
- **Advantages**: Event-driven, excellent for IoT protocols
- **Key Libraries**:
  - `express.js` for API server
  - `mqtt.js` for MQTT operations
  - `socket.io` for real-time communication

### 5.3 Database Design

#### Device Registry Table
```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id VARCHAR(64) UNIQUE NOT NULL,
    device_name VARCHAR(128),
    device_type VARCHAR(32),
    mac_address VARCHAR(18),
    ip_address VARCHAR(15),
    certificate_fingerprint VARCHAR(128),
    status VARCHAR(16) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    security_level INTEGER DEFAULT 1
);
```

#### Traffic Logs Table
```sql
CREATE TABLE traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id VARCHAR(64),
    source_ip VARCHAR(15),
    destination_ip VARCHAR(15),
    protocol VARCHAR(16),
    port INTEGER,
    bytes_transferred INTEGER,
    threat_level INTEGER DEFAULT 0,
    action VARCHAR(16),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 6. Security Features Implementation

### 6.1 Device Authentication

#### Certificate-Based Authentication
```python
# Device certificate validation
def validate_device_certificate(cert_data):
    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Verify certificate chain
        if not verify_certificate_chain(cert):
            return False
            
        # Check certificate validity
        now = datetime.utcnow()
        if cert.not_valid_after < now or cert.not_valid_before > now:
            return False
            
        # Extract device ID from certificate
        device_id = extract_device_id_from_cert(cert)
        
        # Register or update device
        register_device(device_id, cert)
        
        return True
    except Exception as e:
        log_security_event("cert_validation_failed", str(e))
        return False
```

### 6.2 Traffic Filtering Rules

#### Firewall Rule Engine
```python
class FirewallRuleEngine:
    def __init__(self):
        self.rules = []
        self.load_rules_from_config()
    
    def add_rule(self, rule):
        """Add new firewall rule"""
        self.rules.append(rule)
        self.apply_iptables_rule(rule)
    
    def evaluate_packet(self, packet_info):
        """Evaluate packet against all rules"""
        for rule in self.rules:
            if rule.matches(packet_info):
                return rule.action
        return "ALLOW"  # Default allow
    
    def apply_iptables_rule(self, rule):
        """Apply rule to iptables"""
        cmd = f"iptables {rule.to_iptables_format()}"
        subprocess.run(cmd.split(), check=True)
```

### 6.3 Protocol Translation

#### MQTT to HTTP/HTTPS Translation
```python
class ProtocolTranslator:
    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.http_session = requests.Session()
        self.setup_mqtt_handlers()
    
    def setup_mqtt_handlers(self):
        self.mqtt_client.on_message = self.on_mqtt_message
        self.mqtt_client.on_connect = self.on_mqtt_connect
    
    def on_mqtt_message(self, client, userdata, message):
        """Translate MQTT message to HTTP request"""
        try:
            # Parse MQTT topic and payload
            topic_parts = message.topic.split('/')
            device_id = topic_parts[1]
            data_type = topic_parts[2]
            
            # Validate device authentication
            if not self.is_device_authenticated(device_id):
                self.log_security_violation(device_id, "unauthenticated_mqtt")
                return
            
            # Convert to HTTP request
            http_payload = {
                'device_id': device_id,
                'data_type': data_type,
                'payload': message.payload.decode(),
                'timestamp': time.time()
            }
            
            # Send to cloud service
            response = self.http_session.post(
                f"{CLOUD_ENDPOINT}/devices/{device_id}/data",
                json=http_payload,
                headers={'Authorization': f'Bearer {self.get_cloud_token()}'}
            )
            
            # Log transaction
            self.log_transaction(device_id, 'mqtt_to_http', response.status_code)
            
        except Exception as e:
            self.log_error(f"Protocol translation failed: {str(e)}")
```

---

## 7. Implementation Steps

### Step 1: Create Yocto Recipes

#### 7.1 IoT Gateway Main Recipe

Create the main application recipe:

```bash
# Create recipe directory
mkdir -p /home/pg3930/capstone1/raspberrypi3/poky/build/meta-blink/recipes-apps/iot-security-gateway
```

#### 7.2 Recipe Files Structure
```
recipes-apps/iot-security-gateway/
├── iot-security-gateway_1.0.bb
├── files/
│   ├── iot-gateway.service
│   ├── iot-gateway.conf
│   ├── gateway-init.sh
│   └── src/
│       ├── main.py
│       ├── auth_service.py
│       ├── protocol_translator.py
│       ├── firewall_manager.py
│       ├── vpn_manager.py
│       └── monitoring_service.py
```

### Step 2: Network Configuration

#### 7.2.1 Network Interface Setup
```bash
# Configure network interfaces
# /etc/systemd/network/eth0.network
[Match]
Name=eth0

[Network]
DHCP=yes
IPForward=yes

# /etc/systemd/network/wlan0.network
[Match]
Name=wlan0

[Network]
Address=192.168.100.1/24
DHCPServer=yes

[DHCPServer]
PoolOffset=10
PoolSize=100
```

### Step 3: Security Configuration

#### 7.3.1 Certificate Management
```bash
# Create CA and device certificates
mkdir -p /etc/iot-gateway/certs
cd /etc/iot-gateway/certs

# Generate CA key and certificate
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Generate gateway certificate
openssl genrsa -out gateway-key.pem 4096
openssl req -subj "/CN=iot-gateway" -sha256 -new -key gateway-key.pem -out gateway.csr
openssl x509 -req -days 365 -sha256 -in gateway.csr -CA ca.pem -CAkey ca-key.pem -out gateway-cert.pem
```

#### 7.3.2 VPN Configuration
```bash
# OpenVPN server configuration
# /etc/openvpn/server.conf
port 1194
proto udp
dev tun
ca /etc/iot-gateway/certs/ca.pem
cert /etc/iot-gateway/certs/gateway-cert.pem
key /etc/iot-gateway/certs/gateway-key.pem
dh /etc/iot-gateway/certs/dh.pem
server 10.8.0.0 255.255.255.0
push "route 192.168.100.0 255.255.255.0"
client-to-client
keepalive 10 120
comp-lzo
user nobody
group nobody
persist-key
persist-tun
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
```

### Step 4: Service Implementation

#### 7.4.1 Main Gateway Service
```python
#!/usr/bin/env python3
"""
IoT Security Gateway - Main Service
"""
import asyncio
import logging
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

from auth_service import AuthenticationService
from protocol_translator import ProtocolTranslator
from firewall_manager import FirewallManager
from vpn_manager import VPNManager
from monitoring_service import MonitoringService

class IoTSecurityGateway:
    def __init__(self):
        self.setup_logging()
        self.running = False
        
        # Initialize services
        self.auth_service = AuthenticationService()
        self.protocol_translator = ProtocolTranslator()
        self.firewall_manager = FirewallManager()
        self.vpn_manager = VPNManager()
        self.monitoring_service = MonitoringService()
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/iot-gateway.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def start_services(self):
        """Start all gateway services"""
        try:
            self.logger.info("Starting IoT Security Gateway...")
            
            # Start services concurrently
            tasks = [
                self.auth_service.start(),
                self.protocol_translator.start(),
                self.firewall_manager.start(),
                self.vpn_manager.start(),
                self.monitoring_service.start()
            ]
            
            await asyncio.gather(*tasks)
            self.running = True
            self.logger.info("All services started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start services: {str(e)}")
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Shutting down IoT Security Gateway...")
        self.running = False
        
        # Stop all services
        await asyncio.gather(
            self.auth_service.stop(),
            self.protocol_translator.stop(),
            self.firewall_manager.stop(),
            self.vpn_manager.stop(),
            self.monitoring_service.stop(),
            return_exceptions=True
        )
        
        self.logger.info("Gateway shutdown complete")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(self.shutdown())
    
    async def run(self):
        """Main run loop"""
        await self.start_services()
        
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            await self.shutdown()

if __name__ == "__main__":
    gateway = IoTSecurityGateway()
    asyncio.run(gateway.run())
```

---

## 8. Testing and Validation

### 8.1 Unit Testing Framework

```python
import unittest
import asyncio
from unittest.mock import Mock, patch

class TestAuthenticationService(unittest.TestCase):
    def setUp(self):
        self.auth_service = AuthenticationService()
    
    def test_certificate_validation(self):
        # Test valid certificate
        valid_cert = self.load_test_certificate("valid_cert.pem")
        self.assertTrue(self.auth_service.validate_certificate(valid_cert))
        
        # Test expired certificate
        expired_cert = self.load_test_certificate("expired_cert.pem")
        self.assertFalse(self.auth_service.validate_certificate(expired_cert))
    
    def test_device_registration(self):
        device_id = "test-device-001"
        result = self.auth_service.register_device(device_id, {})
        self.assertTrue(result)

class TestProtocolTranslator(unittest.TestCase):
    def setUp(self):
        self.translator = ProtocolTranslator()
    
    @patch('requests.Session.post')
    def test_mqtt_to_http_translation(self, mock_post):
        mock_post.return_value.status_code = 200
        
        # Simulate MQTT message
        message = Mock()
        message.topic = "devices/sensor001/temperature"
        message.payload = b'{"value": 23.5}'
        
        result = self.translator.translate_mqtt_message(message)
        self.assertTrue(result)
        mock_post.assert_called_once()
```

### 8.2 Integration Testing

```bash
#!/bin/bash
# integration_test.sh

echo "Starting IoT Gateway Integration Tests..."

# Test 1: Service Startup
echo "Test 1: Service startup test"
systemctl start iot-gateway
sleep 5
if systemctl is-active --quiet iot-gateway; then
    echo "✓ Gateway service started successfully"
else
    echo "✗ Gateway service failed to start"
    exit 1
fi

# Test 2: Network Interface Configuration
echo "Test 2: Network interface test"
if ip addr show wlan0 | grep -q "192.168.100.1"; then
    echo "✓ WiFi interface configured correctly"
else
    echo "✗ WiFi interface configuration failed"
fi

# Test 3: MQTT Broker Connectivity
echo "Test 3: MQTT broker test"
timeout 5 mosquitto_pub -h localhost -t "test/topic" -m "test message"
if [ $? -eq 0 ]; then
    echo "✓ MQTT broker is accessible"
else
    echo "✗ MQTT broker connection failed"
fi

# Test 4: VPN Service
echo "Test 4: VPN service test"
if systemctl is-active --quiet openvpn@server; then
    echo "✓ VPN service is running"
else
    echo "✗ VPN service is not running"
fi

# Test 5: Firewall Rules
echo "Test 5: Firewall rules test"
if iptables -L | grep -q "IOT-GATEWAY"; then
    echo "✓ Firewall rules are applied"
else
    echo "✗ Firewall rules not found"
fi

echo "Integration tests completed"
```

### 8.3 Security Testing

```python
#!/usr/bin/env python3
"""Security testing framework"""

import socket
import ssl
import time
import threading
from scapy.all import *

class SecurityTester:
    def __init__(self, gateway_ip="192.168.100.1"):
        self.gateway_ip = gateway_ip
        self.results = []
    
    def test_port_scanning_detection(self):
        """Test if gateway detects port scanning"""
        print("Testing port scanning detection...")
        
        # Perform rapid port scan
        ports = range(20, 100)
        start_time = time.time()
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((self.gateway_ip, port))
                sock.close()
            except:
                pass
        
        # Check if scan was logged/blocked
        # This would check gateway logs for scan detection
        return self.check_security_logs("port_scan_detected")
    
    def test_certificate_validation(self):
        """Test certificate-based authentication"""
        print("Testing certificate validation...")
        
        # Test with invalid certificate
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.gateway_ip, 8883)) as sock:
                with context.wrap_socket(sock, server_hostname=self.gateway_ip) as ssock:
                    ssock.send(b"invalid auth attempt")
                    
        except Exception as e:
            # Expected to fail with invalid cert
            return True
        
        return False
    
    def test_ddos_protection(self):
        """Test DDoS protection mechanisms"""
        print("Testing DDoS protection...")
        
        # Send high volume of requests
        def send_requests():
            for _ in range(1000):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((self.gateway_ip, 80))
                    sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                    sock.close()
                except:
                    pass
        
        # Launch multiple threads
        threads = []
        for _ in range(10):
            t = threading.Thread(target=send_requests)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Check if rate limiting was applied
        return self.check_security_logs("rate_limit_applied")
    
    def check_security_logs(self, event_type):
        """Check security logs for specific events"""
        try:
            with open('/var/log/iot-gateway-security.log', 'r') as f:
                logs = f.read()
                return event_type in logs
        except:
            return False
    
    def run_all_tests(self):
        """Run complete security test suite"""
        tests = [
            ("Port Scan Detection", self.test_port_scanning_detection),
            ("Certificate Validation", self.test_certificate_validation),
            ("DDoS Protection", self.test_ddos_protection)
        ]
        
        results = {}
        for test_name, test_func in tests:
            print(f"\n--- {test_name} ---")
            try:
                result = test_func()
                results[test_name] = "PASS" if result else "FAIL"
                print(f"Result: {results[test_name]}")
            except Exception as e:
                results[test_name] = f"ERROR: {str(e)}"
                print(f"Result: {results[test_name]}")
        
        return results

if __name__ == "__main__":
    tester = SecurityTester()
    results = tester.run_all_tests()
    
    print("\n=== Security Test Results ===")
    for test, result in results.items():
        print(f"{test}: {result}")
```

---

## 9. Performance Monitoring and Optimization

### 9.1 Resource Monitoring

```python
#!/usr/bin/env python3
"""Performance monitoring service"""

import psutil
import time
import json
import sqlite3
from datetime import datetime

class PerformanceMonitor:
    def __init__(self, db_path="/var/lib/iot-gateway/performance.db"):
        self.db_path = db_path
        self.setup_database()
    
    def setup_database(self):
        """Initialize performance monitoring database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL,
                network_bytes_sent INTEGER,
                network_bytes_recv INTEGER,
                temperature REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_metrics (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                service_name TEXT,
                cpu_percent REAL,
                memory_mb REAL,
                connections INTEGER,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_system_metrics(self):
        """Collect system-level performance metrics"""
        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_usage = disk.percent
        
        # Network statistics
        net_io = psutil.net_io_counters()
        
        # CPU temperature (RPi specific)
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                temp = float(f.read()) / 1000.0
        except:
            temp = 0.0
        
        return {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'network_bytes_sent': net_io.bytes_sent,
            'network_bytes_recv': net_io.bytes_recv,
            'temperature': temp
        }
    
    def collect_service_metrics(self):
        """Collect service-specific metrics"""
        services = ['iot-gateway', 'mosquitto', 'openvpn']
        metrics = []
        
        for service_name in services:
            try:
                # Find process by name
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                    if service_name in proc.info['name']:
                        metrics.append({
                            'service_name': service_name,
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_mb': proc.info['memory_info'].rss / 1024 / 1024,
                            'connections': len(proc.connections()),
                            'status': 'running'
                        })
                        break
                else:
                    # Service not found
                    metrics.append({
                        'service_name': service_name,
                        'cpu_percent': 0,
                        'memory_mb': 0,
                        'connections': 0,
                        'status': 'stopped'
                    })
            except Exception as e:
                print(f"Error collecting metrics for {service_name}: {e}")
        
        return metrics
    
    def store_metrics(self, system_metrics, service_metrics):
        """Store metrics in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store system metrics
        cursor.execute('''
            INSERT INTO system_metrics 
            (cpu_usage, memory_usage, disk_usage, network_bytes_sent, network_bytes_recv, temperature)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            system_metrics['cpu_usage'],
            system_metrics['memory_usage'],
            system_metrics['disk_usage'],
            system_metrics['network_bytes_sent'],
            system_metrics['network_bytes_recv'],
            system_metrics['temperature']
        ))
        
        # Store service metrics
        for metric in service_metrics:
            cursor.execute('''
                INSERT INTO service_metrics
                (service_name, cpu_percent, memory_mb, connections, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                metric['service_name'],
                metric['cpu_percent'],
                metric['memory_mb'],
                metric['connections'],
                metric['status']
            ))
        
        conn.commit()
        conn.close()
    
    def monitor_loop(self, interval=60):
        """Main monitoring loop"""
        print(f"Starting performance monitoring (interval: {interval}s)")
        
        while True:
            try:
                system_metrics = self.collect_system_metrics()
                service_metrics = self.collect_service_metrics()
                
                self.store_metrics(system_metrics, service_metrics)
                
                # Print current status
                print(f"[{datetime.now()}] CPU: {system_metrics['cpu_usage']:.1f}% "
                      f"Mem: {system_metrics['memory_usage']:.1f}% "
                      f"Temp: {system_metrics['temperature']:.1f}°C")
                
                # Check for alerts
                self.check_alerts(system_metrics, service_metrics)
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("Monitoring stopped")
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(interval)
    
    def check_alerts(self, system_metrics, service_metrics):
        """Check for performance alerts"""
        alerts = []
        
        # CPU usage alert
        if system_metrics['cpu_usage'] > 80:
            alerts.append(f"High CPU usage: {system_metrics['cpu_usage']:.1f}%")
        
        # Memory usage alert
        if system_metrics['memory_usage'] > 85:
            alerts.append(f"High memory usage: {system_metrics['memory_usage']:.1f}%")
        
        # Temperature alert
        if system_metrics['temperature'] > 70:
            alerts.append(f"High CPU temperature: {system_metrics['temperature']:.1f}°C")
        
        # Service status alerts
        for metric in service_metrics:
            if metric['status'] != 'running':
                alerts.append(f"Service {metric['service_name']} is {metric['status']}")
        
        # Log alerts
        if alerts:
            with open('/var/log/iot-gateway-alerts.log', 'a') as f:
                for alert in alerts:
                    f.write(f"[{datetime.now()}] ALERT: {alert}\n")
                    print(f"ALERT: {alert}")

if __name__ == "__main__":
    monitor = PerformanceMonitor()
    monitor.monitor_loop()
```

---

## 10. Deployment Guide

### 10.1 Build Process

<function_calls>
<invoke name="manage_todo_list">
<parameter name="todoList">[{"title": "Analyze current workspace and setup", "id": 1, "status": "completed"}, {"title": "Create project documentation structure", "id": 2, "status": "completed"}, {"title": "Design system architecture", "id": 3, "status": "in-progress"}, {"title": "Setup development environment", "id": 4, "status": "not-started"}, {"title": "Implement core gateway components", "id": 5, "status": "not-started"}, {"title": "Create configuration files", "id": 6, "status": "not-started"}]