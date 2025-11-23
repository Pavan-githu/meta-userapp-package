# IoT Gateway Application

A unified C++ application combining LED control and HTTPS firmware upload server for Raspberry Pi IoT gateway.

## Features

- **LED Blink Control**: Controls GPIO pin 17 to blink an LED
- **HTTPS Firmware Server**: Secure firmware upload server on port 8443
- **Multi-threaded**: Both services run simultaneously
- **Graceful Shutdown**: Proper cleanup on Ctrl+C

## Architecture

The application consists of three main components:

### 1. GPIO/LED Control (`blink.h`, `blink.cpp`)
- Controls Raspberry Pi GPIO via sysfs interface
- Manages LED blinking on GPIO pin 17
- Runs in separate thread

### 2. HTTPS Server (`https_server.h`, `https_server.cpp`)
- Secure HTTPS server using libmicrohttpd and GnuTLS
- Accepts firmware uploads via POST to `/upload` endpoint
- Dynamically allocates memory for uploaded data
- Web interface for file uploads at root URL

### 3. Main Program (`main.h`, `main.cpp`)
- Orchestrates both services
- Manages threads and signal handling
- Provides unified startup and shutdown

## Building with Yocto/BitBake

This is a Yocto meta-layer. Add to your `bblayers.conf`:

```
BBLAYERS += "/path/to/meta-userapp-package"
```

Add to your `local.conf` or image recipe:

```
IMAGE_INSTALL:append = " iot-gateway-apps"
```

Build your image:

```bash
bitbake core-image-minimal
```

## Dependencies

- libmicrohttpd
- gnutls
- openssl (for certificate generation)

## Running the Application

On the target device:

```bash
# Generate SSL certificates (first time only)
cd /etc/https-server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# Run the application
iot-gateway
```

The application will:
- Start blinking LED on GPIO 17
- Start HTTPS server on port 8443

## Usage

### LED Blink
LED automatically blinks with 1-second intervals on GPIO 17.

### Upload Firmware

Using curl:
```bash
curl -k -X POST -F "file=@firmware.bin" https://<device-ip>:8443/upload
```

Using web browser:
```
https://<device-ip>:8443
```
(Accept the self-signed certificate warning)

### Stop the Application
Press `Ctrl+C` for graceful shutdown.

## File Structure

```
meta-userapp-package/
├── conf/
│   └── layer.conf
├── recipes-apps/
│   ├── iot-gateway-apps_0.1.bb    # BitBake recipe
│   └── iot-gateway/
│       └── files/
│           ├── main.h              # Main program header
│           ├── main.cpp            # Main program
│           ├── blink.h             # GPIO/LED header
│           ├── blink.cpp           # GPIO/LED implementation
│           ├── https_server.h      # HTTPS server header
│           └── https_server.cpp    # HTTPS server implementation
├── COPYING.MIT
└── README.md
```

## Security Notes

- Default certificates are self-signed (for testing only)
- For production, use proper CA-signed certificates
- Consider adding authentication to the upload endpoint
- Run with appropriate user permissions for GPIO access

## GPIO Permissions

Ensure the user has GPIO access:
```bash
sudo usermod -a -G gpio <username>
```

Or run with sudo:
```bash
sudo iot-gateway
```

## License

MIT License - See COPYING.MIT file

## Author

Created for Raspberry Pi IoT Gateway project
