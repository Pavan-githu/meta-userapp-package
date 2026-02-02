#!/bin/bash
# Script to download firmware from GitHub and make it available via HTTPS server
# This can run on your Raspberry Pi to fetch latest firmware

GITHUB_REPO="Pavan-githu/meta-userapp-package"
FIRMWARE_DIR="/var/www/firmware"
HTTPS_UPLOAD_URL="https://localhost:8443/upload"

# Configuration
GITHUB_TOKEN="${GITHUB_TOKEN:-}"  # Optional: set for private repos
RELEASE_TAG="${1:-latest}"  # Use specific tag or 'latest'

echo "=== GitHub Firmware Sync ==="
echo "Repository: $GITHUB_REPO"
echo "Release: $RELEASE_TAG"
echo ""

# Create firmware directory if it doesn't exist
mkdir -p "$FIRMWARE_DIR"

# Get release information from GitHub
if [ "$RELEASE_TAG" = "latest" ]; then
    API_URL="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
else
    API_URL="https://api.github.com/repos/$GITHUB_REPO/releases/tags/$RELEASE_TAG"
fi

echo "Fetching release info..."
if [ -n "$GITHUB_TOKEN" ]; then
    RELEASE_INFO=$(curl -sH "Authorization: token $GITHUB_TOKEN" "$API_URL")
else
    RELEASE_INFO=$(curl -s "$API_URL")
fi

# Extract download URL for .wic.bz2 file
DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o '"browser_download_url": "[^"]*\.wic\.bz2"' | cut -d'"' -f4 | head -1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: No firmware file found in release"
    echo "Make sure you have uploaded .wic.bz2 file to GitHub release"
    exit 1
fi

FILENAME=$(basename "$DOWNLOAD_URL")
echo "Found firmware: $FILENAME"
echo "Download URL: $DOWNLOAD_URL"
echo ""

# Download firmware
echo "Downloading firmware..."
if [ -n "$GITHUB_TOKEN" ]; then
    curl -L -H "Authorization: token $GITHUB_TOKEN" \
         -o "$FIRMWARE_DIR/$FILENAME" \
         "$DOWNLOAD_URL"
else
    curl -L -o "$FIRMWARE_DIR/$FILENAME" "$DOWNLOAD_URL"
fi

if [ $? -eq 0 ]; then
    echo "✓ Firmware downloaded successfully to $FIRMWARE_DIR/$FILENAME"
    ls -lh "$FIRMWARE_DIR/$FILENAME"
    
    # Create symlink to latest
    ln -sf "$FILENAME" "$FIRMWARE_DIR/latest.wic.bz2"
    echo "✓ Created symlink: latest.wic.bz2 -> $FILENAME"
else
    echo "✗ Download failed"
    exit 1
fi

echo ""
echo "=== Firmware Ready ==="
echo "Local path: $FIRMWARE_DIR/$FILENAME"
echo ""
echo "To serve via HTTPS, clients can use:"
echo "  curl -k https://YOUR_RPI_IP:8443/firmware/$FILENAME -o firmware.wic.bz2"
