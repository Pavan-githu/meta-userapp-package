SUMMARY = "Custom image with dual root partitions for A/B updates"
DESCRIPTION = "Raspberry Pi image with redundant root filesystems for fail-safe OTA updates"

inherit core-image

# Use custom WKS file for dual root partition layout
WKS_FILE = "sdimage-raspberrypi-dual-rootfs.wks"

# Image features
IMAGE_FEATURES += "ssh-server-openssh"

# Install packages
IMAGE_INSTALL:append = " \
    iot-gateway-apps \
    rootfs-manager \
    curl \
    openssh \
    wpa-supplicant \
    iw \
    wireless-regdb \
"

# Remove conflicting package groups
IMAGE_INSTALL:remove = "packagegroup-base-extended"

# Fixed size for both rootfs partitions (2GB each)
# This ensures both partitions are identical size for swapping
IMAGE_ROOTFS_SIZE = "2097152"
IMAGE_ROOTFS_EXTRA_SPACE = "0"
