SUMMARY = "RAUC update bundle for IoT gateway A/B OTA"
LICENSE = "MIT"

inherit bundle

RAUC_BUNDLE_COMPATIBLE = "${MACHINE}"
RAUC_BUNDLE_VERSION    = "${PV}"
RAUC_BUNDLE_FORMAT     = "verity"

RAUC_BUNDLE_SLOTS = "rootfs"
RAUC_SLOT_rootfs          = "core-image-minimal"
RAUC_SLOT_rootfs[fstype]  = "ext4"

RAUC_KEY_FILE  = "${TOPDIR}/../keys/rauc-private.pem"
RAUC_CERT_FILE = "${TOPDIR}/../keys/rauc-cert.pem"