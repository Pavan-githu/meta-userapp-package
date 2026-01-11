SUMMARY = "Simple HTTP client for downloading OTA updates"
DESCRIPTION = "Wrapper for curl to download firmware images"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

RDEPENDS:${PN} = "curl"

# This is a virtual package - curl provides the functionality
ALLOW_EMPTY:${PN} = "1"
