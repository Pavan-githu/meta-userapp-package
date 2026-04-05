SUMMARY = "Static Ethernet network configuration for eth0"
DESCRIPTION = "Configures eth0 with a static IP using systemd-networkd"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
PR = "r2"

SRC_URI = "file://10-eth0-static.network"

S = "${WORKDIR}"

inherit systemd

# systemd-networkd is bundled in the main systemd package (FILES:${PN} includes ${systemd_unitdir}/*)
# Enabling it is handled via SYSTEMD_SERVICE below; no separate RDEPENDS needed.
SYSTEMD_SERVICE:${PN} = "systemd-networkd.service systemd-networkd.socket"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_install() {
    bbwarn "network-config: do_install is RUNNING - not from sstate"
    # Install systemd-networkd config file
    install -d ${D}${sysconfdir}/systemd/network
    install -m 0644 ${WORKDIR}/10-eth0-static.network ${D}${sysconfdir}/systemd/network/
}

FILES:${PN} += " \
    ${sysconfdir}/systemd/network/10-eth0-static.network \
"
