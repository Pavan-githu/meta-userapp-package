SUMMARY = "Static Ethernet network configuration for eth0"
DESCRIPTION = "Configures eth0 with a static IP using systemd-networkd"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
PR = "r1"

SRC_URI = "file://10-eth0-static.network"

S = "${WORKDIR}"

inherit systemd

do_install() {
    bbwarn "network-config: do_install is RUNNING - not from sstate"
    # Install systemd-networkd config file
    install -d ${D}${sysconfdir}/systemd/network
    install -m 0644 ${WORKDIR}/10-eth0-static.network ${D}${sysconfdir}/systemd/network/

    # Enable systemd-networkd service and socket at boot
    install -d ${D}${sysconfdir}/systemd/system/multi-user.target.wants
    install -d ${D}${sysconfdir}/systemd/system/sockets.target.wants
    ln -sf ${systemd_unitdir}/system/systemd-networkd.service \
        ${D}${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service
    ln -sf ${systemd_unitdir}/system/systemd-networkd.socket \
        ${D}${sysconfdir}/systemd/system/sockets.target.wants/systemd-networkd.socket
}

FILES:${PN} += " \
    ${sysconfdir}/systemd/network/10-eth0-static.network \
    ${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service \
    ${sysconfdir}/systemd/system/sockets.target.wants/systemd-networkd.socket \
"
