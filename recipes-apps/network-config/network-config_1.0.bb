SUMMARY = "Static Ethernet network configuration for eth0"
DESCRIPTION = "Configures eth0 with a static IP using systemd-networkd"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://10-eth0-static.network"

S = "${WORKDIR}"

inherit systemd

do_install() {
    # Install systemd-networkd config file
    install -d ${D}${systemd_unitdir}/network
    install -m 0644 ${WORKDIR}/10-eth0-static.network ${D}${systemd_unitdir}/network/

    # Enable systemd-networkd at boot
    install -d ${D}${sysconfdir}/systemd/system/multi-user.target.wants
    ln -sf /lib/systemd/system/systemd-networkd.service \
        ${D}${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service
}

FILES:${PN} += " \
    ${systemd_unitdir}/network/10-eth0-static.network \
    ${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service \
"
