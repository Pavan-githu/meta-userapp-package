SUMMARY = "Network configuration for eth0 (static) and wlan0 (DHCP)"
DESCRIPTION = "Configures eth0 with a static IP and wlan0 with DHCP using systemd-networkd"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
PR = "r5"

SRC_URI = "file://10-eth0-static.network \
           file://20-wlan0-dhcp.network"

S = "${WORKDIR}"

do_install() {
    bbwarn "network-config: do_install is RUNNING - not from sstate"

    # Install systemd-networkd .network configs
    install -d ${D}${sysconfdir}/systemd/network
    install -m 0644 ${WORKDIR}/10-eth0-static.network ${D}${sysconfdir}/systemd/network/
    install -m 0644 ${WORKDIR}/20-wlan0-dhcp.network ${D}${sysconfdir}/systemd/network/

    # Enable systemd-networkd at boot via explicit symlinks.
    # SYSTEMD_SERVICE bbclass is NOT used here because systemd-networkd.service
    # belongs to the 'systemd' package, not this recipe; the bbclass skips
    # symlink creation when the service file is absent from ${D}.
    install -d ${D}${sysconfdir}/systemd/system/multi-user.target.wants
    install -d ${D}${sysconfdir}/systemd/system/sockets.target.wants
    ln -sf /lib/systemd/system/systemd-networkd.service \
        ${D}${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service
    ln -sf /lib/systemd/system/systemd-networkd.socket \
        ${D}${sysconfdir}/systemd/system/sockets.target.wants/systemd-networkd.socket
}

FILES:${PN} += " \
    ${sysconfdir}/systemd/network/10-eth0-static.network \
    ${sysconfdir}/systemd/network/20-wlan0-dhcp.network \
    ${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service \
    ${sysconfdir}/systemd/system/sockets.target.wants/systemd-networkd.socket \
"
