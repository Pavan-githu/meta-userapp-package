SUMMARY = "Dual root filesystem partition manager"
DESCRIPTION = "Tool to manage A/B partition switching for fail-safe updates with automatic fallback"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

inherit systemd

SRC_URI = "file://rootfs-manager \
           file://boot-verify.sh \
           file://boot-success.sh \
           file://boot-verify.service \
           file://boot-success.service \
          "

S = "${WORKDIR}"

SYSTEMD_SERVICE:${PN} = "boot-verify.service boot-success.service"
SYSTEMD_AUTO_ENABLE = "enable"

RDEPENDS:${PN} += "e2fsprogs-e2fsck"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/rootfs-manager ${D}${bindir}/
    install -m 0755 ${WORKDIR}/boot-verify.sh ${D}${bindir}/
    install -m 0755 ${WORKDIR}/boot-success.sh ${D}${bindir}/
    
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/boot-verify.service ${D}${systemd_system_unitdir}/
    install -m 0644 ${WORKDIR}/boot-success.service ${D}${systemd_system_unitdir}/
}

FILES:${PN} = "${bindir}/rootfs-manager \
               ${bindir}/boot-verify.sh \
               ${bindir}/boot-success.sh \
               ${systemd_system_unitdir}/boot-verify.service \
               ${systemd_system_unitdir}/boot-success.service \
              "
