SUMMARY = "Cloudflare Tunnel daemon"
DESCRIPTION = "cloudflared connects the device to Cloudflare's network, \
               exposing local services via a public domain without port forwarding."
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

# Pre-built ARM 32-bit binary — place cloudflared-linux-arm in files/ directory.
# Download with: scripts/download-cloudflared.sh
SRC_URI = "file://cloudflared \
           file://cloudflared.service \
           file://cloudflared-env \
           file://cloudflared-domain \
           file://cloudflared-setup.sh"

inherit systemd

SYSTEMD_SERVICE:${PN} = "cloudflared.service"
SYSTEMD_AUTO_ENABLE = "enable"

# No source to configure or compile — binary only
do_configure[noexec] = "1"
do_compile[noexec] = "1"

do_install() {
    # Install binary
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/cloudflared ${D}${bindir}/cloudflared

    # Install config directory
    install -d ${D}${sysconfdir}/cloudflared

    # Install env file (holds the tunnel token — filled in post-flash)
    install -m 0600 ${WORKDIR}/cloudflared-env ${D}${sysconfdir}/cloudflared/env

    # Install domain file (holds the public domain — filled in post-flash)
    install -m 0644 ${WORKDIR}/cloudflared-domain ${D}${sysconfdir}/cloudflared/domain

    # Install first-boot setup script (converts token -> credentials.json + config.yml)
    install -m 0755 ${WORKDIR}/cloudflared-setup.sh ${D}${sysconfdir}/cloudflared/cloudflared-setup.sh

    # Install systemd service
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/cloudflared.service ${D}${systemd_system_unitdir}/cloudflared.service

    # Enable cloudflared at boot via an explicit symlink so it is pre-enabled
    # in the image without requiring 'systemctl enable' after flashing.
    install -d ${D}${sysconfdir}/systemd/system/multi-user.target.wants
    ln -sf ${systemd_system_unitdir}/cloudflared.service \
        ${D}${sysconfdir}/systemd/system/multi-user.target.wants/cloudflared.service
}

FILES:${PN} += " \
    ${bindir}/cloudflared \
    ${sysconfdir}/cloudflared/env \
    ${sysconfdir}/cloudflared/domain \
    ${sysconfdir}/cloudflared/cloudflared-setup.sh \
    ${systemd_system_unitdir}/cloudflared.service \
    ${sysconfdir}/systemd/system/multi-user.target.wants/cloudflared.service \
"
