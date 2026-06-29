SUMMARY = "IoT Gateway Application - LED blink and HTTPS firmware server"
DESCRIPTION = "Unified application combining LED control and HTTPS firmware download server"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

# ---------------------------------------------------------------------------
# PV from VERSION file — safe approach with AUTOREV
#
# A Python inline expression in PV (${@open(...)...}) fails when AUTOREV
# is used: BitBake embeds ${PV} in the shell PATH for `git ls-remote` before
# the expression is evaluated, so /bin/sh sees a literal ${@...} and raises
# "Bad substitution".
#
# Solution: an anonymous python function reads the VERSION file and calls
# d.setVar('PV', ...) which stores PV as a resolved plain string.  When
# AUTOREV later builds the shell PATH it sees e.g. "0.1.0", not an expression.
# ---------------------------------------------------------------------------
python () {
    import os
    # d.getVar('FILE') gives the absolute path to this recipe file;
    # VERSION lives in the same directory.
    recipe_dir = os.path.dirname(d.getVar('FILE') or '')
    version_file = os.path.join(recipe_dir, 'VERSION')
    try:
        with open(version_file) as vf:
            pv = vf.readline().strip()
        if pv:
            d.setVar('PV', pv)
            bb.debug(1, "iot-gateway-apps: PV set to '%s' from VERSION file" % pv)
    except Exception as e:
        bb.warn("iot-gateway-apps: Could not read VERSION file (%s) — using default PV" % e)
}

DEPENDS = "libmicrohttpd gnutls libgpiod openssl curl"
RDEPENDS:${PN} = "libmicrohttpd gnutls openssl iw wpa-supplicant libgpiod curl"

SRCREV = "${AUTOREV}"
SRC_URI = "git://github.com/Pavan-githu/meta-userapp-package.git;branch=feature/firmwareUpdate;protocol=https"

S = "${WORKDIR}/git"

inherit pkgconfig systemd

SYSTEMD_SERVICE:${PN} = "iot-gateway.service"
SYSTEMD_AUTO_ENABLE = "enable"

do_compile() {
    # Compile unified IoT gateway application
    cd ${S}/recipes-apps/iot-gateway/files
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c keccak256.cpp   -o keccak256.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c otp_manager.cpp -o otp_manager.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c blockchain_logger.cpp -o blockchain_logger.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c blink.cpp        -o blink.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c https_server.cpp -o https_server.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c certificate.cpp  -o certificate.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c wifi_manager.cpp -o wifi_manager.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c user_auth.cpp    -o user_auth.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c main.cpp         -o main.o
    ${CXX} ${CXXFLAGS} -pthread -o iot-gateway \
        main.o blink.o https_server.o certificate.o wifi_manager.o \
        user_auth.o keccak256.o otp_manager.o blockchain_logger.o \
        ${LDFLAGS} -lmicrohttpd -lgnutls -lgpiod -lssl -lcrypto -lcurl
}

do_install() {
    # Install unified IoT gateway application
    install -d ${D}${bindir}
    install -m 0755 ${S}/recipes-apps/iot-gateway/files/iot-gateway ${D}${bindir}/
    
    # Install configuration directory for certificates
    install -d ${D}${sysconfdir}/https-server

    # Install user registry directory (mode 700 – root only)
    install -d -m 0700 ${D}${sysconfdir}/iot-gateway
    
    # Install systemd service
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/recipes-apps/iot-gateway/files/iot-gateway.service ${D}${systemd_system_unitdir}/

    # Bake application version onto the device
    install -d ${D}${sysconfdir}
    echo "${PV}" > ${D}${sysconfdir}/iot-gateway-version
}

FILES:${PN} += "${bindir}/iot-gateway"
FILES:${PN} += "${sysconfdir}/https-server"
FILES:${PN} += "${sysconfdir}/iot-gateway"
FILES:${PN} += "${sysconfdir}/iot-gateway-version"
FILES:${PN} += "${systemd_system_unitdir}/iot-gateway.service"
