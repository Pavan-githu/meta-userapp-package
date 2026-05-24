SUMMARY = "IoT Gateway Application - LED blink and HTTPS firmware server"
DESCRIPTION = "Unified application combining LED control and HTTPS firmware download server"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

# PV is derived from the recipe filename (iot-gateway-apps_0.1.bb → PV = "0.1").
# A Python inline expression for PV cannot be used with AUTOREV: when BitBake
# resolves AUTOREV it runs `git ls-remote` with a PATH that embeds ${PV}, and
# an unexpanded inline expression in that PATH causes /bin/sh "Bad substitution".
# The VERSION file is still fetched via SRC_URI file:// and baked onto the
# device by do_install for runtime version reporting.

DEPENDS = "libmicrohttpd gnutls libgpiod openssl curl"
RDEPENDS:${PN} = "libmicrohttpd gnutls openssl iw wpa-supplicant libgpiod curl"

SRCREV = "${AUTOREV}"
SRC_URI = "git://github.com/Pavan-githu/meta-userapp-package.git;branch=feature/deviceidentification;protocol=https \
           file://VERSION"

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
