SUMMARY = "IoT Gateway Application - LED blink and HTTPS firmware server"
DESCRIPTION = "Unified application combining LED control and HTTPS firmware download server"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

DEPENDS = "libmicrohttpd gnutls libgpiod"
RDEPENDS:${PN} = "libmicrohttpd gnutls openssl iw wpa-supplicant libgpiod"

SRCREV = "${AUTOREV}"
SRC_URI = "git://github.com/Pavan-githu/meta-userapp-package.git;branch=feature/ledblink;protocol=https"

S = "${WORKDIR}/git"

inherit pkgconfig systemd

SYSTEMD_SERVICE:${PN} = "iot-gateway.service"
SYSTEMD_AUTO_ENABLE = "enable"

do_compile() {
    # Compile unified IoT gateway application
    cd ${S}/recipes-apps/iot-gateway/files
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c blink.cpp -o blink.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c https_server.cpp -o https_server.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c certificate.cpp -o certificate.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c wifi_manager.cpp -o wifi_manager.o
    ${CXX} ${CXXFLAGS} -std=c++11 -pthread -c main.cpp -o main.o
    ${CXX} ${CXXFLAGS} -pthread -o iot-gateway main.o blink.o https_server.o certificate.o wifi_manager.o \
        ${LDFLAGS} -lmicrohttpd -lgnutls -lgpiod
}

do_install() {
    # Install unified IoT gateway application
    install -d ${D}${bindir}
    install -m 0755 ${S}/recipes-apps/iot-gateway/files/iot-gateway ${D}${bindir}/
    
    # Install configuration directory for certificates
    install -d ${D}${sysconfdir}/https-server
    
    # Install systemd service
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/recipes-apps/iot-gateway/files/iot-gateway.service ${D}${systemd_system_unitdir}/
}

FILES:${PN} += "${bindir}/iot-gateway"
FILES:${PN} += "${sysconfdir}/https-server"
FILES:${PN} += "${systemd_system_unitdir}/iot-gateway.service"
