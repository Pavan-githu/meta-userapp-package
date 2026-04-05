# Static IP & SSH Access Fix for RPi3 (eth0)

## Problem

After flashing the Yocto image, `eth0` had no IPv4 address — only a link-local IPv6 address was present.
SSH over Ethernet was unreachable. `ifconfig` showed:

```
eth0  Link encap:Ethernet  HWaddr B8:27:EB:12:99:6D
      inet6 addr: fe80::ba27:ebff:fe12:996d/64 Scope:Link
      UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
```

---

## Root Causes

### 1. `systemd-networkd` daemon was never started

The original `network-config_1.0.bb` recipe used the `inherit systemd` bbclass with
`SYSTEMD_SERVICE:${PN}` to enable `systemd-networkd.service`. However, this mechanism
**only creates service symlinks when the recipe itself installs the service unit file**
into `${D}`. Since `systemd-networkd.service` belongs to the `systemd` package (not
this recipe), the bbclass silently skipped symlink creation. As a result:

- `/etc/systemd/system/multi-user.target.wants/systemd-networkd.service` did not exist
- `systemd-networkd` was never started at boot
- The `.network` config file was present on the image but never read

### 2. `DHCP=no` was missing from the `.network` file

Without `DHCP=no`, `systemd-networkd` would attempt DHCP if static address assignment
failed, causing unpredictable behaviour.

### 3. `dhcpcd` conflict

`meta-raspberrypi` pulls in `dhcpcd` as a recommended package. When active alongside
a non-functional `systemd-networkd`, `dhcpcd` runs on `eth0`, gets no DHCP response,
and leaves the interface with no IPv4 address.

### 4. sstate cache served stale image

Previous builds were restored entirely from sstate-cache because the recipe `PR` was
not bumped after changes. The image timestamp and content were identical to the prior
build, so fixes never reached the device.

---

## Changes Made

### File 1: `recipes-apps/network-config/network-config_1.0.bb`

**What changed:**

- Removed `inherit systemd` and `SYSTEMD_SERVICE:${PN}` — these are only valid when
  the recipe itself provides the service unit file.
- Replaced with **explicit `ln -sf` symlinks** in `do_install()` pointing to the
  absolute path `/lib/systemd/system/systemd-networkd.service` and
  `/lib/systemd/system/systemd-networkd.socket`. This is reliable regardless of
  which package owns the service file.
- Bumped `PR` from `r1` → `r3` to invalidate the sstate cache entry and force a
  genuine rebuild.

**Final state:**

```bitbake
SUMMARY = "Static Ethernet network configuration for eth0"
DESCRIPTION = "Configures eth0 with a static IP using systemd-networkd"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
PR = "r3"

SRC_URI = "file://10-eth0-static.network"

S = "${WORKDIR}"

do_install() {
    bbwarn "network-config: do_install is RUNNING - not from sstate"

    # Install systemd-networkd .network config
    install -d ${D}${sysconfdir}/systemd/network
    install -m 0644 ${WORKDIR}/10-eth0-static.network ${D}${sysconfdir}/systemd/network/

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
    ${sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service \
    ${sysconfdir}/systemd/system/sockets.target.wants/systemd-networkd.socket \
"
```

---

### File 2: `recipes-apps/network-config/files/10-eth0-static.network`

**What changed:**

- Added `DHCP=no` to the `[Network]` section to explicitly disable DHCP and prevent
  any fallback behaviour when `systemd-networkd` is handling the interface.

**Final state:**

```ini
[Match]
Name=eth0

[Network]
DHCP=no
Address=192.168.1.100/24
Gateway=192.168.1.1
DNS=8.8.8.8
```

---

### File 3: `build/conf/local.conf`

**What changed:**

- Added `dhcpcd` to `BAD_RECOMMENDATIONS` alongside `connman`. This prevents
  `meta-raspberrypi`'s recommended `dhcpcd` package from being installed in the image,
  eliminating the conflict with `systemd-networkd`.

**Relevant section (final state):**

```bitbake
# Use systemd as init manager
INIT_MANAGER = "systemd"

# Ensure systemd-networkd is compiled into the systemd package
PACKAGECONFIG:append:pn-systemd = " networkd"

# Disable connman and dhcpcd — they conflict with systemd-networkd
# (.network files are ignored when either is active)
VIRTUAL-RUNTIME_net_manager = ""
BAD_RECOMMENDATIONS += "connman dhcpcd"
```

---

## How to Force a Clean Rebuild After Recipe Changes

Whenever changes are made to `network-config_1.0.bb` or its files, run:

```bash
cd /home/ubuntu/rpi3project
source sources/poky/oe-init-build-env build
bitbake -c cleansstate network-config core-image-minimal
bitbake core-image-minimal
```

Always bump the `PR` value in the recipe when changing recipe files, to ensure
BitBake invalidates the sstate cache entry.

---

## Verification on Device

After flashing the new image:

```bash
# Check networkd is running
systemctl status systemd-networkd

# Confirm IP assignment
ip addr show eth0

# Should show: inet 192.168.1.100/24
```

SSH access:
```bash
ssh root@192.168.1.100
```
