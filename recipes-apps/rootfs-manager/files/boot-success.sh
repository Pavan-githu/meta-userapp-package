#!/bin/sh
# Boot Success Marker
# Called after all services start successfully to confirm good boot
# Resets the boot counter to prevent automatic failover

BOOT_COUNT_FILE="/boot/boot_count"
BOOT_SUCCESS_FILE="/var/run/boot_success"

log_msg() {
    echo "[BOOT-SUCCESS] $1"
    logger -t boot-success "$1"
}

# Wait for system to stabilize
sleep 5

log_msg "System services started successfully"
log_msg "Confirming successful boot..."

# Reset boot counter
mount -o remount,rw /boot
echo 0 > "$BOOT_COUNT_FILE"
sync
mount -o remount,ro /boot

log_msg "Boot counter reset - boot confirmed as successful"
log_msg "System is stable and healthy"

exit 0
