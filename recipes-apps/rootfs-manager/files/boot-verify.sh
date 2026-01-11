#!/bin/sh
# Boot Verification and Auto-Fallback Script
# Runs early in boot process to verify filesystem integrity
# Automatically switches to backup partition if primary is corrupted

BOOT_COUNT_FILE="/boot/boot_count"
MAX_BOOT_ATTEMPTS=3
BOOT_SUCCESS_FILE="/var/run/boot_success"
BOOT_CONFIG="/boot/cmdline.txt"
ROOTFS_A="/dev/mmcblk0p2"
ROOTFS_B="/dev/mmcblk0p3"

log_msg() {
    echo "[BOOT-VERIFY] $1"
    logger -t boot-verify "$1"
}

get_current_root() {
    cat /proc/cmdline | grep -o 'root=[^ ]*' | cut -d'=' -f2
}

get_current_partition() {
    current=$(get_current_root)
    if [ "$current" = "$ROOTFS_A" ]; then
        echo "A"
    elif [ "$current" = "$ROOTFS_B" ]; then
        echo "B"
    else
        echo "UNKNOWN"
    fi
}

increment_boot_count() {
    if [ -f "$BOOT_COUNT_FILE" ]; then
        count=$(cat "$BOOT_COUNT_FILE")
    else
        count=0
    fi
    count=$((count + 1))
    echo $count > "$BOOT_COUNT_FILE"
    sync
    echo $count
}

reset_boot_count() {
    echo 0 > "$BOOT_COUNT_FILE"
    sync
    log_msg "Boot counter reset - successful boot confirmed"
}

check_filesystem_health() {
    partition=$1
    label=$2
    
    log_msg "Checking filesystem health: $partition ($label)"
    
    # Check if partition exists
    if [ ! -b "$partition" ]; then
        log_msg "ERROR: Partition $partition does not exist!"
        return 1
    fi
    
    # Run fsck in non-interactive mode
    fsck -n "$partition" > /tmp/fsck_output 2>&1
    fsck_result=$?
    
    # fsck return codes:
    # 0 = No errors
    # 1 = Filesystem errors corrected
    # 2 = System should be rebooted
    # 4 = Filesystem errors left uncorrected
    # 8 = Operational error
    # 16 = Usage or syntax error
    # 32 = Fsck canceled by user request
    # 128 = Shared-library error
    
    if [ $fsck_result -eq 0 ] || [ $fsck_result -eq 1 ]; then
        log_msg "Filesystem $label is healthy (fsck code: $fsck_result)"
        return 0
    else
        log_msg "ERROR: Filesystem $label is corrupted! (fsck code: $fsck_result)"
        cat /tmp/fsck_output | logger -t boot-verify
        return 1
    fi
}

switch_to_backup() {
    log_msg "CRITICAL: Switching to backup partition!"
    
    # Backup current cmdline.txt
    mount -o remount,rw /boot
    cp $BOOT_CONFIG ${BOOT_CONFIG}.bak
    
    # Switch to backup partition (read-only)
    sed -i "s|root=[^ ]*|root=$ROOTFS_B ro|g" $BOOT_CONFIG
    
    # Reset boot counter
    echo 0 > "$BOOT_COUNT_FILE"
    sync
    
    log_msg "Boot partition switched to B (backup, read-only)"
    log_msg "System will reboot in 5 seconds..."
    sleep 5
    reboot -f
}

verify_critical_files() {
    log_msg "Verifying critical system files..."
    
    # Check critical directories and files
    critical_paths="/bin /sbin /lib /etc/init.d /usr/bin"
    
    for path in $critical_paths; do
        if [ ! -e "$path" ]; then
            log_msg "ERROR: Critical path missing: $path"
            return 1
        fi
    done
    
    log_msg "Critical files verification passed"
    return 0
}

# Main boot verification logic
main() {
    log_msg "========================================="
    log_msg "Boot Verification Starting..."
    log_msg "========================================="
    
    current_part=$(get_current_partition)
    current_root=$(get_current_root)
    
    log_msg "Current partition: $current_part ($current_root)"
    
    # If booting from backup, skip verification (backup is read-only and trusted)
    if [ "$current_part" = "B" ]; then
        log_msg "Booted from BACKUP partition (read-only)"
        log_msg "Backup partition is always trusted - skipping verification"
        log_msg "System running in SAFE MODE"
        touch "$BOOT_SUCCESS_FILE"
        reset_boot_count
        return 0
    fi
    
    # Booting from primary partition - verify integrity
    log_msg "Booted from PRIMARY partition - verifying integrity..."
    
    # Increment boot counter
    boot_count=$(increment_boot_count)
    log_msg "Boot attempt: $boot_count/$MAX_BOOT_ATTEMPTS"
    
    # Check if exceeded max boot attempts
    if [ $boot_count -gt $MAX_BOOT_ATTEMPTS ]; then
        log_msg "CRITICAL: Exceeded maximum boot attempts ($MAX_BOOT_ATTEMPTS)"
        log_msg "Primary partition appears to be failing repeatedly"
        switch_to_backup
        exit 1
    fi
    
    # Verify current root filesystem health
    if ! check_filesystem_health "$current_root" "primary"; then
        log_msg "CRITICAL: Primary filesystem is corrupted!"
        switch_to_backup
        exit 1
    fi
    
    # Verify critical system files exist
    if ! verify_critical_files; then
        log_msg "CRITICAL: Critical system files missing or corrupted!"
        switch_to_backup
        exit 1
    fi
    
    # All checks passed
    log_msg "========================================="
    log_msg "Boot verification PASSED"
    log_msg "Primary partition is healthy"
    log_msg "========================================="
    
    # Mark boot as successful (will be confirmed later by boot-success service)
    touch "$BOOT_SUCCESS_FILE"
    
    return 0
}

# Run main verification
main

exit 0
