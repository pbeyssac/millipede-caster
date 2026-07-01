#!/bin/bash
#
# uninstall.sh — Remove millipede-caster from the system.
#
# This script:
#   1. Stops and disables the systemd service (if present).
#   2. Removes the binary, the systemd unit, and the runtime directory.
#   3. Optionally removes the configuration and log directories
#      (use --purge to do so; otherwise they are preserved).
#
# Usage:
#   sudo ./uninstall.sh              # remove binary, keep config & logs
#   sudo ./uninstall.sh --purge      # remove everything (binary + config + logs)
#
set -e

PURGE=0
PREFIX="/usr/local"

while [[ $# -gt 0 ]]; do
        case "$1" in
                --purge) PURGE=1; shift ;;
                --prefix) PREFIX="$2"; shift 2 ;;
                --help|-h)
                        echo "Usage: $0 [--purge] [--prefix /usr/local]"
                        echo "  --purge  Also remove /etc/millipede and /var/log/millipede"
                        exit 0
                        ;;
                *) echo "Unknown argument: $1"; exit 1 ;;
        esac
done

if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root (use sudo)." >&2
        exit 1
fi

SERVICE_NAME="millipede-caster"
CONFIG_DIR="/etc/millipede"
LOG_DIR="/var/log/millipede"

#
# 1. Stop and disable the service
#
echo "==> Stopping and disabling $SERVICE_NAME (if active)..."
if systemctl list-unit-files 2>/dev/null | grep -q "^$SERVICE_NAME.service"; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
elif [[ -f /usr/local/etc/rc.d/caster ]]; then
        service caster stop 2>/dev/null || true
        rm -f /usr/local/etc/rc.d/caster
fi

#
# 2. Remove the binary
#
echo "==> Removing binary..."
rm -f "$PREFIX/sbin/caster"
rm -f "$PREFIX/sbin/mapi"
rm -f "$PREFIX/sbin/caster.bak."* 2>/dev/null || true

#
# 3. Remove runtime directory
#
rm -rf /run/millipede 2>/dev/null || true

#
# 4. Optionally remove config and logs
#
if [[ $PURGE -eq 1 ]]; then
        echo "==> --purge: removing $CONFIG_DIR and $LOG_DIR"
        rm -rf "$CONFIG_DIR" "$LOG_DIR"
        echo "==> Removing caster user (if no other process uses it)..."
        if id -u caster >/dev/null 2>&1; then
                userdel caster 2>/dev/null || echo "  (caster user kept — still in use)"
        fi
else
        echo "==> Keeping $CONFIG_DIR and $LOG_DIR (use --purge to remove them)."
fi

echo "==> Uninstall complete."
