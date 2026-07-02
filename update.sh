#!/bin/bash
#
# update.sh — Update an existing millipede-caster installation.
#
# This script:
#   1. Pulls the latest source from git (or uses the current working tree).
#   2. Rebuilds the binary.
#   3. Replaces the installed binary (kept in a backup).
#   4. Reloads the systemd unit file (if changed) and restarts the service.
#
# Usage:
#   sudo ./update.sh              # git pull + rebuild + restart
#   sudo ./update.sh --no-pull    # rebuild from current source, no git pull
#   sudo ./update.sh --no-restart # rebuild but don't restart the service
#
set -e

NO_PULL=0
NO_RESTART=0
PREFIX="/usr/local"

while [[ $# -gt 0 ]]; do
        case "$1" in
                --no-pull) NO_PULL=1; shift ;;
                --no-restart) NO_RESTART=1; shift ;;
                --prefix) PREFIX="$2"; shift 2 ;;
                --help|-h)
                        echo "Usage: $0 [--no-pull] [--no-restart] [--prefix /usr/local]"
                        exit 0
                        ;;
                *) echo "Unknown argument: $1"; exit 1 ;;
        esac
done

if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root (use sudo)." >&2
        exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
SERVICE_NAME="millipede-caster"

#
# 1. Pull latest source (unless --no-pull)
#
if [[ $NO_PULL -eq 0 ]]; then
        if [[ -d "$REPO_ROOT/.git" ]]; then
                echo "==> Pulling latest source..."
                ( cd "$REPO_ROOT" && git pull --ff-only )
        else
                echo "==> Not a git checkout; skipping pull."
        fi
fi

#
# 2. Rebuild
#
echo "==> Building..."
BUILD_DIR="$REPO_ROOT/build-update"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
( cd "$BUILD_DIR" && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" "$REPO_ROOT" )
( cd "$BUILD_DIR" && make -j"$(nproc 2>/dev/null || echo 2)" )

#
# 3. Backup existing binary and install the new one
#
BIN_PATH="$PREFIX/sbin/caster"
if [[ -f "$BIN_PATH" ]]; then
        BACKUP="$BIN_PATH.bak.$(date +%Y%m%d-%H%M%S)"
        echo "==> Backing up old binary to $BACKUP"
        cp -a "$BIN_PATH" "$BACKUP"
fi

echo "==> Installing new binary to $BIN_PATH"
install -m 0755 "$BUILD_DIR/caster" "$BIN_PATH"

# Also reinstall mapi if it exists
if [[ -f "$REPO_ROOT/caster/bin/mapi" ]]; then
        install -m 0755 "$REPO_ROOT/caster/bin/mapi" "$PREFIX/sbin/mapi"
fi

#
# 4. Update systemd unit (if changed)
#
if [[ -f "$REPO_ROOT/deploy/millipede-caster.service" ]] && [[ -d /etc/systemd/system ]]; then
        if ! diff -q "$REPO_ROOT/deploy/millipede-caster.service" /etc/systemd/system/millipede-caster.service >/dev/null 2>&1; then
                echo "==> Updating systemd unit file"
                install -m 0644 "$REPO_ROOT/deploy/millipede-caster.service" /etc/systemd/system/millipede-caster.service
                systemctl daemon-reload
        fi
fi

#
# 5. Restart the service (unless --no-restart)
#
if [[ $NO_RESTART -eq 0 ]]; then
        if systemctl list-unit-files | grep -q "^$SERVICE_NAME.service"; then
                echo "==> Restarting $SERVICE_NAME..."
                systemctl restart "$SERVICE_NAME"
                sleep 1
                if systemctl is-active --quiet "$SERVICE_NAME"; then
                        echo "==> Service is running."
                else
                        echo "==> WARNING: service failed to start. Check: journalctl -u $SERVICE_NAME -n 50"
                        exit 1
                fi
        else
                echo "==> $SERVICE_NAME is not enabled; skipping restart."
                echo "   Start it manually with: systemctl start $SERVICE_NAME"
        fi
fi

echo "==> Update complete."
