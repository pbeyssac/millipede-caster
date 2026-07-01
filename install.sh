#!/bin/bash
#
# install.sh — Install millipede-caster from source on Debian/Ubuntu or FreeBSD.
#
# This script:
#   1. Detects the OS and installs build dependencies.
#   2. Builds the caster binary.
#   3. Creates a 'caster' system user and required directories.
#   4. Installs the binary, default config, and (on Linux) a systemd unit.
#   5. Does NOT start the service — run 'systemctl start millipede-caster' afterwards.
#
# Usage:
#   sudo ./install.sh                 # install with defaults
#   sudo ./install.sh --prefix /opt   # install under /opt instead of /usr/local
#   sudo ./install.sh --config-only   # only install config files (skip build)
#
set -e

PREFIX="/usr/local"
CONFIG_DIR="/etc/millipede"
LOG_DIR="/var/log/millipede"
CONFIG_ONLY=0

while [[ $# -gt 0 ]]; do
        case "$1" in
                --prefix) PREFIX="$2"; shift 2 ;;
                --config-only) CONFIG_ONLY=1; shift ;;
                --help|-h)
                        echo "Usage: $0 [--prefix /usr/local] [--config-only]"
                        exit 0
                        ;;
                *) echo "Unknown argument: $1"; exit 1 ;;
        esac
done

# Detect OS
if [[ -f /etc/debian_version ]]; then
        OS="debian"
elif [[ -f /etc/freebsd-update.conf ]]; then
        OS="freebsd"
elif command -v pkg >/dev/null 2>&1 && [[ "$(uname)" == "FreeBSD" ]]; then
        OS="freebsd"
else
        OS="linux-generic"
fi

echo "==> Detected OS: $OS"
echo "==> Install prefix: $PREFIX"
echo "==> Config dir: $CONFIG_DIR"
echo "==> Log dir: $LOG_DIR"

# Check root
if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root (use sudo)." >&2
        exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

#
# 1. Install build dependencies
#
if [[ $CONFIG_ONLY -eq 0 ]]; then
        echo "==> Installing build dependencies..."
        case "$OS" in
                debian)
                        apt-get update -qq
                        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                                build-essential cmake libcyaml-dev libjson-c-dev \
                                libevent-dev libyaml-dev libssl-dev
                        ;;
                freebsd)
                        pkg install -y libevent libcyaml json-c yaml-prototypes openssl cmake
                        ;;
                linux-generic)
                        echo "WARNING: unrecognized Linux distribution."
                        echo "  Please install manually: cmake, gcc, libcyaml-dev, libjson-c-dev,"
                        echo "  libevent-dev, libyaml-dev, libssl-dev."
                        read -p "  Continue anyway? [y/N] " yn
                        [[ "$yn" =~ ^[Yy] ]] || exit 1
                        ;;
        esac
fi

#
# 2. Build
#
if [[ $CONFIG_ONLY -eq 0 ]]; then
        echo "==> Building millipede-caster..."
        BUILD_DIR="$REPO_ROOT/build-install"
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        ( cd "$BUILD_DIR" && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" "$REPO_ROOT" )
        ( cd "$BUILD_DIR" && make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)" )
fi

#
# 3. Create system user and directories
#
echo "==> Creating caster user and directories..."
case "$OS" in
        freebsd)
                if ! pw user show caster >/dev/null 2>&1; then
                        pw useradd -n caster -d /nonexistent -s /usr/sbin/nologin -c "Millipede NTRIP Caster"
                fi
                ;;
        *)
                if ! id -u caster >/dev/null 2>&1; then
                        useradd --system --no-create-home --shell /usr/sbin/nologin --user-group caster
                fi
                ;;
esac

mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chown caster:caster "$LOG_DIR"
chmod 0750 "$LOG_DIR"

#
# 4. Install binary
#
if [[ $CONFIG_ONLY -eq 0 ]]; then
        echo "==> Installing binary to $PREFIX/sbin/ ..."
        install -m 0755 "$BUILD_DIR/caster" "$PREFIX/sbin/caster"
        if [[ -f "$REPO_ROOT/caster/bin/mapi" ]]; then
                install -m 0755 "$REPO_ROOT/caster/bin/mapi" "$PREFIX/sbin/mapi"
        fi

        # Install web admin UI
        if [[ -d "$REPO_ROOT/web/admin" ]]; then
                echo "==> Installing web admin UI to $PREFIX/share/millipede/web/ ..."
                mkdir -p "$PREFIX/share/millipede/web/admin"
                cp -a "$REPO_ROOT/web/admin/"* "$PREFIX/share/millipede/web/admin/"
        fi
fi

#
# 5. Install default config (only if not already present)
#
install_one_config() {
        local src="$1" dst="$2"
        if [[ -f "$dst" ]]; then
                echo "    keeping existing $dst"
        else
                install -m 0640 -o caster -g caster "$src" "$dst"
                echo "    installed $dst"
        fi
}

echo "==> Installing default configuration to $CONFIG_DIR/ ..."
install_one_config "$REPO_ROOT/sample-config/caster.yaml"        "$CONFIG_DIR/caster.yaml"
install_one_config "$REPO_ROOT/sample-config/sourcetable.dat"   "$CONFIG_DIR/sourcetable.dat"
install_one_config "$REPO_ROOT/sample-config/source.auth"       "$CONFIG_DIR/source.auth"
install_one_config "$REPO_ROOT/sample-config/host.auth"         "$CONFIG_DIR/host.auth"
install_one_config "$REPO_ROOT/sample-config/sourcetable-filter.json" "$CONFIG_DIR/sourcetable-filter.json"
install_one_config "$REPO_ROOT/sample-config/blocklist"         "$CONFIG_DIR/blocklist"
install_one_config "$REPO_ROOT/sample-config/caster.sh"         "$CONFIG_DIR/caster.sh"

# Patch the config: replace relative filenames with absolute paths in /etc/millipede
# (only if the file is fresh — we never overwrite an existing config)
if [[ ! -f "$CONFIG_DIR/.install-stamp" ]]; then
        sed -i \
                -e "s|^sourcetable_file:.*|sourcetable_file: $CONFIG_DIR/sourcetable.dat|" \
                -e "s|^source_auth_file:.*|source_auth_file: $CONFIG_DIR/source.auth|" \
                -e "s|^host_auth_file:.*|host_auth_file: $CONFIG_DIR/host.auth|" \
                -e "s|^blocklist_file:.*|blocklist_file: $CONFIG_DIR/blocklist|" \
                -e "s|^access_log:.*|access_log: $LOG_DIR/caster-access.log|" \
                -e "s|^log:.*|log: $LOG_DIR/caster.log|" \
                "$CONFIG_DIR/caster.yaml"
        date -Iseconds > "$CONFIG_DIR/.install-stamp"
fi

#
# 6. Install init script / systemd unit
#
echo "==> Installing service unit..."
case "$OS" in
        freebsd)
                install -m 0755 "$REPO_ROOT/sample-config/caster.sh" /usr/local/etc/rc.d/caster
                echo "==> Run: sysrc caster_enable=YES"
                ;;
        *)
                install -m 0644 "$REPO_ROOT/deploy/millipede-caster.service" /etc/systemd/system/millipede-caster.service
                systemctl daemon-reload
                echo "==> Run: systemctl enable --now millipede-caster"
                ;;
esac

#
# 7. Done
#
cat <<EOF

==> Installation complete!

Next steps:
  1. Edit $CONFIG_DIR/caster.yaml and the .auth files to match your setup.
  2. (Linux) Enable and start the service:
        systemctl enable --now millipede-caster
     (FreeBSD)
        sysrc caster_enable=YES
        service caster start
  3. Check the log: tail -f $LOG_DIR/caster.log
  4. Test the JSON API:
        curl -u "admin:admin" http://localhost:2101/adm/api/v1/net

To uninstall, run: sudo ./uninstall.sh

EOF
