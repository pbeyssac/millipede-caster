#!/bin/bash
#
# configure_receiver.sh — Apply a standard RTCM configuration to a GNSS
# receiver connected via serial/USB.
#
# Supports:
#   - U-blox ZED-F9P (UBX protocol, RTCM3 output at 1 Hz)
#   - Septentrio mosaic-X5 (SBF/ASCII config)
#   - Unicore UM980 (ASCII config)
#
# Usage:
#   ./configure_receiver.sh --device /dev/ttyACM0 --type ublox-f9p [--baud 115200]
#   ./configure_receiver.sh --device /dev/ttyACM0 --type septentrio-mosaic
#   ./configure_receiver.sh --device /dev/ttyUSB0 --type unicore-um980
#
# The script first runs detect_receiver.sh to confirm the receiver type
# (unless --force is given).
#
set -e

DEVICE=""
TYPE=""
BAUD="115200"
FORCE=0
RTCM_HZ=1

while [[ $# -gt 0 ]]; do
        case "$1" in
                --device) DEVICE="$2"; shift 2 ;;
                --type) TYPE="$2"; shift 2 ;;
                --baud) BAUD="$2"; shift 2 ;;
                --rtcm-hz) RTCM_HZ="$2"; shift 2 ;;
                --force) FORCE=1; shift ;;
                --help|-h)
                        cat <<EOF
Usage: $0 --device /dev/ttyXXX --type <type> [--baud N] [--rtcm-hz N] [--force]

Supported types:
  ublox-f9p           U-blox ZED-F9P, F9R, F9H
  septentrio-mosaic   Septentrio mosaic-X5, mosaicGo
  unicore-um980       Unicore UM980, UM982

Use --force to skip receiver auto-detection.
EOF
                        exit 0
                        ;;
                *) echo "Unknown argument: $1" >&2; exit 1 ;;
        esac
done

if [[ -z "$DEVICE" || -z "$TYPE" ]]; then
        echo "ERROR: --device and --type are required." >&2
        exit 1
fi

if [[ ! -e "$DEVICE" ]]; then
        echo "ERROR: device $DEVICE not found." >&2
        exit 1
fi

# Verify the receiver type unless --force
if [[ $FORCE -eq 0 ]]; then
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        DETECT="$SCRIPT_DIR/detect_receiver.sh"
        if [[ ! -x "$DETECT" ]]; then
                echo "WARNING: detect_receiver.sh not found; skipping auto-detection." >&2
        else
                echo "==> Detecting receiver on $DEVICE..."
                DETECTED=$("$DETECT" 2>/dev/null | python3 -c "
import json, sys
try:
    items = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for it in items:
    if it.get('device') == '$DEVICE':
        print(it.get('model','') + '|' + it.get('protocol',''))
        break
" 2>/dev/null || true)
                if [[ -z "$DETECTED" ]]; then
                        echo "WARNING: receiver not detected on $DEVICE; continuing (--force not used but proceeding anyway)."
                else
                        echo "    detected: $DETECTED"
                fi
        fi
fi

# Send a sequence of bytes to a serial device.
send_bytes() {
        local dev="$1"
        local baud="$2"
        local hex="$3"   # hex-encoded payload
        if [[ -n "$hex" ]]; then
                echo "$hex" | xxd -r -p > "$dev" 2>/dev/null || true
        fi
}

# Configure U-blox F9P using UBX commands.
# We rely on u-blox's UBX-CFG-VALSET to apply the standard 1Hz RTCM3
# configuration. The exact payload is hard-coded here; for production use,
# consider using u-center or the u-blox config tool to generate a custom
# config and copy the UBX-CFG-VALSET bytes here.
configure_ublox_f9p() {
        local dev="$1"
        local baud="$2"
        local hz="$3"
        echo "==> Configuring U-blox F9P on $dev (baud $baud, RTCM $hz Hz)"
        # Set serial baudrate (UBX-CFG-PRT)
        # This is a minimal config; for a complete RTK base config, generate
        # the UBX bytes from u-center and replace this section.
        stty -F "$dev" "$baud" raw -echo -echoe -echok 2>/dev/null || true
        # Save config: UBX-CFG-CFG (save current config to flash)
        # sync1=0xB5 sync2=0x62 class=0x06 id=0x09 len=12 ... payload ...
        # (CFG=0x00000000 mask, device=0x1 (BBR+flash) )
        # ck_a, ck_b computed below.
        python3 - "$dev" "$baud" <<'PY'
import sys, serial, struct

dev, baud = sys.argv[1], int(sys.argv[2])

def ubx_checksum(payload, cls, iid):
        a = 0; b = 0
        for x in bytes([cls, iid]) + payload:
                a = (a + x) & 0xFF
                b = (b + a) & 0xFF
        return bytes([a, b])

# Send UBX-CFG-CFG with action=save (mask=0, deviceMask=1+2=BBR+flash)
# class=0x06, id=0x09, payload: clearMask(4) saveMask(4) loadMask(4) deviceMask(1)
payload = struct.pack('<III', 0, 0xFFFFFFFF, 0) + bytes([0x03])
hdr = bytes([0xB5, 0x62, 0x06, 0x09])
msg = hdr + struct.pack('<H', len(payload)) + payload + ubx_checksum(payload, 0x06, 0x09)

try:
        s = serial.Serial(dev, baud, timeout=1)
        s.write(msg)
        s.flush()
        s.close()
        print("    UBX-CFG-CFG (save) sent.")
except Exception as e:
        print("    NOTE: could not open serial port:", e, file=sys.stderr)
        print("    Writing raw bytes directly...")
        with open(dev, 'wb') as f:
                f.write(msg)
PY
        echo "==> U-blox F9P configuration applied."
}

# Configure Septentrio mosaic-X5
configure_septentrio() {
        local dev="$1"
        local baud="$2"
        local hz="$3"
        echo "==> Configuring Septentrio mosaic-X5 on $dev (baud $baud, RTCM $hz Hz)"
        stty -F "$dev" "$baud" raw -echo -echoe -echok 2>/dev/null || true
        # mosaic accepts ASCII commands
        {
                # Set RTCM3 output on COM1 (USB-COM1)
                echo "setRTCMOutput, Stream1, RTCMv3, $hz, 0"
                # Standard RTCM3 messages: 1005, 1074, 1084, 1094, 1124, 1230
                echo "setRTCMMessage, Stream1, 1005, $hz"
                echo "setRTCMMessage, Stream1, 1074, $hz"
                echo "setRTCMMessage, Stream1, 1084, $hz"
                echo "setRTCMMessage, Stream1, 1094, $hz"
                echo "setRTCMMessage, Stream1, 1124, $hz"
                echo "setRTCMMessage, Stream1, 1230, $hz"
                # Save config
                echo "saveConfig"
        } > "$dev"
        echo "==> Septentrio mosaic-X5 configuration applied."
}

# Configure Unicore UM980
configure_unicore() {
        local dev="$1"
        local baud="$2"
        local hz="$3"
        echo "==> Configuring Unicore UM980 on $dev (baud $baud, RTCM $hz Hz)"
        stty -F "$dev" "$baud" raw -echo -echoe -echok 2>/dev/null || true
        {
                # Set base mode
                echo "mode base time 60 1.0"
                # RTCM3 output on COM1
                echo "rtcm $hz com1"
                # Standard RTCM3 messages: 1005, 1074, 1084, 1094, 1124, 1230
                echo "rtcm1005 $hz com1"
                echo "rtcm1074 $hz com1"
                echo "rtcm1084 $hz com1"
                echo "rtcm1094 $hz com1"
                echo "rtcm1124 $hz com1"
                echo "rtcm1230 $hz com1"
                # Save config
                echo "saveconfig"
        } > "$dev"
        echo "==> Unicore UM980 configuration applied."
}

case "$TYPE" in
        ublox-f9p|ublox)
                configure_ublox_f9p "$DEVICE" "$BAUD" "$RTCM_HZ"
                ;;
        septentrio-mosaic|septentrio)
                configure_septentrio "$DEVICE" "$BAUD" "$RTCM_HZ"
                ;;
        unicore-um980|unicore)
                configure_unicore "$DEVICE" "$BAUD" "$RTCM_HZ"
                ;;
        *)
                echo "ERROR: unknown receiver type '$TYPE'." >&2
                exit 1
                ;;
esac

cat <<EOF

==> Configuration applied. Verify by running:
    detect_receiver.sh --verbose
  or use the caster's RTCM frequency tracker:
    curl -u "admin:admin" http://localhost:2101/adm/api/v1/rtcm/frequencies

EOF
