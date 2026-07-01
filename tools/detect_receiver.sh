#!/bin/bash
#
# detect_receiver.sh — Detect and identify GNSS receivers connected via
# serial/USB/TCP.
#
# Supports:
#   - U-blox ZED-F9P, F9R, F9H (USB ID 1546:01a9 / 1546:01a7)
#   - Septentrio mosaic-X5 (USB ID 09d7:0300)
#   - Septentrio AsteRx (any USB ID matching vendor 09d7:*, or by-id string)
#   - Unicore UM980 / UM982 (USB ID 1d00:2010, or by-id string)
#   - Trimble BX992 / BX996 (USB ID 0c1d:0020 / 0c1d:0021, or by-id string)
#     — also detects via TAIP/RTP response on serial
#
# Output: a JSON document on stdout describing each detected receiver.
#
# Usage:
#   ./detect_receiver.sh                 # probe serial + USB
#   ./detect_receiver.sh --verbose       # include probing logs
#   ./detect_receiver.sh --tcp 192.168.1.50:5050  # also probe a TCP receiver
#
# Dependencies: bash, stty, udevadm (optional), python3 (for JSON output)
#
set -e

VERBOSE=0
TCP_TARGETS=()

while [[ $# -gt 0 ]]; do
        case "$1" in
                --verbose|-v) VERBOSE=1; shift ;;
                --tcp) TCP_TARGETS+=("$2"); shift 2 ;;
                --help|-h)
                        cat <<EOF
Usage: $0 [--verbose] [--tcp HOST:PORT ...]

Probes /dev/ttyUSB*, /dev/ttyACM*, /dev/serial/by-id/* for known
GNSS receivers (U-blox F9P, Septentrio mosaic-X5, Unicore UM980).

For each --tcp HOST:PORT argument, also probes that TCP target.

Output: JSON document on stdout.
EOF
                        exit 0
                        ;;
                *) echo "Unknown argument: $1" >&2; exit 1 ;;
        esac
done

log() { [[ $VERBOSE -eq 1 ]] && echo "[detect] $*" >&2 || true; }

#
# Probe one device for a U-blox receiver by sending a UBX-MON-VER poll.
# Returns the model string on stdout (empty if not a U-blox).
#
probe_ublox() {
        local dev="$1"
        local baud="$2"
        # UBX-MON-VER (0x0A 0x04) packet:
        # sync1=0xB5 sync2=0x62 class=0x0A id=0x04 len=0 len=0 ck_a=0x4E ck_b=0x0B
        local ubx_mon_ver="\xb5\x62\x0a\x04\x00\x00\x4e\x0b"
        local reply
        reply=$(timeout 1 bash -c "
                exec 3<>'$dev'
                stty -F '$dev' '$baud' raw -echo -echoe -echok 2>/dev/null || true
                printf '$ubx_mon_ver' >&3
                head -c 256 <&3 2>/dev/null | xxd -p
                exec 3<&-
        " 2>/dev/null || true)
        # Look for the UBX-MON-VER response (B5 62 0A 04) and extract the
        # software version string (first 30 bytes after the header).
        if [[ "$reply" =~ b5620a04 ]]; then
                # Strip the header (8 bytes = 16 hex chars) and take the next 30 bytes (60 hex chars)
                local ver_hex="${reply#*b5620a04}"
                ver_hex="${ver_hex:0:60}"
                # Decode hex to ASCII
                local ver
                ver=$(echo "$ver_hex" | xxd -r -p 2>/dev/null | tr -d '\0' | tr -dc '[:print:]')
                echo "$ver"
                return 0
        fi
        return 1
}

#
# Probe one device for a Septentrio receiver by sending an SBF identify cmd.
# Returns the model string on stdout (empty if not Septentrio).
#
probe_septentrio() {
        local dev="$1"
        local baud="$2"
        # Septentrio ASCII command: "spoof\r\n" gets an error reply that
        # includes the receiver model. Better: send "exePrintVersion\r\n"
        local cmd="exePrintVersion\r\n"
        local reply
        reply=$(timeout 1 bash -c "
                exec 3<>'$dev'
                stty -F '$dev' '$baud' raw -echo -echoe -echok 2>/dev/null || true
                printf '$cmd' >&3
                head -c 256 <&3 2>/dev/null
                exec 3<&-
        " 2>/dev/null || true)
        if echo "$reply" | grep -qi "septentrio\|mosaic\|asterx\|polarx"; then
                echo "$reply" | head -1 | tr -dc '[:print:]'
                return 0
        fi
        return 1
}

#
# Probe one device for a Unicore receiver by sending a version query.
# Returns the model string on stdout (empty if not Unicore).
#
probe_unicore() {
        local dev="$1"
        local baud="$2"
        # Unicore UM980 ASCII command: "version\r\n"
        local cmd="version\r\n"
        local reply
        reply=$(timeout 1 bash -c "
                exec 3<>'$dev'
                stty -F '$dev' '$baud' raw -echo -echoe -echok 2>/dev/null || true
                printf '$cmd' >&3
                head -c 256 <&3 2>/dev/null
                exec 3<&-
        " 2>/dev/null || true)
        if echo "$reply" | grep -qi "unicore\|um980\|um982\|um4b8"; then
                echo "$reply" | head -1 | tr -dc '[:print:]'
                return 0
        fi
        return 1
}

#
# Probe one device for a Trimble receiver (BX992, BX996, etc.) by sending
# a TSIP "report software version" packet (0x13 command 0x06).
# Returns the model string on stdout (empty if not Trimble).
#
probe_trimble() {
        local dev="$1"
        local baud="$2"
        # TSIP packet: DLE [0x13] [0x06] DLE ETX
        # 0x13 = "report packet" command, 0x06 = "software version"
        # Any 0x10 (DLE) in payload must be byte-stuffed, but here the
        # payload is just 0x06 (no DLE) so no stuffing needed.
        local tsip_cmd=$'\x10\x13\x06\x10\x03'
        local reply
        reply=$(timeout 1 bash -c "
                exec 3<>'$dev'
                stty -F '$dev' '$baud' raw -echo -echoe -echok 2>/dev/null || true
                printf '%s' '$tsip_cmd' >&3
                head -c 256 <&3 2>/dev/null | xxd -p
                exec 3<&-
        " 2>/dev/null || true)
        # TSIP response to 0x13/0x06 is packet 0x4D (report software version).
        # Reply format: DLE 4D [major] [minor] [day] [month] [year] ... DLE ETX
        # The receiver model name isn't in this packet, but Trimble BX992/BX996
        # also expose a TAIP/RTP ASCII interface — try that as a fallback.
        if [[ "$reply" =~ 104d ]]; then
                echo "Trimble BX-series (TSIP)"
                return 0
        fi

        # Try TAIP/RTP ASCII: ">QTM<CR><LF>" requests model identity
        # (TAIP packet format: '>' [id] [data] '<' [checksum] <CR>)
        local taip_cmd='>QTM<CR>\r\n'
        reply=$(timeout 1 bash -c "
                exec 3<>'$dev'
                stty -F '$dev' '$baud' raw -echo -echoe -echok 2>/dev/null || true
                printf '%s' '$taip_cmd' >&3
                head -c 256 <&3 2>/dev/null
                exec 3<&-
        " 2>/dev/null || true)
        if echo "$reply" | grep -qiE "trimble|bx99[0-9]|sp80|sp85|r8s|r10"; then
                echo "$reply" | head -1 | tr -dc '[:print:]'
                return 0
        fi
        return 1
}

#
# Identify a device by its USB ID (via udevadm).
# Returns "VENDOR MODEL" on stdout (empty if unknown).
#
identify_by_usb_id() {
        local dev="$1"
        if command -v udevadm >/dev/null 2>&1; then
                local idVendor idProduct vendor model
                idVendor=$(udevadm info -q property -n "$dev" 2>/dev/null | grep ^ID_VENDOR_ID= | cut -d= -f2)
                idProduct=$(udevadm info -q property -n "$dev" 2>/dev/null | grep ^ID_MODEL_ID= | cut -d= -f2)
                case "$idVendor:$idProduct" in
                        1546:01a9|1546:01a7|1546:01a8)
                                echo "U-blox ZED-F9P"
                                return 0
                                ;;
                        09d7:0300|09d7:0200|09d7:0301|09d7:0302)
                                echo "Septentrio mosaic-X5"
                                return 0
                                ;;
                        09d7:0400|09d7:0401|09d7:0402)
                                # AsteRx-i, AsteRx-m, AsteRx-U series
                                echo "Septentrio AsteRx"
                                return 0
                                ;;
                        1d00:2010|1d00:2011)
                                echo "Unicore UM980/UM982"
                                return 0
                                ;;
                        0c1d:0020|0c1d:0021|0c1d:0022)
                                # Trimble BX992, BX996, BX996G
                                echo "Trimble BX-series"
                                return 0
                                ;;
                esac
                # Fall through: try the by-id string
                local by_id
                by_id=$(udevadm info -q property -n "$dev" 2>/dev/null | grep ^ID_SERIAL= | cut -d= -f2)
                if [[ "$by_id" =~ [Uu]blox ]]; then
                        echo "U-blox (USB)"; return 0
                elif [[ "$by_id" =~ [Ss]eptentrio ]]; then
                        # Distinguish AsteRx from mosaic by name
                        if [[ "$by_id" =~ [Aa]steRx ]]; then
                                echo "Septentrio AsteRx"
                        else
                                echo "Septentrio mosaic"
                        fi
                        return 0
                elif [[ "$by_id" =~ [Uu]nicore ]]; then
                        echo "Unicore (USB)"; return 0
                elif [[ "$by_id" =~ [Tt]rimble|BX99 ]]; then
                        echo "Trimble BX-series"; return 0
                fi
        fi
        return 1
}

#
# Probe a single device at all common baud rates.
# Echoes a JSON object on stdout (or nothing if no receiver detected).
#
probe_device() {
        local dev="$1"
        log "probing $dev"
        local usb_id
        usb_id=$(identify_by_usb_id "$dev" 2>/dev/null || true)
        local detected_model=""
        local detected_baud=""
        local detected_protocol=""

        # First try: based on USB ID, only probe the right protocol
        for baud in 115200 460800 9600 38400 19200; do
                if [[ "$usb_id" == U-blox* ]] || [[ -z "$usb_id" ]]; then
                        if model=$(probe_ublox "$dev" "$baud"); then
                                detected_model="$model"
                                detected_baud="$baud"
                                detected_protocol="UBX"
                                break
                        fi
                fi
                if [[ "$usb_id" == Septentrio* ]] || [[ -z "$usb_id" ]]; then
                        if model=$(probe_septentrio "$dev" "$baud"); then
                                detected_model="$model"
                                detected_baud="$baud"
                                detected_protocol="SBF"
                                break
                        fi
                fi
                if [[ "$usb_id" == Unicore* ]] || [[ -z "$usb_id" ]]; then
                        if model=$(probe_unicore "$dev" "$baud"); then
                                detected_model="$model"
                                detected_baud="$baud"
                                detected_protocol="UNICORE"
                                break
                        fi
                fi
                if [[ "$usb_id" == Trimble* ]] || [[ -z "$usb_id" ]]; then
                        if model=$(probe_trimble "$dev" "$baud"); then
                                detected_model="$model"
                                detected_baud="$baud"
                                detected_protocol="TSIP"
                                break
                        fi
                fi
        done

        if [[ -n "$detected_model" ]]; then
                # Build JSON manually to avoid python3 dependency if possible
                # (but use python3 if available for proper escaping)
                if command -v python3 >/dev/null 2>&1; then
                        python3 -c "
import json, sys
print(json.dumps({
    'device': '$dev',
    'vendor_id_guess': '$usb_id',
    'model': '''$(echo "$detected_model" | sed "s/'/'\\\\''/g")''',
    'baudrate': $detected_baud,
    'protocol': '$detected_protocol',
}))
"
                else
                        echo "{\"device\":\"$dev\",\"model\":\"$detected_model\",\"baudrate\":$detected_baud,\"protocol\":\"$detected_protocol\"}"
                fi
                return 0
        fi
        return 1
}

#
# Probe a TCP target (host:port).
#
probe_tcp() {
        local target="$1"
        local host="${target%:*}"
        local port="${target##*:}"
        log "probing tcp $host:$port"
        # Send a UBX-MON-VER poll and check the reply
        local ubx_mon_ver="\xb5\x62\x0a\x04\x00\x00\x4e\x0b"
        local reply
        reply=$(timeout 2 bash -c "
                exec 3<>/dev/tcp/$host/$port
                printf '$ubx_mon_ver' >&3
                head -c 256 <&3 2>/dev/null | xxd -p
                exec 3<&-
        " 2>/dev/null || true)
        if [[ "$reply" =~ b5620a04 ]]; then
                local ver_hex="${reply#*b5620a04}"
                ver_hex="${ver_hex:0:60}"
                local ver
                ver=$(echo "$ver_hex" | xxd -r -p 2>/dev/null | tr -d '\0' | tr -dc '[:print:]')
                if command -v python3 >/dev/null 2>&1; then
                        python3 -c "
import json
print(json.dumps({
    'device': 'tcp:$host:$port',
    'model': '''$(echo "$ver" | sed "s/'/'\\\\''/g")''',
    'protocol': 'UBX',
}))
"
                else
                        echo "{\"device\":\"tcp:$host:$port\",\"model\":\"$ver\",\"protocol\":\"UBX\"}"
                fi
                return 0
        fi
        return 1
}

#
# Main
#
results=()

# Collect candidate devices
devices=()
for d in /dev/ttyUSB* /dev/ttyACM* /dev/serial/by-id/*; do
        [[ -e "$d" ]] || continue
        devices+=("$d")
done

if [[ ${#devices[@]} -eq 0 ]] && [[ ${#TCP_TARGETS[@]} -eq 0 ]]; then
        log "no devices to probe"
fi

# Probe each device
for dev in "${devices[@]}"; do
        if out=$(probe_device "$dev" 2>/dev/null); then
                results+=("$out")
        fi
done

# Probe TCP targets
for target in "${TCP_TARGETS[@]}"; do
        if out=$(probe_tcp "$target" 2>/dev/null); then
                results+=("$out")
        fi
done

# Output as a JSON array
if [[ ${#results[@]} -eq 0 ]]; then
        echo "[]"
else
        if command -v python3 >/dev/null 2>&1; then
                printf '%s\n' "${results[@]}" | python3 -c "
import json, sys
items = [json.loads(line) for line in sys.stdin if line.strip()]
print(json.dumps(items, indent=2))
"
        else
                echo "["
                for i in "${!results[@]}"; do
                        echo "  ${results[$i]}"$([[ $i -lt $((${#results[@]} - 1)) ]] && echo ",")
                done
                echo "]"
        fi
fi
