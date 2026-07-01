# Hardware detection and configuration

millipede-caster is a pure NTRIP relay — it does not manage the GNSS
receiver itself. For deployments where the caster runs on the same host
as the receiver (e.g. a Raspberry Pi base station), a pair of companion
scripts in `tools/` help with receiver detection and configuration.

## Supported receivers

| Vendor      | Models              | Protocol | Detection method          |
|-------------|---------------------|----------|---------------------------|
| U-blox      | ZED-F9P, F9R, F9H   | UBX      | USB ID 1546:01a7/01a8/01a9 + UBX-MON-VER probe |
| Septentrio  | mosaic-X5, mosaicGo | SBF/ASCII| USB ID 09d7:0200/0300 + `exePrintVersion` probe |
| Unicore     | UM980, UM982        | ASCII    | USB ID 1d00:2010/2011 + `version` probe |

## Detecting receivers

```sh
# Auto-probe all /dev/ttyUSB*, /dev/ttyACM*, /dev/serial/by-id/*
./tools/detect_receiver.sh

# Also probe a TCP-attached receiver (e.g. an NTRIP source)
./tools/detect_receiver.sh --tcp 192.168.1.50:5050

# Verbose mode (logs probing steps on stderr)
./tools/detect_receiver.sh --verbose
```

Output is a JSON array on stdout:

```json
[
  {
    "device": "/dev/ttyACM0",
    "vendor_id_guess": "U-blox ZED-F9P",
    "model": "ZED-F9P (FW 1.32 HW 00040000)",
    "baudrate": 115200,
    "protocol": "UBX"
  }
]
```

## Configuring a receiver

```sh
# Apply a standard 1 Hz RTCM3 base configuration to an F9P
./tools/configure_receiver.sh --device /dev/ttyACM0 --type ublox-f9p

# Apply to a Septentrio mosaic-X5
./tools/configure_receiver.sh --device /dev/ttyACM0 --type septentrio-mosaic

# Apply to a Unicore UM980
./tools/configure_receiver.sh --device /dev/ttyUSB0 --type unicore-um980

# Custom RTCM rate (5 Hz)
./tools/configure_receiver.sh --device /dev/ttyACM0 --type ublox-f9p --rtcm-hz 5
```

The configuration scripts apply a sensible default for an RTK base station:
- RTCM3 output at the requested rate
- Standard message set: 1005 (station position), 1074/1084/1094/1124 (MSM4
  for GPS/GLO/GAL/BDS), 1230 (GLONASS code biases)
- For U-blox: saved to flash (UBX-CFG-CFG with deviceMask=BBR+flash)
- For Septentrio: `saveConfig`
- For Unicore: `saveconfig`

## Verification

After configuration, you can verify the receiver is emitting RTCM at the
expected rate by querying the caster's RTCM frequency tracker:

```sh
curl -u "admin:admin" http://localhost:2101/adm/api/v1/rtcm/frequencies
```

Expected output (1 Hz base):
```json
{
  "MYBASE": {
    "1005": { "rate_hz": 0.2, "total": 12, ... },
    "1074": { "rate_hz": 1.0, "total": 60, ... },
    "1084": { "rate_hz": 1.0, "total": 60, ... },
    ...
  }
}
```

If `rate_hz` is much lower than expected, the receiver is not configured
correctly. If `rate_hz` is 0, the receiver is not sending RTCM at all
(check serial connection, baud rate, power supply).

## Pairing with the caster

A typical deployment on a Raspberry Pi:

1. Connect the receiver via USB.
2. Run `detect_receiver.sh` to confirm the device path and baud rate.
3. Run `configure_receiver.sh` to apply the RTCM3 base configuration.
4. Configure the caster with a `ntripsrv` source that reads from the
   serial port:

   ```yaml
   # In caster.yaml (alternative: use str2str as a relay)
   # Actually, millipede-caster doesn't read from serial directly.
   # Use str2str (from RTKLIB) to bridge serial → caster:
   #   str2str -in serial://ttyACM0:115200 -out ntrips://:password@localhost:2101/MYBASE
   ```

5. Verify with the frequency tracker endpoint.

## Comparison with RTKBase

These scripts are intentionally minimal — they handle **detection** and
**base configuration** only. They do NOT provide:
- A web UI for receiver configuration (use RTKBase for that)
- Receiver firmware updates
- NTRIP client / rover configuration
- PPK / RINEX recording

For a full-featured base station management UI, see [RTKBase](https://github.com/Stefal/rtkbase).
