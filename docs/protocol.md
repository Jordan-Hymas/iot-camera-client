# 0xf1 P2P Protocol — Research Notes

All findings are derived from passive capture of owned devices on a controlled
lab network. Evidence chain is in the `iot-camera-packet-analysis` repo.

---

## Protocol Family

Magic byte: `0xf1`
Consistent with a family of P2P protocols (sometimes called PPPP or CS2)
used across many Chinese IoT camera manufacturers. Operates over UDP.

## Packet Format

```
Byte  0:    0xf1        magic (always)
Byte  1:    cmd         command code (1 byte)
Bytes 2-3:  length      payload byte count, big-endian uint16
Bytes 4+:   payload     variable length
```

Total minimum packet: 4 bytes (header only, no payload).

## Confirmed Command Codes

| Code | Direction | Description |
|------|-----------|-------------|
| `0x10` | Camera → Relay | Relay registration: announces local IP + port to relay servers |
| `0x30` | Phone → Broadcast | Keepalive ping (no payload) |
| `0x36` | Phone → Broadcast | LAN discovery: "camera, are you here?" |

## Speculative Command Codes (NOT confirmed from capture)

Standard in the 0xf1 protocol family — included for probing:

| Code | Probable Role |
|------|---------------|
| `0x00` | HELLO — initial session open |
| `0x08` | HELLO_ACK — acknowledge HELLO |
| `0x20` | PUNCH — NAT hole-punch packet |
| `0x28` | PUNCH_ACK — acknowledge punch |
| `0xf0` | CLOSE — close session |

## Device Identity Block (bytes 4–23 of all observed packets)

```
Bytes  4-11:  46 54 59 44 00 00 00 00    "FTYD\x00\x00\x00\x00"  UID prefix
Bytes 12-15:  00 0b 90 0e                 (binary)                MAC suffix
Bytes 16-23:  49 43 4f 53 4e 00 00 00    "ICOSN\x00\x00\x00"     Brand string
```

Full MAC of camera: `50:49:56:0B:90:0E` — last 3 bytes are `0b:90:0e`.

## Relay Registration Packet (cmd 0x10) Extra Fields

```
Bytes 24-27:  08 00 02 01    Probable firmware version: 8.0.2.1
Bytes 28-29:  00 00          Padding
Bytes 30-31:  6c 7d          Local port: 32108 (little-endian uint16)
Bytes 32-35:  7a 01 a8 c0    Local IP: 192.168.1.122 (little-endian)
Bytes 36-43:  00 * 8         Padding
```

## Exact Observed Packets (ground truth)

Phone discovery broadcast:
```
f13600144654594400000000000b900e49434f534e000000
```

Phone keepalive ping:
```
f1300000
```

Camera relay registration:
```
f11000284654594400000000000b900e49434f534e0000000800020100006c7d7a01a8c00000000000000000
```

## Behavior Observed

1. Phone broadcasts `f1 36` to `255.255.255.255:32108` approximately every 7s
2. Camera responds to discovery by sending `f1 10` to all three relay servers
3. Camera sends relay keepalive every ~8 seconds independent of phone activity
4. No direct camera→phone response observed — all coordination via relay
5. UDP port 32108 on camera is `open|filtered` (listens but filters unexpected senders)

## Relay Servers

| IP | Port | Provider |
|----|------|----------|
| `146.56.226.66` | 32100 | Alibaba Cloud |
| `170.106.50.82` | 32100 | Alibaba Cloud |
| `35.156.204.247` | 32100 | AWS eu-central-1 |

## Open Questions

1. **Full UID** — "FTYD" is the confirmed prefix. Full format unknown.
   Check camera app Settings → Device Info for the UID string.

2. **"ICOSN" brand string** — not a known retail brand. Likely an OEM or SDK vendor.

3. **Authentication** — unknown. Relay traffic is opaque binary with no TLS SNI.

4. **Video stream command** — unknown. Requires session establishment + further capture.

5. **Direct local video** — camera may support local streaming once a session is
   established (bypassing relay), but this has not been confirmed.

## Path to Live Video

Based on current knowledge, the minimum required steps are:

1. Establish a session with the camera (send `f1 36` or `f1 00`, get response)
2. Identify and handle the authentication step (if any)
3. Send the AV channel open command (format unknown — needs capture)
4. Receive and decode the video stream

Step 1 is achievable now. Steps 2-4 require observing the camera's responses
and iterating. Running `tools/connect.py` with the phone app open is the
most likely way to get step 1 working.
