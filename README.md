# iot-camera-client

Local P2P client for an IoT camera, built from lawful passive traffic analysis.
Owned device, controlled lab network. No exploitation.

**Analysis repo:** `iot-camera-packet-analysis`
**Ground truth:** `confirmed_facts.md` in analysis repo

---

## Camera Identity

| Field | Value | Source |
|---|---|---|
| IP | `192.168.1.122` | ARP / capture |
| MAC | `50:49:56:0B:90:0E` | nmap |
| Full UID | `FTYD757774ICOSN` | QR code |
| Username | `admin` | QR code |
| Password | `admin` | QR code |
| QR format | `3;{UID};{user};{pass}` | QR code |
| UID formula | `FTYD` + `decimal(uint24(mac_last3))` + `ICOSN` | reverse-engineered |
| Local port | `32108` UDP | capture |
| Relay port | `32100` UDP | capture |

**Relay servers (camera contacts all three simultaneously):**

| IP | Provider |
|---|---|
| `146.56.226.66:32100` | Alibaba Cloud |
| `170.106.50.82:32100` | Alibaba Cloud |
| `35.156.204.247:32100` | AWS eu-central-1 |

---

## Protocol

Magic byte `0xf1`, 4-byte header: `[magic][cmd][len_hi][len_lo][payload]`

| Cmd | Direction | Payload | Status |
|---|---|---|---|
| `0x10` | camera → relay | identity + local IP:port (little-endian) | Confirmed |
| `0x21` | camera → client | `fc000000` | Confirmed |
| `0x30` | client → camera | empty | Confirmed |
| `0x36` | client → camera | DEVICE_IDENTITY (20 bytes) | Confirmed |
| `0x41` | camera → client | DEVICE_IDENTITY (20 bytes) | Confirmed |
| `0x42` | phone → camera | DEVICE_IDENTITY (20 bytes) | Confirmed |
| `0x43` | camera → phone | unknown | Speculative — tried, did not advance session |

**Architecture:** Relay-only. Zero open TCP ports confirmed (no RTSP, HTTP, ONVIF locally).
All video goes through the cloud relay servers on port 32100.

---

## Current Status

| Component | Status |
|---|---|
| Protocol constants | Confirmed from capture |
| Discovery `0x36` + ping `0x30` | Confirmed working |
| Local session handshake | Partial — confirmed through `0x42`, correct response unknown |
| Relay probe | Implemented — **run this next** |
| Video stream | Blocked — needs relay session data |

---

## Setup

```bash
python3 --version   # requires 3.10+
# no dependencies — stdlib only
```

---

## Usage

### 1. Discover camera on LAN

```bash
python3 tools/discover.py
```

### 2. Local session probe (direct to camera)

```bash
python3 tools/connect.py
```

Sends discovery + speculative session commands to the camera. Output saved to `output/`.

### 3. Relay probe — primary path to video

```bash
# Single relay (default: 146.56.226.66)
python3 tools/relay.py

# All three relay servers
python3 tools/relay.py --all
```

Sends the full relay handshake with UID `FTYD757774ICOSN` and `admin`/`admin` credentials.

What to look for in the output:
- `cmd=0x08` — relay acknowledged hello
- `cmd=0x1c` — auth succeeded
- `cmd=0xd8` — AV channel opened (payload will contain stream parameters)

### 4. Camera emulator / phone intercept

```bash
python3 tools/intercept.py --duration 60
```

Emulates the camera to capture what the phone app sends after the handshake.
Open the camera app on the phone while this is running.

---

## Project Structure

```
client/
  protocol.py    — packet constants, Packet class, confirmed payloads
  discovery.py   — LAN broadcast discovery
  session.py     — local session probe (confirmed + speculative steps)
  relay.py       — relay server probe with UID and credentials
  stream.py      — placeholder (blocked on relay session data)
tools/
  discover.py    — CLI: LAN discovery broadcast
  connect.py     — CLI: local session probe
  relay.py       — CLI: relay server probe (run this next)
  intercept.py   — CLI: camera emulator, captures phone AV request
docs/
  protocol.md    — full protocol documentation with hex evidence
output/          — JSON results from all probe runs
```

---

## Path to Live Video

The camera is relay-only. The path:

1. **Run** `python3 tools/relay.py --all` — probe relay servers with credentials
2. **Examine** `output/relay_probe_<ts>.json` — look for auth ACK and stream parameters
3. If no relay response: capture port 32100 traffic while phone is in live view, decode the sequence
4. **Implement** `client/stream.py` once relay session and stream command format is known

---

## Legal

Owned devices only. Lab network `iot-network`. No exploitation, no credential attacks,
no third-party systems targeted.
