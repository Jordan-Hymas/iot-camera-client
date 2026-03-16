# iot-camera-client

Local P2P client for IoT camera at `192.168.1.122`, built from lawful
passive traffic analysis. Owned device, controlled lab network.

**Analysis repo:** `iot-camera-packet-analysis` (see `confirmed_facts.md`)

---

## Status

| Component | Status |
|---|---|
| Protocol constants | Confirmed from capture |
| Discovery (f1 36 broadcast) | Implemented — high confidence |
| Session probe (f1 00 hello) | Implemented — speculative |
| Video stream | Blocked — needs session data |

---

## What We Know

Camera speaks the `0xf1` P2P protocol over UDP:

- **Discovery port:** `192.168.1.122:32108` UDP
- **Relay port:** `32100` UDP (contacts Alibaba Cloud + AWS relay servers)
- **Magic byte:** `0xf1`
- **Device identity string:** `FTYD` (UID prefix) + MAC suffix + `ICOSN` (brand)
- **No open TCP ports** — no local RTSP, HTTP, or ONVIF

See `docs/protocol.md` for full packet-level documentation.

---

## Setup

```bash
python3 --version   # requires 3.10+
# no dependencies — stdlib only
```

---

## Usage

### 1. Discover the camera on your LAN

```bash
python3 tools/discover.py
```

Sends the exact discovery broadcast observed from the phone app and
prints any response from the camera.

**Tip:** Open the camera app on your phone first — the camera is most
responsive while the app is actively connected.

### 2. Attempt session probe

```bash
python3 tools/connect.py
```

Sends discovery + speculative session commands directly to the camera
and records every byte in the response. Output saved to `output/`.

### 3. Review results

```bash
cat output/session_probe_<ts>.json
cat output/discovery_<ts>.json
```

Each camera response reveals more about the handshake sequence.

---

## Project Structure

```
client/
  __init__.py
  protocol.py    — packet constants, Packet class, confirmed payloads
  discovery.py   — LAN broadcast discovery
  session.py     — session probe (sends known + speculative commands)
  stream.py      — placeholder (blocked on session data)
tools/
  discover.py    — CLI: discovery broadcast
  connect.py     — CLI: session probe
docs/
  protocol.md    — protocol documentation and evidence
output/          — JSON results from discovery + session runs
```

---

## Getting to Live Video

We have enough to attempt the first step (making the camera respond).
The full path requires iterating on what the camera responds with:

1. **Run** `tools/connect.py` — with phone app open
2. **Examine** `output/session_probe_<ts>.json` — look at camera response payloads
3. **Update** `client/session.py` with what the next handshake step should be
4. **Repeat** until a session is established
5. **Implement** `client/stream.py` once stream command format is known

---

## Scope and Legal

- Targets only `192.168.1.122` — owned device
- Lab network `iot-network` — controlled environment
- No credential attacks, no exploitation, no third-party systems
- Clean-room implementation based on observed protocol behavior
