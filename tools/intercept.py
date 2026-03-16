#!/usr/bin/env python3
"""
intercept.py — Camera emulator / AV session interceptor

What this does:
  1. Sends f1 10 (P2P_RDY) to camera to register our address with the relay
  2. Sends f1 20 (PUNCH) to camera to trigger the relay to notify the phone
  3. Listens for the phone's connection attempt (f1 36 + f1 30)
  4. Responds to the phone AS IF we are the camera:
       f1 36 (phone discovery) → we reply f1 21 + fc000000
       f1 30 (phone ping)      → we reply f1 41 + device identity
  5. Records EVERYTHING the phone sends after that — specifically looking for
     the AV session open command, which will tell us the stream request format.

Why this works:
  Observed in session probe: after f1 20 (PUNCH), the phone sent us
  f1 36 + f1 30 from ephemeral ports. The relay told the phone our address.
  If we complete the handshake the phone expects, it will send the next
  protocol message — the AV stream request — which is the format we need.

Usage:
  python3 tools/intercept.py              # run with phone app open
  python3 tools/intercept.py --duration 30

Output:
  output/intercept_<ts>.json   — all captured packets
  Prints any unknown packet the phone sends (potential AV request)

Scope: owned devices, controlled lab network. No exploitation.
"""

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.protocol import (
    CAMERA_IP,
    CAMERA_PORT,
    DEVICE_IDENTITY,
    Packet,
    CMD_DISCOVERY,
    CMD_DISCOVERY_ACK,
    CMD_PING,
    CMD_PING_ACK,
    CMD_RELAY_REGISTER,
    CMD_PUNCH_SPEC,
    DISCOVERY_ACK_PAYLOAD,
    describe,
    make_discovery_packet,
    make_ping_packet,
)

LOCAL_IP   = "192.168.1.212"
LOCAL_PORT = 32108
PHONE_IP   = "192.168.1.241"


def encode_ip_port(ip: str, port: int) -> bytes:
    parts  = [int(x) for x in ip.split(".")]
    ip_le  = bytes(reversed(parts))
    port_le = struct.pack("<H", port)
    return port_le + b"\x00\x00" + ip_le


def ts() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description="Camera emulator — capture AV session request")
    parser.add_argument("--duration", type=int,   default=60,    help="Seconds to run (default: 60)")
    parser.add_argument("--out",      type=str,   default="output", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    run_ts  = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    events: list[dict] = []

    # -----------------------------------------------------------------------
    # Socket setup — bind to port 32108 so phone can reach us
    # -----------------------------------------------------------------------
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.2)

    try:
        sock.bind(("0.0.0.0", LOCAL_PORT))
        print(f"[*] Bound to 0.0.0.0:{LOCAL_PORT}")
    except OSError as e:
        print(f"[!] Could not bind to port {LOCAL_PORT}: {e}")
        print(f"    Another process may hold it. Run: sudo lsof -i UDP:{LOCAL_PORT}")
        sys.exit(1)

    print("=" * 60)
    print(" IoT Camera — Intercept / AV Session Capture")
    print(f" Emulating camera at  : {LOCAL_IP}:{LOCAL_PORT}")
    print(f" Real camera          : {CAMERA_IP}:{CAMERA_PORT}")
    print(f" Watching for phone   : {PHONE_IP}")
    print(f" Duration             : {args.duration}s")
    print("=" * 60)
    print()
    print(" Step 1: Registering with relay via camera")
    print(" Step 2: Triggering phone notification")
    print(" Step 3: Responding to phone as camera")
    print(" Step 4: Capturing AV session request")
    print()

    def log_event(direction, src_or_dst, pkt=None, raw=None, note=""):
        entry = {
            "ts":        ts(),
            "direction": direction,
            "addr":      src_or_dst,
            "raw":       raw.hex() if raw else (pkt.encode().hex() if pkt else ""),
            "note":      note,
        }
        if pkt:
            entry["cmd"]     = f"0x{pkt.cmd:02x}"
            entry["payload"] = pkt.payload.hex()
        events.append(entry)
        return entry

    def send(pkt: Packet, dest, note=""):
        data = pkt.encode()
        sock.sendto(data, dest)
        log_event("send", f"{dest[0]}:{dest[1]}", pkt=pkt, note=note)
        print(f"  --> {dest[0]}:{dest[1]}  {describe(data)}  {('| ' + note) if note else ''}")

    def recv_one():
        try:
            data, addr = sock.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None

    # -----------------------------------------------------------------------
    # Phase 1: Register our address with the camera and trigger phone notify
    # -----------------------------------------------------------------------
    print("[Phase 1] Registering our address with camera/relay...")

    ip_port_payload = encode_ip_port(LOCAL_IP, LOCAL_PORT)
    reg_payload     = DEVICE_IDENTITY + b"\x08\x00\x02\x01" + ip_port_payload + b"\x00" * 8
    reg_pkt         = Packet(CMD_RELAY_REGISTER, reg_payload)
    punch_pkt       = Packet(CMD_PUNCH_SPEC, DEVICE_IDENTITY)

    # Send registration to camera
    send(reg_pkt,   (CAMERA_IP, CAMERA_PORT), note="Register our IP:port with relay")
    time.sleep(0.3)

    # Send discovery to camera (warm up)
    send(make_discovery_packet(), (CAMERA_IP, CAMERA_PORT), note="Discovery warm-up")
    time.sleep(0.3)

    # Send punch to camera — this triggers relay to notify phone
    send(punch_pkt, (CAMERA_IP, CAMERA_PORT), note="PUNCH → relay notifies phone")
    time.sleep(0.3)

    print()
    print("[Phase 2] Listening for phone connection + responding as camera...")
    print("          Open the camera app on your phone NOW if not already open.")
    print()

    # -----------------------------------------------------------------------
    # Phase 2: Respond to phone, capture everything
    # -----------------------------------------------------------------------
    deadline      = time.time() + args.duration
    punch_interval = 5.0   # Re-send punch to camera every N seconds to keep relay alive
    last_punch     = time.time()
    phone_sessions: dict = {}   # track unique phone source ports
    av_candidates:  list  = []  # packets that look like AV/session requests

    while time.time() < deadline:
        remaining = int(deadline - time.time())

        # Re-send punch periodically to keep relay notified
        if time.time() - last_punch >= punch_interval:
            send(punch_pkt,          (CAMERA_IP, CAMERA_PORT), note="Keepalive punch")
            send(make_ping_packet(), (CAMERA_IP, CAMERA_PORT), note="Keepalive ping to camera")
            last_punch = time.time()

        data, addr = recv_one()
        if data is None or addr is None:
            continue

        src_ip, src_port = addr

        # Parse
        pkt = None
        try:
            pkt = Packet.decode(data)
        except Exception:
            pass

        cmd = pkt.cmd if pkt else None

        # Ignore our own reflections
        if src_ip == LOCAL_IP:
            continue

        log_event("recv", f"{src_ip}:{src_port}", pkt=pkt, raw=data,
                  note="camera" if src_ip == CAMERA_IP else "phone" if src_ip == PHONE_IP else "unknown")

        # ----------------------------------------------------------------
        # Handle camera responses
        # ----------------------------------------------------------------
        if src_ip == CAMERA_IP:
            if cmd == 0x21:
                print(f"  <-- camera  f1 21 DISCOVERY_ACK  payload={pkt.payload.hex()}")
            elif cmd == 0x41:
                print(f"  <-- camera  f1 41 PING_ACK  (alive)")
            else:
                print(f"  <-- camera  {describe(data)}")
            continue

        # ----------------------------------------------------------------
        # Handle phone / unknown source responses
        # ----------------------------------------------------------------
        label = "phone" if src_ip == PHONE_IP else f"unknown({src_ip})"

        if cmd == CMD_DISCOVERY:
            # Phone is discovering us — respond as camera
            print(f"  <-- {label}:{src_port}  f1 36 DISCOVERY  → responding with f1 21")
            ack = Packet(CMD_DISCOVERY_ACK, DISCOVERY_ACK_PAYLOAD)
            send(ack, (src_ip, src_port), note="Camera emulator: discovery ack")
            phone_sessions[src_port] = {"discovered": True, "av_requested": False}

        elif cmd == CMD_PING:
            # Phone is pinging us — respond as camera
            print(f"  <-- {label}:{src_port}  f1 30 PING  → responding with f1 41")
            pong = Packet(CMD_PING_ACK, DEVICE_IDENTITY)
            send(pong, (src_ip, src_port), note="Camera emulator: ping ack")

        else:
            # Anything that is NOT a discovery or ping from the phone is a new protocol message
            # This is what we're hunting for — the AV session request
            print()
            print(f"  *** NEW PACKET from {label}:{src_port} ***")
            print(f"      cmd     : 0x{cmd:02x}" if cmd else f"      raw     : {data.hex()}")
            print(f"      payload : {pkt.payload.hex()}" if pkt else f"      raw     : {data.hex()}")
            print(f"      length  : {len(data)}")
            print(f"      desc    : {describe(data)}")
            print()
            av_candidates.append({
                "src": f"{src_ip}:{src_port}",
                "raw": data.hex(),
                "cmd": f"0x{cmd:02x}" if cmd else None,
                "payload": pkt.payload.hex() if pkt else None,
                "note": "POTENTIAL AV SESSION REQUEST",
            })

    # -----------------------------------------------------------------------
    # Save and summarise
    # -----------------------------------------------------------------------
    sock.close()

    out_path = out_dir / f"intercept_{run_ts}.json"
    out_path.write_text(json.dumps({
        "run_ts":        run_ts,
        "duration":      args.duration,
        "phone_sessions": phone_sessions,
        "av_candidates": av_candidates,
        "events":        events,
    }, indent=2))

    print()
    print("=" * 60)
    print(f" Intercept complete.")
    print(f"   Total events    : {len(events)}")
    print(f"   Phone sessions  : {len(phone_sessions)}")
    print(f"   AV candidates   : {len(av_candidates)}")
    print(f"   Saved to        : {out_path}")

    if av_candidates:
        print()
        print(" *** AV SESSION CANDIDATES (stream request format) ***")
        for c in av_candidates:
            print(f"   src     : {c['src']}")
            print(f"   cmd     : {c['cmd']}")
            print(f"   payload : {c['payload']}")
            print(f"   raw     : {c['raw']}")
            print()
    else:
        print()
        print(" No AV candidates captured yet.")
        print(" Try:")
        print("   1. Run again with phone app already on live view screen")
        print("   2. Increase --duration to 120")
        print("   3. While running, open live view in the phone app")

    print("=" * 60)


if __name__ == "__main__":
    main()
