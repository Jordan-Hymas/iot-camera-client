"""
discovery.py — Local LAN camera discovery

Replicates the exact UDP broadcast sequence observed from the phone app.
Sends cmd 0x36 (discovery) + cmd 0x30 (ping) to 255.255.255.255:32108
and listens for camera responses.

Also sends directly to the known camera IP as a fallback.
"""

import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from .protocol import (
    BROADCAST_ADDR,
    CAMERA_IP,
    CAMERA_PORT,
    DISCOVERY_PORT,
    Packet,
    describe,
    make_discovery_packet,
    make_ping_packet,
)


def discover(
    iface_ip: str = "0.0.0.0",
    timeout: float = 10.0,
    interval: float = 2.0,
    verbose: bool = True,
) -> list[dict]:
    """
    Broadcast discovery packets and collect responses.

    Args:
        iface_ip:  Local interface IP to bind (0.0.0.0 = any)
        timeout:   Total seconds to listen
        interval:  Seconds between re-broadcasts
        verbose:   Print live output

    Returns:
        List of response dicts with timestamp, src, raw hex, and parsed fields.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)

    # Try to bind to the discovery port so the camera can reach us directly.
    # Falls back to ephemeral port if already in use.
    try:
        sock.bind((iface_ip, DISCOVERY_PORT))
        if verbose:
            print(f"[*] Bound to :{DISCOVERY_PORT}")
    except OSError:
        sock.bind((iface_ip, 0))
        bound_port = sock.getsockname()[1]
        if verbose:
            print(f"[WARN] Port {DISCOVERY_PORT} busy, using :{bound_port}")

    disc_pkt = make_discovery_packet()
    ping_pkt = make_ping_packet()

    if verbose:
        print(f"[*] Discovery packet : {disc_pkt.encode().hex()}")
        print(f"[*] Ping packet      : {ping_pkt.encode().hex()}")
        print(f"[*] Broadcasting to  : {BROADCAST_ADDR}:{DISCOVERY_PORT}")
        print(f"[*] Also targeting   : {CAMERA_IP}:{CAMERA_PORT} (direct)")
        print(f"[*] Listening for {timeout}s...")
        print()

    responses = []
    seen = set()
    deadline  = time.time() + timeout
    last_send = 0.0

    while time.time() < deadline:
        # Re-broadcast on interval
        if time.time() - last_send >= interval:
            for dest in [
                (BROADCAST_ADDR, DISCOVERY_PORT),
                (CAMERA_IP,      CAMERA_PORT),
            ]:
                sock.sendto(disc_pkt.encode(), dest)
                sock.sendto(ping_pkt.encode(), dest)
            last_send = time.time()
            if verbose:
                remaining = int(deadline - time.time())
                print(f"  [send] Discovery + ping broadcast  ({remaining}s remaining)")

        # Receive
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue

        # Ignore our own broadcasts reflected back
        src_ip = addr[0]
        if src_ip in ("0.0.0.0", "127.0.0.1", iface_ip):
            continue

        key = (src_ip, data.hex())
        duplicate = key in seen
        seen.add(key)

        ts = datetime.now(tz=timezone.utc).isoformat()

        entry: dict = {
            "timestamp": ts,
            "src_ip":    src_ip,
            "src_port":  addr[1],
            "raw_hex":   data.hex(),
            "length":    len(data),
            "duplicate": duplicate,
        }

        # Parse
        try:
            pkt = Packet.decode(data)
            entry["parsed"] = {
                "cmd":         f"0x{pkt.cmd:02x}",
                "payload_len": len(pkt.payload),
                "payload_hex": pkt.payload.hex(),
            }
        except Exception as e:
            entry["parse_error"] = str(e)

        responses.append(entry)

        if verbose and not duplicate:
            print(f"\n  [recv] {src_ip}:{addr[1]}")
            print(f"         raw : {data.hex()}")
            print(f"         desc: {describe(data)}")

    sock.close()
    return [r for r in responses if not r["duplicate"]]


def save_results(responses: list[dict], out_dir: str = "output") -> Path:
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    ts  = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = out / f"discovery_{ts}.json"
    path.write_text(json.dumps(responses, indent=2))
    return path
