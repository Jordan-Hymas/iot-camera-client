#!/usr/bin/env python3
"""
relay.py — CLI tool: probe the cloud relay servers with camera credentials.

Sends the full relay handshake sequence to each relay server and records
every response. Output is saved to output/relay_probe_<ts>.json.

Usage:
  python3 tools/relay.py
  python3 tools/relay.py --relay 146.56.226.66
  python3 tools/relay.py --all

What to look for in the output:
  - Any response to f1 10 (connect) — relay may ACK or send a ticket
  - Any response to f1 14 (auth) — auth success/failure indicator
  - Response to f1 d0 (AV open) — stream parameters or redirect
  - Cmd 0x08 or 0x1c — expected ack codes for hello and auth
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.relay import RelayProbe, CAMERA_UID, CAMERA_USERNAME, CAMERA_PASSWORD_MD5
from client.protocol import RELAY_SERVERS, RELAY_PORT


def probe_one(ip: str, port: int, out_dir: str) -> None:
    probe  = RelayProbe(relay_ip=ip, relay_port=port, verbose=True)
    events = probe.run()
    path   = probe.save(out_dir)
    print(f"\n Full event log: {path}")

    recvs = [e for e in events if e["direction"] == "recv"]
    if recvs:
        print(f"\n  *** {len(recvs)} relay response(s) — examine for auth/stream clues ***")
        for e in recvs:
            cmd  = e.get("cmd", "?")
            plen = len(bytes.fromhex(e.get("payload", ""))) if "payload" in e else 0
            print(f"    cmd={cmd} payload_len={plen}  raw={e['raw']}")
    else:
        print("\n  No relay responses received.")
        print("  The relay may require the camera to be online and registered.")


def main():
    parser = argparse.ArgumentParser(description="Relay probe — 0xf1 P2P relay server")
    parser.add_argument("--relay", type=str, default=RELAY_SERVERS[0],
                        help=f"Relay IP (default: {RELAY_SERVERS[0]})")
    parser.add_argument("--port",  type=int, default=RELAY_PORT,
                        help=f"Relay port (default: {RELAY_PORT})")
    parser.add_argument("--all",   action="store_true",
                        help="Probe all three relay servers")
    parser.add_argument("--out",   type=str, default="output",
                        help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print(" IoT Camera Client — Relay Probe")
    print(f" Camera UID  : {CAMERA_UID}")
    print(f" Username    : {CAMERA_USERNAME}")
    print(f" PW MD5      : {CAMERA_PASSWORD_MD5}")
    print(" Scope       : owned device, lawful analysis only")
    print("=" * 60)

    targets = RELAY_SERVERS if args.all else [args.relay]
    for ip in targets:
        print(f"\n{'─'*60}")
        print(f" Target: {ip}:{args.port}")
        print(f"{'─'*60}")
        probe_one(ip, args.port, args.out)


if __name__ == "__main__":
    main()
