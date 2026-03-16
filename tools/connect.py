#!/usr/bin/env python3
"""
connect.py — CLI tool: attempt session probe against the camera.

Sends discovery + speculative session commands directly to the camera IP
and records every byte the camera responds with. Output is saved to
output/session_probe_<ts>.json for analysis.

Usage:
  python3 tools/connect.py
  python3 tools/connect.py --ip 192.168.1.122 --port 32108

What to look for in the output:
  - Any response to f1 36 (discovery) — confirms camera hears us
  - Any response to f1 00 (hello spec) — may contain session token
  - Response cmd byte — tells us what the camera expects next
  - Response payload — may reveal full UID, auth challenge, or stream params
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.session import SessionProbe
from client.protocol import CAMERA_IP, CAMERA_PORT


def main():
    parser = argparse.ArgumentParser(description="Session probe — 0xf1 P2P camera")
    parser.add_argument("--ip",   type=str,   default=CAMERA_IP,   help="Camera IP")
    parser.add_argument("--port", type=int,   default=CAMERA_PORT, help="Camera port")
    parser.add_argument("--out",  type=str,   default="output",    help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print(" IoT Camera Client — Session Probe")
    print(f" Target : {args.ip}:{args.port}")
    print(" Scope  : owned device, lab network, lawful analysis only")
    print("=" * 60)

    probe  = SessionProbe(ip=args.ip, port=args.port, verbose=True)
    events = probe.run()

    path = probe.save(args.out)
    print(f"\n Full event log saved to: {path}")

    # Summary
    sends  = [e for e in events if e["direction"] == "send"]
    recvs  = [e for e in events if e["direction"] == "recv"]

    print(f"\n {'='*56}")
    print(f"  Packets sent    : {len(sends)}")
    print(f"  Responses recvd : {len(recvs)}")

    if recvs:
        print(f"\n  Camera responses:")
        for r in recvs:
            cmd  = r.get("cmd", "?")
            plen = len(bytes.fromhex(r.get("payload", "")))
            print(f"    [{r['src']}] cmd={cmd} payload_len={plen}  raw={r['raw']}")
        print()
        print("  NEXT STEP:")
        print("  Examine the response payload(s) above.")
        print("  Each byte tells us more about the handshake sequence.")
        print(f"  Full detail: {path}")
    else:
        print()
        print("  No camera responses.")
        print("  Try running with the phone app open — the camera may only")
        print("  respond while actively registered with the relay.")

    print(f" {'='*56}")


if __name__ == "__main__":
    main()
