#!/usr/bin/env python3
"""
discover.py — CLI tool: broadcast discovery and collect camera responses.

Usage:
  python3 tools/discover.py
  python3 tools/discover.py --timeout 15
  python3 tools/discover.py --iface 192.168.1.212

Opens a UDP socket, sends the exact discovery + ping packets observed from
the phone app, and prints everything the camera sends back.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.discovery import discover, save_results
from client.protocol import CAMERA_IP, CAMERA_PORT, DISCOVERY_PORT


def main():
    parser = argparse.ArgumentParser(description="Discover IoT camera via 0xf1 broadcast")
    parser.add_argument("--timeout",  type=float, default=10.0, help="Seconds to listen (default: 10)")
    parser.add_argument("--interval", type=float, default=2.0,  help="Seconds between re-broadcasts (default: 2)")
    parser.add_argument("--iface",    type=str,   default="0.0.0.0", help="Interface IP to bind")
    parser.add_argument("--out",      type=str,   default="output",  help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print(" IoT Camera Client — Discovery")
    print(f" Camera IP   : {CAMERA_IP}:{CAMERA_PORT}")
    print(f" Broadcast   : 255.255.255.255:{DISCOVERY_PORT}")
    print(f" Timeout     : {args.timeout}s")
    print("=" * 60)
    print()
    print(" Tip: For best results, have the camera app open on your phone.")
    print(" The camera is most responsive just after the app connects.")
    print()

    responses = discover(
        iface_ip=args.iface,
        timeout=args.timeout,
        interval=args.interval,
        verbose=True,
    )

    print(f"\n{'='*60}")
    print(f" Discovery complete — {len(responses)} unique response(s) received.")

    if responses:
        path = save_results(responses, args.out)
        print(f" Saved to: {path}")
        print()
        print(" Response summary:")
        for r in responses:
            src   = f"{r['src_ip']}:{r['src_port']}"
            cmd   = r.get("parsed", {}).get("cmd", "?")
            plen  = r.get("parsed", {}).get("payload_len", "?")
            print(f"   {src}  cmd={cmd}  payload_len={plen}  raw={r['raw_hex'][:40]}...")
    else:
        print()
        print(" No responses. Possible reasons:")
        print("   - Camera requires phone app to be open/active")
        print("   - Discovery filter: camera may require exact UID match")
        print("   - Interface issue: try --iface 192.168.1.212")
        print()
        print(" Try:")
        print("   1. Open camera app on phone")
        print("   2. Run this tool again immediately")

    print("=" * 60)


if __name__ == "__main__":
    main()
