#!/usr/bin/env python3
"""
stream.py — CLI: connect to camera and receive MJPEG frames.

Implements the full P2P viewer handshake confirmed from iPhone rvi0 capture
on 2026-03-16. All video traffic is direct LAN UDP — no cloud relay needed
for video once the session is established.

Usage:
  # Save frames as JPEG files:
  python3 tools/stream.py --frames-dir ./frames

  # Raw MJPEG to stdout (pipe to ffplay):
  python3 tools/stream.py --mjpeg-out | ffplay -f mjpeg -

  # Serve MJPEG over HTTP (open http://localhost:8080 in browser):
  python3 tools/stream.py --http 8080

  # Grab first 10 frames then stop:
  python3 tools/stream.py --frames-dir ./frames --count 10

  # Skip relay lookup (use configured camera IP directly):
  python3 tools/stream.py --skip-relay --frames-dir ./frames

Options:
  --camera IP      Camera IP  (default: 192.168.1.157)
  --port PORT      Camera UDP port  (default: 32108)
  --relay IP       Relay server IP  (default: 146.56.226.66)
  --skip-relay     Skip relay PUNCH, go direct to camera
  --frames-dir DIR Save each JPEG frame as frames/frame_NNNN.jpg
  --mjpeg-out      Write raw MJPEG stream to stdout (for piping)
  --http PORT      Serve MJPEG over HTTP on localhost:PORT
  --count N        Stop after N frames (0 = unlimited)
  --timeout SECS   Socket receive timeout  (default: 5)
  --quiet          Suppress handshake log output
"""

import argparse
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from queue import Empty, Queue

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.protocol import (
    CAMERA_IP, CAMERA_IP_WORKING, CAMERA_PORT, RELAY_SERVERS, RELAY_PORT,
    DEVICE_IDENTITY, DEVICE_IDENTITY_WORKING,
)
from client.stream import StreamClient

# Map known camera IPs to their DEVICE_IDENTITY
_KNOWN_IDENTITIES = {
    CAMERA_IP:         DEVICE_IDENTITY,          # 192.168.1.122 — MAC 0b:90:0e, brand ICOSN
    CAMERA_IP_WORKING: DEVICE_IDENTITY_WORKING,  # 192.168.1.157 — MAC 0b:9d:b1, brand TQKYF
}

def _identity_for(camera_ip: str) -> bytes:
    """Return the DEVICE_IDENTITY for a known camera IP, or the working-camera default."""
    return _KNOWN_IDENTITIES.get(camera_ip, DEVICE_IDENTITY_WORKING)


# ---------------------------------------------------------------------------
# Output modes
# ---------------------------------------------------------------------------

def make_file_saver(frames_dir: str):
    """Return a callback that saves each JPEG frame to a directory."""
    out = Path(frames_dir)
    out.mkdir(parents=True, exist_ok=True)
    print(f"[Output] Saving frames to {out.resolve()}", file=sys.stderr)

    def save(jpeg: bytes, n: int) -> None:
        path = out / f"frame_{n:06d}.jpg"
        path.write_bytes(jpeg)
        print(f"  frame {n:6d}  {len(jpeg):7d} bytes  → {path.name}", file=sys.stderr)

    return save


def make_mjpeg_stdout():
    """Return a callback that writes raw MJPEG frames to stdout."""
    out = sys.stdout.buffer

    def write(jpeg: bytes, n: int) -> None:
        # MJPEG boundary format used by most players / browsers
        boundary = b"--frame\r\nContent-Type: image/jpeg\r\n\r\n"
        out.write(boundary + jpeg + b"\r\n")
        out.flush()
        print(f"  frame {n:6d}  {len(jpeg):7d} bytes", file=sys.stderr)

    return write


# ---------------------------------------------------------------------------
# Simple HTTP MJPEG server
# ---------------------------------------------------------------------------

_frame_queue: Queue = Queue(maxsize=2)


def make_http_feeder():
    """Return a callback that feeds frames into the HTTP server queue."""
    def feed(jpeg: bytes, n: int) -> None:
        try:
            _frame_queue.put_nowait(jpeg)
        except Exception:
            pass  # drop frame if queue full (slow browser)
        print(f"  frame {n:6d}  {len(jpeg):7d} bytes", file=sys.stderr)
    return feed


class MjpegHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def do_GET(self):
        if self.path == "/":
            # Serve a tiny HTML page that embeds the stream
            body = (
                b"<html><body style='background:#000;margin:0'>"
                b"<img src='/stream' style='max-width:100%'></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/stream":
            boundary = "frame"
            self.send_response(200)
            self.send_header(
                "Content-Type",
                f"multipart/x-mixed-replace; boundary={boundary}"
            )
            self.end_headers()
            try:
                while True:
                    try:
                        jpeg = _frame_queue.get(timeout=10.0)
                    except Empty:
                        break
                    header = (
                        f"--{boundary}\r\n"
                        f"Content-Type: image/jpeg\r\n"
                        f"Content-Length: {len(jpeg)}\r\n\r\n"
                    ).encode()
                    try:
                        self.wfile.write(header + jpeg + b"\r\n")
                        self.wfile.flush()
                    except BrokenPipeError:
                        break
            except Exception:
                pass
            return

        self.send_response(404)
        self.end_headers()


def start_http_server(port: int) -> None:
    server = HTTPServer(("127.0.0.1", port), MjpegHandler)
    print(f"[HTTP]   MJPEG server: http://localhost:{port}/", file=sys.stderr)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="IoT camera stream client — connects via confirmed P2P handshake",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--camera",      default=CAMERA_IP_WORKING,
                        help=f"Camera IP (default: {CAMERA_IP_WORKING}). "
                             f"Known cameras: {CAMERA_IP} (ICOSN), {CAMERA_IP_WORKING} (TQKYF)")
    parser.add_argument("--port",        type=int, default=CAMERA_PORT,
                        help=f"Camera UDP port (default: {CAMERA_PORT})")
    parser.add_argument("--relay",       default=RELAY_SERVERS[0],
                        help=f"Relay IP (default: {RELAY_SERVERS[0]})")
    parser.add_argument("--relay-port",  type=int, default=RELAY_PORT,
                        help=f"Relay port (default: {RELAY_PORT})")
    parser.add_argument("--skip-relay",  action="store_true",
                        help="Skip relay PUNCH, go direct to camera")
    parser.add_argument("--frames-dir",  default=None,
                        help="Save frames as JPEG files in this directory")
    parser.add_argument("--mjpeg-out",   action="store_true",
                        help="Write raw MJPEG to stdout (for piping to ffplay)")
    parser.add_argument("--http",        type=int, default=None, metavar="PORT",
                        help="Serve MJPEG over HTTP on localhost:PORT")
    parser.add_argument("--count",       type=int, default=0,
                        help="Stop after N frames (0 = unlimited)")
    parser.add_argument("--timeout",     type=float, default=5.0,
                        help="Socket receive timeout in seconds (default: 5)")
    parser.add_argument("--quiet",       action="store_true",
                        help="Suppress handshake log output")
    parser.add_argument("--debug",       action="store_true",
                        help="Log ALL received UDP packets (any source) — for diagnosis")
    args = parser.parse_args()

    # Require at least one output mode
    if not args.frames_dir and not args.mjpeg_out and not args.http:
        args.frames_dir = "frames"
        print(f"[Output] No output mode specified — defaulting to --frames-dir frames",
              file=sys.stderr)

    # Build callbacks
    callbacks = []
    if args.frames_dir:
        callbacks.append(make_file_saver(args.frames_dir))
    if args.mjpeg_out:
        callbacks.append(make_mjpeg_stdout())
    if args.http:
        start_http_server(args.http)
        callbacks.append(make_http_feeder())

    def combined_callback(jpeg: bytes, n: int) -> None:
        for cb in callbacks:
            cb(jpeg, n)

    # Select DEVICE_IDENTITY automatically based on camera IP
    identity = _identity_for(args.camera)
    identity_label = {
        DEVICE_IDENTITY:         "ICOSN (192.168.1.122)",
        DEVICE_IDENTITY_WORKING: "TQKYF (192.168.1.157)",
    }.get(identity, identity.hex())

    # Print run parameters
    verbose = not args.quiet
    print("=" * 60, file=sys.stderr)
    print(" IoT Camera Stream Client", file=sys.stderr)
    print(f" Camera  : {args.camera}:{args.port}", file=sys.stderr)
    print(f" Identity: {identity_label}", file=sys.stderr)
    if not args.skip_relay:
        print(f" Relay   : {args.relay}:{args.relay_port}", file=sys.stderr)
    else:
        print(" Relay   : skipped (--skip-relay)", file=sys.stderr)
    print(f" Frames  : {'unlimited' if args.count == 0 else args.count}", file=sys.stderr)
    print(" Scope   : owned device, lawful analysis only", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    client = StreamClient(
        camera_ip       = args.camera,
        camera_port     = args.port,
        relay_ip        = args.relay,
        relay_port      = args.relay_port,
        device_identity = identity,
        skip_relay      = args.skip_relay,
        timeout         = args.timeout,
        verbose         = verbose,
        debug           = args.debug,
    )

    start = time.time()
    try:
        n = client.run(combined_callback, max_frames=args.count)
    except KeyboardInterrupt:
        print("\n[Interrupted]", file=sys.stderr)
        client.close()
        n = 0

    elapsed = time.time() - start
    fps = n / elapsed if elapsed > 0 else 0
    print(f"\n[Done] {n} frames in {elapsed:.1f}s  ({fps:.1f} fps)", file=sys.stderr)


if __name__ == "__main__":
    main()
