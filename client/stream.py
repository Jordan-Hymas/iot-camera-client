"""
stream.py — Full P2P stream client

Implements the complete viewer handshake confirmed from iPhone rvi0 capture
on 2026-03-16. Connects directly to the camera over LAN UDP and streams
MJPEG frames.

Confirmed handshake sequence (source: iphone_20260316_103428.pcapng):
  1.  Client → Relay (32100)  : f1 20 (PUNCH) × 3  with DEVICE_IDENTITY
  2.  Relay  → Client         : f1 21 (PUNCH_ACK) + f1 40 × 2 (camera LAN + WAN)
  3.  Client → Camera (32108) : f1 41 (HOLE_PUNCH + DEVICE_IDENTITY) × 6
  4.  Camera → Client         : f1 42 (SESSION_CONF + DEVICE_IDENTITY)
  5.  Client → Camera         : f1 42 (echo SESSION_CONF back)
  6.  Client → Camera         : f1 e0 (empty)
      Camera → Client         : f1 e0 (16 zero bytes)
  7.  Client → Camera         : f1 e1 (empty)
      Camera → Client         : f1 e1 (16 zero bytes)
  8.  AV negotiation round 1  : Client → f1 d1 (AV_NEG1_PHONE)
                                Camera → f1 d0 (response)
  9.  AV negotiation round 2  : Client → f1 d1 (AV_NEG2_PHONE)
                                Camera → f1 d0 (response)
 10.  AV stream               : Camera → f1 d0 (MJPEG frames)
                                Client → f1 d1 (batch ACK)
 11.  Keepalive (periodic)    : Camera → f1 e0; Client → f1 e1

MJPEG framing inside f1 d0 payload:
  bytes 0-3 : d1 01 seq_hi seq_lo  (4-byte header)
  bytes 4+  : JPEG data (start ff d8 … end ff d9), split across packets

f1 d1 ACK payload format:
  d2 01 00 count [seq_hi seq_lo] × count
"""

import socket
import struct
import time
from typing import Callable, Optional

from .protocol import (
    CAMERA_IP_WORKING,
    CAMERA_PORT,
    RELAY_SERVERS,
    RELAY_PORT,
    DEVICE_IDENTITY_WORKING,
    CMD_PUNCH,
    CMD_PUNCH_TO,
    CMD_HOLE_PUNCH,
    CMD_SESSION_CONF,
    CMD_SESSION_SETUP,
    CMD_SESSION_ACK,
    CMD_AV_CMD,
    CMD_AV_DATA,
    AV_NEG1_PHONE,
    AV_NEG2_PHONE,
    Packet,
    parse_punch_to,
)

# JPEG frame boundaries
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"

# f1 d0 payload: 4-byte header before actual data
AV_HEADER_SIZE = 4

# Send one f1 d1 ACK after this many d0 packets
ACK_BATCH = 6

# How many consecutive empty receives before giving up
MAX_NO_DATA = 20


class StreamClient:
    """
    Full P2P viewer for the IoT camera.

    Usage:
        client = StreamClient()
        if client.connect():
            client.stream(lambda jpeg, n: open(f"frame_{n:04d}.jpg", "wb").write(jpeg))
        client.close()

    Or use the convenience method:
        client.run(frame_callback)
    """

    def __init__(
        self,
        camera_ip:       str   = CAMERA_IP_WORKING,
        camera_port:     int   = CAMERA_PORT,
        relay_ip:        str   = RELAY_SERVERS[0],
        relay_port:      int   = RELAY_PORT,
        device_identity: bytes = DEVICE_IDENTITY_WORKING,
        timeout:         float = 5.0,
        verbose:         bool  = True,
        skip_relay:      bool  = False,
        debug:           bool  = False,
    ):
        self.camera_ip       = camera_ip
        self.camera_port     = camera_port
        self.relay_ip        = relay_ip
        self.relay_port      = relay_port
        self.device_identity = device_identity
        self.timeout         = timeout
        self.verbose         = verbose
        self.skip_relay      = skip_relay
        self.debug           = debug
        self._sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _get_local_ip(self) -> str:
        """Return our LAN IP on the interface that can reach the camera."""
        try:
            tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tmp.connect((self.camera_ip, self.camera_port))
            ip = tmp.getsockname()[0]
            tmp.close()
            return ip
        except Exception:
            return "0.0.0.0"

    def _send(self, cmd: int, payload: bytes = b"") -> None:
        data = Packet(cmd, payload).encode()
        self._sock.sendto(data, (self.camera_ip, self.camera_port))
        self._log(f"  --> f1 {cmd:02x}  ({len(payload)}b)")

    def _recv_one(self, timeout: float = 1.0) -> Optional[Packet]:
        """Receive one f1 packet from the camera; return None on timeout or bad magic."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data, src = self._sock.recvfrom(65535)
            except socket.timeout:
                return None
            if src[0] != self.camera_ip:
                if self.debug:
                    self._log(f"  [dbg] pkt from {src[0]}:{src[1]}  raw={data.hex()[:40]}")
                continue  # skip relay stragglers
            try:
                return Packet.decode(data)
            except ValueError:
                if self.debug:
                    self._log(f"  [dbg] bad magic from camera: {data.hex()[:20]}")
                continue
        return None

    def _recv_until(self, cmd: int, timeout: float = None) -> Optional[Packet]:
        """
        Drain incoming packets until one from the camera matches cmd or timeout.
        Auto-responds to f1 e0 keepalives so the camera doesn't stall waiting
        for our ack while we're blocking in this receive loop.
        """
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            remaining = max(0.05, deadline - time.time())
            self._sock.settimeout(min(0.3, remaining))
            try:
                data, src = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            if src[0] != self.camera_ip:
                if self.debug:
                    self._log(f"  [dbg] pkt from {src[0]}:{src[1]}  raw={data.hex()[:40]}")
                else:
                    self._log(f"  <-- {src[0]} (ignored — not camera)")
                continue
            try:
                pkt = Packet.decode(data)
            except ValueError:
                if self.debug:
                    self._log(f"  [dbg] bad magic from camera: {data.hex()[:20]}")
                continue
            # Return immediately if this is the packet we want
            if pkt.cmd == cmd:
                self._log(f"  <-- f1 {pkt.cmd:02x}  ({len(pkt.payload)}b)")
                return pkt
            # Auto-respond to keepalives so camera doesn't stall
            if pkt.cmd == CMD_SESSION_SETUP:
                self._log(f"  <-- f1 e0  (keepalive — acking)")
                self._send(CMD_SESSION_ACK, b"")
                continue
            self._log(f"  <-- f1 {pkt.cmd:02x}  ({len(pkt.payload)}b)")
        return None

    # ------------------------------------------------------------------
    # Step 1: Relay PUNCH — uses self._sock so our source port is preserved
    # ------------------------------------------------------------------

    def _relay_punch(self) -> Optional[tuple]:
        """
        Send f1 20 PUNCH × 3 to relay via self._sock.

        CRITICAL: uses self._sock (not a separate socket) so the relay
        records our source port and tells the camera to reach us at that port.

        Payload is 40 bytes (same extended format as camera's f1 10 register):
          [DEVICE_IDENTITY 20b][zeros 4b][zeros 2b][port_le 2b][ip_le 4b][zeros 8b]
        Including our LAN IP lets the relay tell the camera our LAN address,
        so the camera responds directly on LAN (no NAT hairpin required).

        Returns (ip, port) of the first non-zero PUNCH_TO address, or None.
        """
        local_ip = self._get_local_ip()
        self._log(f"\n[Relay] PUNCH → {self.relay_ip}:{self.relay_port}")
        self._log(f"       Our LAN : {local_ip}")

        # 20-byte payload: camera DEVICE_IDENTITY (relay uses this for camera lookup)
        pkt_bytes = Packet(CMD_PUNCH, self.device_identity).encode()
        for _ in range(3):
            self._sock.sendto(pkt_bytes, (self.relay_ip, self.relay_port))
            time.sleep(0.05)

        deadline = time.time() + self.timeout
        lan_addr = None
        while time.time() < deadline:
            remaining = max(0.05, deadline - time.time())
            self._sock.settimeout(min(0.5, remaining))
            try:
                data, src = self._sock.recvfrom(4096)
            except socket.timeout:
                continue  # keep waiting until deadline, not break
            try:
                p = Packet.decode(data)
                self._log(f"  <-- {src[0]} f1 {p.cmd:02x}  (payload={p.payload.hex()})")
                if p.cmd == CMD_PUNCH_TO and len(p.payload) >= 16:
                    addr = parse_punch_to(p.payload)
                    self._log(f"       PUNCH_TO  {addr['ip']}:{addr['port']}")
                    if lan_addr is None and addr['ip'] not in ("0.0.0.0", ""):
                        lan_addr = (addr['ip'], addr['port'])
            except ValueError:
                if self.debug:
                    self._log(f"  [dbg] relay non-f1 pkt: {data.hex()[:40]}")
        self._sock.settimeout(self.timeout)
        return lan_addr

    # ------------------------------------------------------------------
    # Steps 3-9: direct camera handshake
    # ------------------------------------------------------------------

    def _hole_punch(self, count: int = 6) -> None:
        """Send f1 41 + DEVICE_IDENTITY × count (NAT hole-punch)."""
        self._log(f"\n[Handshake] HOLE_PUNCH (f1 41) × {count} → {self.camera_ip}:{self.camera_port}")
        pkt_bytes = Packet(CMD_HOLE_PUNCH, self.device_identity).encode()
        for _ in range(count):
            self._sock.sendto(pkt_bytes, (self.camera_ip, self.camera_port))
            time.sleep(0.05)

    def _session_exchange(self, conf_payload: bytes) -> bool:
        """
        After receiving camera f1 42:
          - Echo f1 42 back
          - Exchange f1 e0 / f1 e1
        Returns True on success.
        """
        # Echo the session conf back (use same payload camera sent us)
        self._log("[Handshake] Echoing SESSION_CONF (f1 42)")
        self._send(CMD_SESSION_CONF, conf_payload)

        # f1 e0 exchange
        self._log("[Handshake] Sending SESSION_SETUP (f1 e0)")
        self._send(CMD_SESSION_SETUP, b"")
        r = self._recv_until(CMD_SESSION_SETUP, 3.0)
        if r is None:
            self._log("  WARNING: no f1 e0 response")
        else:
            self._log(f"  f1 e0 response: {r.payload.hex()}")

        # f1 e1 exchange
        self._log("[Handshake] Sending SESSION_ACK (f1 e1)")
        self._send(CMD_SESSION_ACK, b"")
        r = self._recv_until(CMD_SESSION_ACK, 3.0)
        if r is None:
            self._log("  WARNING: no f1 e1 response")
        else:
            self._log(f"  f1 e1 response: {r.payload.hex()}")

        return True

    def _av_negotiate(self) -> None:
        """
        Two-round AV capability negotiation.
        Payloads captured from camera 192.168.1.157 (TQKYF).
        May not apply to all cameras — if both rounds get no f1 d0 response,
        we proceed anyway; the camera may start streaming spontaneously.
        """
        self._log("\n[AV] Negotiation round 1")
        self._send(CMD_AV_CMD, AV_NEG1_PHONE)
        r = self._recv_until(CMD_AV_DATA, 5.0)
        self._log(f"  Camera response: {r.payload.hex() if r else '<none>'}")

        self._log("[AV] Negotiation round 2")
        self._send(CMD_AV_CMD, AV_NEG2_PHONE)
        r = self._recv_until(CMD_AV_DATA, 5.0)
        self._log(f"  Camera response: {r.payload.hex() if r else '<none>'}")

        if r is None:
            self._log("  [Note] Standard AV_NEG got no response — trying fallback probes ...")
            self._av_probe_fallbacks()

    def _av_probe_fallbacks(self) -> None:
        """
        Try alternative AV start payloads when the standard negotiation fails.
        Logged as [probe N] — the one that gets a f1 d0 response is the right format.
        """
        fallbacks = [
            # channel 0, all zeros (some cameras default to ch 0)
            ("ch0-zeros",   bytes.fromhex("d100000000000000000000000000000000"[:32])),
            # channel 1, minimal params
            ("ch1-minimal", bytes.fromhex("d1000000010000000000000000000000")),
            # 4-byte minimal
            ("minimal-4",   bytes.fromhex("d1000001")),
            # round 2 only, no round 1 (some cameras skip round 1)
            ("r2-only",     AV_NEG2_PHONE),
        ]
        for label, payload in fallbacks:
            self._log(f"  [probe {label}]  f1 d1 payload={payload.hex()}")
            self._send(CMD_AV_CMD, payload)
            r = self._recv_until(CMD_AV_DATA, 3.0)
            if r:
                self._log(f"  *** MATCH: probe '{label}' got f1 d0 response: {r.payload.hex()}")
                return
            self._log(f"           no f1 d0 response")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Run the full connection handshake.
        Returns True if session established; False on failure.
        After a successful connect(), call stream() to receive frames.
        """
        # Create socket FIRST — relay punch must use this same socket so the
        # relay records our source port and tells it to the camera.
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self.timeout)

        if not self.skip_relay:
            lan = self._relay_punch()
            if lan and lan[0] not in ("0.0.0.0", self.camera_ip):
                self._log(f"[Relay] Using relay-provided address: {lan[0]}:{lan[1]}")
                self.camera_ip, self.camera_port = lan
            elif lan:
                self._log(f"[Relay] Relay confirms camera at {lan[0]}:{lan[1]}")
            else:
                self._log("[Relay] No address from relay — proceeding with configured IP")

        self._log(f"\n[Connect] Camera: {self.camera_ip}:{self.camera_port}")

        # Hole-punch + wait for SESSION_CONF.
        # Keep sending f1 41 every 0.5s for up to 10s (camera may be slow after relay notify).
        self._log("[Handshake] Sending HOLE_PUNCH (f1 41), waiting for SESSION_CONF (f1 42) ...")
        pkt_punch = Packet(CMD_HOLE_PUNCH, self.device_identity).encode()
        conf = None
        deadline = time.time() + 10.0
        punch_count = 0
        while time.time() < deadline:
            # Send a burst of f1 41 then listen briefly
            for _ in range(3):
                self._sock.sendto(pkt_punch, (self.camera_ip, self.camera_port))
                punch_count += 1
                time.sleep(0.05)
            # Check for f1 42 for 0.5s
            conf = self._recv_until(CMD_SESSION_CONF, timeout=0.5)
            if conf is not None:
                break
        self._log(f"  Sent {punch_count} HOLE_PUNCH packets")
        if conf is None:
            local_ip = self._get_local_ip()
            self._log("[ERROR] No SESSION_CONF (f1 42) received.")
            self._log(f"  Our LAN IP : {local_ip}")
            self._log(f"  Camera IP  : {self.camera_ip}")
            if not local_ip.startswith(self.camera_ip.rsplit('.', 1)[0]):
                self._log("  *** NETWORK MISMATCH: MacBook and camera are on different subnets.")
                self._log(f"      Connect MacBook to the IoT network (same as {self.camera_ip}) and retry.")
            else:
                self._log("  Possible causes:")
                self._log("    1. Phone app has an active session — force-quit the app and retry")
                self._log("    2. Run with --debug to log all received packets for diagnosis")
            self.close()
            return False
        self._log(f"  SESSION_CONF payload: {conf.payload.hex()}")

        # Session + AV negotiation
        self._session_exchange(conf.payload)
        self._av_negotiate()

        self._log("\n[Stream] Ready — receiving MJPEG frames ...")
        return True

    def stream(
        self,
        frame_callback: Callable[[bytes, int], None],
        max_frames: int = 0,
    ) -> int:
        """
        Receive MJPEG frames after connect().

        frame_callback(jpeg_bytes, frame_index) is called for each complete frame.
        max_frames=0 means run until the stream ends or times out.
        Returns the total number of frames received.
        """
        buf          = bytearray()
        frame_count  = 0
        ack_pending: list = []
        last_keepalive = time.time()
        no_data_count  = 0

        while True:
            pkt = self._recv_one(timeout=1.0)

            if pkt is None:
                no_data_count += 1
                if no_data_count >= MAX_NO_DATA:
                    self._log("[Stream] No data — stream ended.")
                    break
                # Send keepalive every ~5 s when idle
                if time.time() - last_keepalive > 5.0:
                    self._send(CMD_SESSION_ACK, b"")
                    last_keepalive = time.time()
                continue

            no_data_count = 0

            if pkt.cmd == CMD_AV_DATA:
                p = pkt.payload
                if len(p) < AV_HEADER_SIZE:
                    continue

                # 4-byte header: sub_cmd(d1) flags(01) seq_hi seq_lo
                seq_hi, seq_lo = p[2], p[3]
                data = p[AV_HEADER_SIZE:]

                # Skip embedded keepalive sentinel
                if data[:4] == b"\x55\xaa\x15\xa8":
                    continue

                buf.extend(data)
                ack_pending.append((seq_hi, seq_lo))

                # Extract complete JPEG frames from accumulated buffer
                start = buf.find(JPEG_SOI)
                while start != -1:
                    end = buf.find(JPEG_EOI, start + 2)
                    if end == -1:
                        break
                    end += 2  # include EOI bytes
                    jpeg = bytes(buf[start:end])
                    frame_callback(jpeg, frame_count)
                    frame_count += 1
                    buf = buf[end:]
                    start = buf.find(JPEG_SOI)

                # Batch ACK
                if len(ack_pending) >= ACK_BATCH:
                    self._send_av_ack(ack_pending)
                    ack_pending = []

                if max_frames and frame_count >= max_frames:
                    self._log(f"[Stream] Reached max_frames={max_frames}.")
                    break

            elif pkt.cmd == CMD_SESSION_SETUP:
                # Periodic keepalive from camera — echo e1 back
                self._send(CMD_SESSION_ACK, b"")
                last_keepalive = time.time()

            else:
                # Unknown command — log it (may reveal alternative AV start cmd)
                self._log(f"  <-- f1 {pkt.cmd:02x}  ({len(pkt.payload)}b)  raw={pkt.payload.hex()[:32]}")

        # Final ACK
        if ack_pending:
            self._send_av_ack(ack_pending)

        return frame_count

    def _send_av_ack(self, seqs: list) -> None:
        """Send f1 d1 batch ACK for a list of (seq_hi, seq_lo) tuples."""
        # Payload: d2 01 00 count [seq_hi seq_lo] × count
        count = len(seqs)
        payload = bytes([0xd2, 0x01, 0x00, count])
        for sh, sl in seqs:
            payload += bytes([sh, sl])
        self._send(CMD_AV_CMD, payload)

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def run(
        self,
        frame_callback: Callable[[bytes, int], None],
        max_frames: int = 0,
    ) -> int:
        """Connect, stream, close. Returns frame count."""
        if not self.connect():
            return 0
        try:
            return self.stream(frame_callback, max_frames)
        finally:
            self.close()
