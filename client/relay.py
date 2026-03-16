"""
relay.py — Relay server connection client

Connects to the camera's cloud relay servers on port 32100 using the
0xf1 protocol with the camera's UID and admin credentials from QR code.

Confirmed data (from QR code scan 2026-03-15):
  UID      : FTYD757774ICOSN
  Username : admin
  Password : admin
  QR format: 3;{UID};{user};{pass}

UID formula (reverse-engineered):
  FTYD + decimal(uint24(mac_last3_bytes)) + ICOSN
  MAC 50:49:56:0B:90:0E → last3 = 0x0B900E = 757774 → FTYD757774ICOSN

Relay servers (from passive capture):
  146.56.226.66:32100   Alibaba Cloud
  170.106.50.82:32100   Alibaba Cloud
  35.156.204.247:32100  AWS eu-central-1
"""

import hashlib
import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from .protocol import (
    CAMERA_UID_FIELD,
    CAMERA_MAC_FIELD,
    CAMERA_BRAND,
    DEVICE_IDENTITY,
    MAGIC,
    RELAY_PORT,
    RELAY_SERVERS,
    Packet,
    make_ping_packet,
    describe,
)

# ---------------------------------------------------------------------------
# Camera credentials — from QR code
# ---------------------------------------------------------------------------
CAMERA_UID      = "FTYD757774ICOSN"   # full UID from QR code
CAMERA_USERNAME = "admin"
CAMERA_PASSWORD = "admin"
CAMERA_PASSWORD_MD5 = hashlib.md5(CAMERA_PASSWORD.encode()).hexdigest()

# Relay-specific command codes (speculative — trying standard PPPP relay codes)
CMD_RELAY_HELLO       = 0x00   # initial greeting to relay
CMD_RELAY_HELLO_ACK   = 0x08   # expected relay ack
CMD_RELAY_CONNECT     = 0x10   # connect to camera via relay (same as camera's register)
CMD_RELAY_AUTH        = 0x14   # probable: send credentials
CMD_RELAY_AUTH_ACK    = 0x1C   # probable: auth acknowledgement
CMD_RELAY_AV_OPEN     = 0xD0   # probable: open AV channel
CMD_RELAY_AV_OPEN_ACK = 0xD8   # probable: AV channel opened
CMD_PING              = 0x30
CMD_PING_ACK          = 0x41
CMD_DISCOVERY         = 0x36
CMD_DISCOVERY_ACK     = 0x21


def encode_uid(uid: str) -> bytes:
    """Encode a UID string into the 20-byte identity block format."""
    prefix = uid[:4].encode()                    # "FTYD"
    brand  = uid[10:].encode()                   # "ICOSN"  (chars 10-14)
    prefix_padded = prefix.ljust(8, b'\x00')
    brand_padded  = brand.ljust(8, b'\x00')
    # MAC suffix from the known device (bytes 12-15 of identity block)
    mac_suffix = CAMERA_MAC_FIELD
    return prefix_padded + mac_suffix + brand_padded


def build_auth_payload(username: str, password_md5: str) -> bytes:
    """
    Build a probable authentication payload.
    Format is speculative — common in PPPP variants:
      [username null-padded to 32 bytes] [password_md5 null-padded to 32 bytes]
    """
    user_bytes = username.encode().ljust(32, b'\x00')
    pass_bytes = password_md5.encode().ljust(32, b'\x00')
    return user_bytes + pass_bytes


class RelayProbe:
    """
    Probe the relay server with the camera's UID and credentials.
    Records every packet for analysis.
    """

    def __init__(
        self,
        relay_ip:  str   = RELAY_SERVERS[0],
        relay_port: int  = RELAY_PORT,
        verbose:   bool  = True,
        timeout:   float = 3.0,
    ):
        self.relay_ip   = relay_ip
        self.relay_port = relay_port
        self.verbose    = verbose
        self.timeout    = timeout
        self.events: list[dict] = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def _send(self, pkt: Packet, label: str = "", note: str = "") -> bytes:
        data = pkt.encode()
        self.sock.sendto(data, (self.relay_ip, self.relay_port))
        ts = datetime.now(tz=timezone.utc).isoformat()
        self.events.append({
            "ts": ts, "direction": "send",
            "label": label, "note": note,
            "raw": data.hex(), "cmd": f"0x{pkt.cmd:02x}",
        })
        self._log(f"  --> [{label}] {data.hex()}")
        if note:
            self._log(f"      {note}")
        return data

    def _recv(self, window: float = None) -> list[Packet]:
        window   = window or self.timeout
        received = []
        deadline = time.time() + window
        while time.time() < deadline:
            try:
                data, addr = self.sock.recvfrom(4096)
                ts = datetime.now(tz=timezone.utc).isoformat()
                entry = {
                    "ts": ts, "direction": "recv",
                    "src": f"{addr[0]}:{addr[1]}",
                    "raw": data.hex(), "length": len(data),
                }
                pkt = None
                try:
                    pkt = Packet.decode(data)
                    entry["cmd"]     = f"0x{pkt.cmd:02x}"
                    entry["payload"] = pkt.payload.hex()
                    entry["desc"]    = describe(data)
                except Exception as e:
                    entry["parse_error"] = str(e)
                    entry["desc"] = f"<raw> {data.hex()}"
                self.events.append(entry)
                self._log(f"  <-- [{addr[0]}:{addr[1]}] {entry.get('desc', data.hex())}")
                if pkt:
                    received.append(pkt)
            except socket.timeout:
                break
        return received

    def run(self) -> list[dict]:
        self._log(f"\n{'='*60}")
        self._log(f" Relay probe → {self.relay_ip}:{self.relay_port}")
        self._log(f" Camera UID  : {CAMERA_UID}")
        self._log(f" Username    : {CAMERA_USERNAME}")
        self._log(f" PW MD5      : {CAMERA_PASSWORD_MD5}")
        self._log(f"{'='*60}")

        # ------------------------------------------------------------------
        # Step 1: Discovery (confirmed format) — tell relay we want this UID
        # ------------------------------------------------------------------
        self._log("\n[Step 1] Discovery (f1 36) — confirmed format")
        self._send(Packet(CMD_DISCOVERY, DEVICE_IDENTITY), "discovery_f136",
                   note="Exact phone app format sent to relay")
        r1 = self._recv(3.0)
        self._log(f"         → {len(r1)} response(s)")

        # ------------------------------------------------------------------
        # Step 2: Ping relay
        # ------------------------------------------------------------------
        self._log("\n[Step 2] Ping relay (f1 30)")
        self._send(make_ping_packet(), "ping_f130")
        r2 = self._recv(2.0)
        self._log(f"         → {len(r2)} response(s)")

        # ------------------------------------------------------------------
        # Step 3: HELLO to relay (f1 00)
        # ------------------------------------------------------------------
        self._log("\n[Step 3] Hello to relay (f1 00) + identity")
        self._send(Packet(CMD_RELAY_HELLO, DEVICE_IDENTITY), "hello_f100",
                   note="Greeting relay with camera identity")
        r3 = self._recv(2.0)
        self._log(f"         → {len(r3)} response(s)")

        # ------------------------------------------------------------------
        # Step 4: Connect request with UID (f1 10 — relay register format)
        # ------------------------------------------------------------------
        self._log("\n[Step 4] Connect to relay as viewer (f1 10 + identity)")
        self._send(Packet(CMD_RELAY_CONNECT, DEVICE_IDENTITY), "relay_connect_f110",
                   note="Requesting connection to camera via relay")
        r4 = self._recv(3.0)
        self._log(f"         → {len(r4)} response(s)")

        # ------------------------------------------------------------------
        # Step 5: Auth with plaintext credentials
        # ------------------------------------------------------------------
        self._log("\n[Step 5] Auth plaintext (f1 14) — speculative")
        auth_plain = (CAMERA_UID.encode().ljust(20, b'\x00') +
                      CAMERA_USERNAME.encode().ljust(16, b'\x00') +
                      CAMERA_PASSWORD.encode().ljust(16, b'\x00'))
        self._send(Packet(CMD_RELAY_AUTH, auth_plain), "auth_plain_f114",
                   note=f"uid={CAMERA_UID} user={CAMERA_USERNAME} pass={CAMERA_PASSWORD}")
        r5 = self._recv(3.0)
        self._log(f"         → {len(r5)} response(s)")

        # ------------------------------------------------------------------
        # Step 6: Auth with MD5 password
        # ------------------------------------------------------------------
        self._log("\n[Step 6] Auth MD5 (f1 14 with MD5 password) — speculative")
        auth_md5 = build_auth_payload(CAMERA_USERNAME, CAMERA_PASSWORD_MD5)
        self._send(Packet(CMD_RELAY_AUTH, auth_md5), "auth_md5_f114",
                   note=f"user={CAMERA_USERNAME} pw_md5={CAMERA_PASSWORD_MD5}")
        r6 = self._recv(3.0)
        self._log(f"         → {len(r6)} response(s)")

        # ------------------------------------------------------------------
        # Step 7: AV channel open (f1 d0) — speculative
        # ------------------------------------------------------------------
        self._log("\n[Step 7] AV channel open (f1 d0) — speculative")
        av_payload = DEVICE_IDENTITY + b'\x00' * 4  # identity + zero padding
        self._send(Packet(CMD_RELAY_AV_OPEN, av_payload), "av_open_f1d0")
        r7 = self._recv(3.0)
        self._log(f"         → {len(r7)} response(s)")

        # Summary
        recv_events = [e for e in self.events if e["direction"] == "recv"]
        self._log(f"\n{'='*60}")
        self._log(f" Relay probe complete.")
        self._log(f"   Sent      : {len([e for e in self.events if e['direction'] == 'send'])}")
        self._log(f"   Received  : {len(recv_events)}")
        if recv_events:
            self._log(f"\n   Relay responses:")
            for e in recv_events:
                cmd = e.get("cmd", "?")
                plen = len(bytes.fromhex(e.get("payload", ""))) if "payload" in e else 0
                self._log(f"     cmd={cmd} len={plen}  raw={e['raw']}")
        self._log(f"{'='*60}")

        self.sock.close()
        return self.events

    def save(self, out_dir: str = "output") -> Path:
        out = Path(out_dir)
        out.mkdir(exist_ok=True)
        ts   = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = out / f"relay_probe_{ts}.json"
        path.write_text(json.dumps(self.events, indent=2))
        return path
