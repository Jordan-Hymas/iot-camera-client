"""
session.py — P2P session establishment attempt

Sends the known-good discovery packet directly to the camera's IP:port
and tries several session initiation commands, recording every byte the
camera sends back. Output is saved for further protocol analysis.

Confidence levels:
  HIGH   — packet format confirmed from capture, camera will receive it
  MEDIUM — command code is speculative but consistent with 0xf1 protocol family
  LOW    — complete guess; included to capture any camera response

We do NOT attempt authentication, credential stuffing, or exploitation.
"""

import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from .protocol import (
    CAMERA_IP,
    CAMERA_PORT,
    DEVICE_IDENTITY,
    Packet,
    CMD_HELLO_SPEC,
    CMD_PING,
    CMD_DISCOVERY,
    CMD_PUNCH_SPEC,
    describe,
    make_discovery_packet,
    make_ping_packet,
)


class SessionProbe:
    """
    Sends probes to the camera and records all responses.
    Does not assume any specific response format — everything is saved raw.
    """

    def __init__(self, ip: str = CAMERA_IP, port: int = CAMERA_PORT, verbose: bool = True):
        self.ip      = ip
        self.port    = port
        self.verbose = verbose
        self.events: list[dict] = []
        self.sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def _send(self, pkt: Packet, label: str = "", confidence: str = ""):
        data = pkt.encode()
        self.sock.sendto(data, (self.ip, self.port))
        ts = datetime.now(tz=timezone.utc).isoformat()
        entry = {
            "ts":         ts,
            "direction":  "send",
            "label":      label,
            "confidence": confidence,
            "raw":        data.hex(),
            "cmd":        f"0x{pkt.cmd:02x}",
        }
        self.events.append(entry)
        self._log(f"  --> [{label}] {data.hex()}")

    def _recv_window(self, window: float = 2.0) -> list[dict]:
        """Collect all responses within `window` seconds."""
        received = []
        deadline = time.time() + window
        while time.time() < deadline:
            try:
                data, addr = self.sock.recvfrom(4096)
                ts = datetime.now(tz=timezone.utc).isoformat()
                entry = {
                    "ts":        ts,
                    "direction": "recv",
                    "src":       f"{addr[0]}:{addr[1]}",
                    "raw":       data.hex(),
                    "length":    len(data),
                }
                try:
                    pkt = Packet.decode(data)
                    entry["cmd"]     = f"0x{pkt.cmd:02x}"
                    entry["payload"] = pkt.payload.hex()
                    entry["desc"]    = describe(data)
                except Exception as e:
                    entry["parse_error"] = str(e)
                    entry["desc"]        = f"<unparseable> {data.hex()}"

                self.events.append(entry)
                received.append(entry)
                self._log(f"  <-- [{addr[0]}:{addr[1]}] {entry['desc']}")
            except socket.timeout:
                break
        return received

    def run(self) -> list[dict]:
        """
        Execute the full probe sequence. Returns all events (sends + receives).
        """
        self._log(f"\n{'='*60}")
        self._log(f" Session probe → {self.ip}:{self.port}")
        self._log(f"{'='*60}")

        # ------------------------------------------------------------------
        # Step 1: Exact discovery packet (HIGH confidence)
        # Identical to what the phone app sends. Camera has been observed to
        # respond to this with a relay registration.
        # ------------------------------------------------------------------
        self._log("\n[Step 1] Discovery broadcast (f1 36) — HIGH confidence")
        self._send(make_discovery_packet(), label="discovery_f136", confidence="HIGH")
        r1 = self._recv_window(3.0)
        self._log(f"         → {len(r1)} response(s)")

        # ------------------------------------------------------------------
        # Step 2: Ping (HIGH confidence)
        # Exact phone keepalive packet.
        # ------------------------------------------------------------------
        self._log("\n[Step 2] Ping (f1 30) — HIGH confidence")
        self._send(make_ping_packet(), label="ping_f130", confidence="HIGH")
        r2 = self._recv_window(2.0)
        self._log(f"         → {len(r2)} response(s)")

        # ------------------------------------------------------------------
        # Step 3: HELLO (MEDIUM — speculative cmd 0x00)
        # Standard opening handshake in the 0xf1 P2P protocol family.
        # Sending empty payload first.
        # ------------------------------------------------------------------
        self._log("\n[Step 3] Hello empty (f1 00) — MEDIUM confidence (speculative)")
        self._send(Packet(CMD_HELLO_SPEC, b""), label="hello_empty_f100", confidence="MEDIUM")
        r3 = self._recv_window(2.0)
        self._log(f"         → {len(r3)} response(s)")

        # ------------------------------------------------------------------
        # Step 4: HELLO with device identity payload (MEDIUM)
        # Many 0xf1 implementations expect the device identity block in HELLO.
        # ------------------------------------------------------------------
        self._log("\n[Step 4] Hello with identity (f1 00 + DEVICE_IDENTITY) — MEDIUM")
        self._send(
            Packet(CMD_HELLO_SPEC, DEVICE_IDENTITY),
            label="hello_with_id_f100",
            confidence="MEDIUM",
        )
        r4 = self._recv_window(2.0)
        self._log(f"         → {len(r4)} response(s)")

        # ------------------------------------------------------------------
        # Step 5: PUNCH (MEDIUM — speculative cmd 0x20)
        # NAT hole-punch packet — may prompt the camera to open a session.
        # ------------------------------------------------------------------
        self._log("\n[Step 5] Punch (f1 20) — MEDIUM confidence (speculative)")
        self._send(Packet(CMD_PUNCH_SPEC, b""), label="punch_f120", confidence="MEDIUM")
        r5 = self._recv_window(2.0)
        self._log(f"         → {len(r5)} response(s)")

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        recv_total = len([e for e in self.events if e["direction"] == "recv"])
        self._log(f"\n{'='*60}")
        self._log(f" Probe complete. {recv_total} total response(s) from camera.")
        if recv_total == 0:
            self._log(
                "\n [!] No responses received.\n"
                "     Possible reasons:\n"
                "     - Camera only responds when the phone app is actively open\n"
                "     - Camera filters packets not matching its full UID\n"
                "     - Firewall or rate limiting\n"
                "     Try running with the phone app open in the background."
            )
        self._log(f"{'='*60}")

        self.sock.close()
        return self.events

    def save(self, out_dir: str = "output") -> Path:
        out = Path(out_dir)
        out.mkdir(exist_ok=True)
        ts   = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = out / f"session_probe_{ts}.json"
        path.write_text(json.dumps(self.events, indent=2))
        return path
