"""
session.py — Multi-step P2P session handshake

Confirmed handshake steps so far (2026-03-15):
  Step 1: f1 36 (DISCOVERY) → camera replies f1 21 (DISCOVERY_ACK) + fc000000
  Step 2: f1 30 (PING)      → camera replies f1 41 (PING_ACK) + device identity

Next steps attempt (speculative, in order of likelihood):
  Step 3: After f1 21, send f1 10 with our local IP:port  (tell camera where to connect)
  Step 4: After f1 21, send f1 20 (PUNCH) with device identity
  Step 5: After f1 21, send f1 08 (HELLO_ACK) echoing fc000000 back
  Step 6: After any session, send f1 00 (HELLO) with identity

We do NOT attempt authentication, credential attacks, or exploitation.
All probes are lawful reverse engineering of owned devices.
"""

import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from .protocol import (
    BROADCAST_ADDR,
    CAMERA_IP,
    CAMERA_PORT,
    DEVICE_IDENTITY,
    DISCOVERY_PORT,
    Packet,
    CMD_DISCOVERY,
    CMD_DISCOVERY_ACK,
    CMD_HELLO_SPEC,
    CMD_HELLO_ACK_SPEC,
    CMD_P2P_RDY_SPEC,
    CMD_PING,
    CMD_PING_ACK,
    CMD_PUNCH_SPEC,
    CMD_RELAY_REGISTER,
    describe,
    make_discovery_packet,
    make_ping_packet,
)

# Our local network address — used in Step 3 to tell camera where to reach us
LOCAL_IP   = "192.168.1.212"
LOCAL_PORT = 32108


def _encode_ip_port(ip: str, port: int) -> bytes:
    """Encode IP + port in little-endian, same format camera uses in 0x10 packets."""
    parts = [int(x) for x in ip.split(".")]
    ip_le   = bytes(reversed(parts))          # e.g. 192.168.1.212 → d4 01 a8 c0
    port_le = struct.pack("<H", port)         # little-endian uint16
    return port_le + b"\x00\x00" + ip_le     # match camera's layout: port(2) pad(2) ip(4)


class SessionProbe:
    """
    Sends probes to the camera in a reactive multi-step sequence.
    Reacts to what the camera sends back at each step.
    Records every byte for analysis.
    """

    def __init__(
        self,
        ip:      str   = CAMERA_IP,
        port:    int   = CAMERA_PORT,
        verbose: bool  = True,
        timeout: float = 3.0,
    ):
        self.ip      = ip
        self.port    = port
        self.verbose = verbose
        self.timeout = timeout
        self.events: list[dict] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(self.timeout)

        # Try binding to discovery port so camera can respond to us by port
        try:
            self.sock.bind(("0.0.0.0", LOCAL_PORT))
        except OSError:
            self.sock.bind(("0.0.0.0", 0))

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def _send(self, pkt: Packet, label: str = "", note: str = "") -> bytes:
        data = pkt.encode()
        self.sock.sendto(data, (self.ip, self.port))
        ts = datetime.now(tz=timezone.utc).isoformat()
        self.events.append({
            "ts": ts, "direction": "send",
            "label": label, "note": note,
            "raw": data.hex(), "cmd": f"0x{pkt.cmd:02x}",
        })
        self._log(f"  --> [{label}] {data.hex()}")
        if note:
            self._log(f"      note: {note}")
        return data

    def _recv(self, window: float = None) -> list[Packet]:
        """Receive all packets within window seconds. Returns parsed Packet list."""
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
                self.events.append(entry)
                self._log(f"  <-- [{addr[0]}:{addr[1]}] {entry.get('desc', data.hex())}")
                if pkt:
                    received.append(pkt)
            except socket.timeout:
                break
        return received

    # ------------------------------------------------------------------
    # Individual handshake steps
    # ------------------------------------------------------------------

    def step_discovery(self) -> list[Packet]:
        """
        Step 1 (CONFIRMED): Send f1 36 discovery → expect f1 21 + fc000000
        """
        self._log("\n[Step 1] DISCOVERY (f1 36) — CONFIRMED")
        self._send(make_discovery_packet(), "discovery_f136",
                   note="Exact phone app packet. Camera WILL respond with f1 21.")
        return self._recv()

    def step_ping(self) -> list[Packet]:
        """
        Step 2 (CONFIRMED): Send f1 30 ping → expect f1 41 + device identity
        """
        self._log("\n[Step 2] PING (f1 30) — CONFIRMED")
        self._send(make_ping_packet(), "ping_f130",
                   note="Camera responds with f1 41 echoing its full identity.")
        return self._recv()

    def step_p2p_rdy_with_our_address(self) -> list[Packet]:
        """
        Step 3 (SPECULATIVE): After getting f1 21, send f1 10 with our local IP:port.
        Mirrors what the camera sends to relay servers — but directed at the camera,
        telling it 'here is where I (the client) am reachable locally'.
        """
        self._log("\n[Step 3] P2P_RDY with client address (f1 10) — SPECULATIVE")
        # Build payload matching the camera's relay registration format,
        # but with our local IP/port instead of the camera's
        ip_port  = _encode_ip_port(LOCAL_IP, LOCAL_PORT)
        payload  = DEVICE_IDENTITY + b"\x08\x00\x02\x01" + ip_port + b"\x00" * 8
        self._send(Packet(CMD_RELAY_REGISTER, payload), "p2p_rdy_f110_our_addr",
                   note=f"Telling camera our address: {LOCAL_IP}:{LOCAL_PORT}")
        return self._recv()

    def step_punch(self) -> list[Packet]:
        """
        Step 4 (SPECULATIVE): Send f1 20 PUNCH with device identity.
        Standard NAT hole-punch in 0xf1 protocol family.
        """
        self._log("\n[Step 4] PUNCH (f1 20) + identity — SPECULATIVE")
        self._send(Packet(CMD_PUNCH_SPEC, DEVICE_IDENTITY), "punch_f120_with_id",
                   note="NAT hole-punch with device identity payload.")
        return self._recv()

    def step_hello_ack_echo(self, session_token: bytes = b"\xfc\x00\x00\x00") -> list[Packet]:
        """
        Step 5 (SPECULATIVE): Echo the fc000000 token back to the camera as a HELLO_ACK.
        Hypothesis: camera sent fc000000 as a session challenge; we echo it to confirm.
        """
        self._log(f"\n[Step 5] HELLO_ACK echo (f1 08) + token {session_token.hex()} — SPECULATIVE")
        self._send(Packet(CMD_HELLO_ACK_SPEC, session_token), "hello_ack_f108_echo_token",
                   note="Echoing fc000000 back — treating it as a session challenge token.")
        return self._recv()

    def step_hello_with_identity(self) -> list[Packet]:
        """
        Step 6 (SPECULATIVE): Send f1 00 HELLO with full device identity.
        """
        self._log("\n[Step 6] HELLO (f1 00) + identity — SPECULATIVE")
        self._send(Packet(CMD_HELLO_SPEC, DEVICE_IDENTITY), "hello_f100_with_id",
                   note="Session HELLO with device identity.")
        return self._recv()

    def step_ping_ack_echo(self) -> list[Packet]:
        """
        Step 7 (SPECULATIVE): Send f1 41 (PING_ACK) with device identity.
        Hypothesis: camera expects client to echo PING_ACK format to confirm pairing.
        """
        self._log("\n[Step 7] PING_ACK echo (f1 41) + identity — SPECULATIVE")
        self._send(Packet(CMD_PING_ACK, DEVICE_IDENTITY), "ping_ack_f141_echo",
                   note="Echoing PING_ACK format back — attempting mutual identity confirmation.")
        return self._recv()

    # ------------------------------------------------------------------
    # Full probe sequence
    # ------------------------------------------------------------------

    def run(self) -> list[dict]:
        self._log(f"\n{'='*60}")
        self._log(f" Session probe → {self.ip}:{self.port}")
        self._log(f"{'='*60}")

        session_token = b"\xfc\x00\x00\x00"  # from camera's 0x21 response

        # Step 1 — confirmed
        r1 = self.step_discovery()
        if r1:
            discovered_ack = r1[0]
            if discovered_ack.cmd == 0x21 and len(discovered_ack.payload) >= 1:
                session_token = discovered_ack.payload
                self._log(f"      [!] Session token captured: {session_token.hex()}")

        # Step 2 — confirmed
        self.step_ping()

        # Pause briefly so camera processes our packets
        time.sleep(0.5)

        # Step 3 — tell camera our local address
        r3 = self.step_p2p_rdy_with_our_address()
        if r3:
            self._log(f"      [!] Camera responded to f1 10 — SIGNIFICANT")

        # Step 4 — punch with identity
        r4 = self.step_punch()
        if r4:
            self._log(f"      [!] Camera responded to f1 20 — SIGNIFICANT")

        # Step 5 — echo session token back as HELLO_ACK
        r5 = self.step_hello_ack_echo(session_token)
        if r5:
            self._log(f"      [!] Camera responded to f1 08 — SIGNIFICANT")

        # Step 6 — HELLO with identity
        r6 = self.step_hello_with_identity()
        if r6:
            self._log(f"      [!] Camera responded to f1 00 HELLO — SIGNIFICANT")

        # Step 7 — PING_ACK echo
        r7 = self.step_ping_ack_echo()
        if r7:
            self._log(f"      [!] Camera responded to f1 41 echo — SIGNIFICANT")

        # Re-ping to confirm camera is still alive after all probes
        self._log("\n[Final] Confirming camera still alive (f1 30)...")
        self._send(make_ping_packet(), "final_ping", note="Verify camera still responsive.")
        rf = self._recv()
        if rf:
            self._log("      [OK] Camera still responding — session probe complete.")
        else:
            self._log("      [!] Camera not responding to final ping.")

        # Summary
        recv_events = [e for e in self.events if e["direction"] == "recv"]
        self._log(f"\n{'='*60}")
        self._log(f" Probe complete.")
        self._log(f"   Packets sent    : {len([e for e in self.events if e['direction'] == 'send'])}")
        self._log(f"   Responses recvd : {len(recv_events)}")
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
