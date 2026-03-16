"""
protocol.py — 0xf1 P2P packet definitions

All constants and packet formats are derived exclusively from passive capture
analysis of owned devices. See docs/protocol.md for full evidence chain.

Ground truth source: confirmed_facts.md in iot-camera-packet-analysis repo
Capture date: 2026-03-15
"""

import struct


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

MAGIC = 0xF1  # Magic byte — present in every observed packet

# Observed command codes
CMD_RELAY_REGISTER = 0x10  # camera → relay: "I'm alive, here is my local IP:port"
CMD_PING           = 0x30  # phone → broadcast: keepalive heartbeat (no payload)
CMD_DISCOVERY      = 0x36  # phone → broadcast: "camera, are you on this LAN?"

# Confirmed response codes (observed 2026-03-15 session probe)
CMD_DISCOVERY_ACK  = 0x21  # camera → client: response to CMD_DISCOVERY (payload: fc000000)
CMD_PING_ACK       = 0x41  # camera → client: response to CMD_PING (payload: device identity)

# Speculative command codes — standard in PPPP/0xf1 protocol family
# These have NOT been confirmed from capture. Marked with _SPEC suffix.
CMD_HELLO_SPEC       = 0x00  # probable: initial session hello
CMD_HELLO_ACK_SPEC   = 0x08  # probable: hello acknowledgement
CMD_P2P_RDY_SPEC     = 0x10  # speculative: P2P ready (same code as relay register)
CMD_PUNCH_SPEC       = 0x20  # probable: NAT hole-punch packet
CMD_PUNCH_ACK_SPEC   = 0x28  # probable: hole-punch acknowledgement
CMD_CLOSE_SPEC       = 0xF0  # probable: close session

# Known payload from camera's 0x21 discovery ack
DISCOVERY_ACK_PAYLOAD = bytes.fromhex("fc000000")  # 0xFC = unknown — possibly state/capability

# ---------------------------------------------------------------------------
# Device identity — confirmed from capture 2026-03-15
# ---------------------------------------------------------------------------

# Camera: 192.168.1.122  MAC: 50:49:56:0B:90:0E
CAMERA_UID_FIELD  = bytes.fromhex("4654594400000000")  # "FTYD" + 4 null bytes
CAMERA_MAC_FIELD  = bytes.fromhex("000b900e")           # bytes 12-15 in all packets
CAMERA_BRAND      = bytes.fromhex("49434f534e000000")   # "ICOSN" + null padding

DEVICE_IDENTITY = CAMERA_UID_FIELD + CAMERA_MAC_FIELD + CAMERA_BRAND  # 20 bytes

# Network
CAMERA_IP         = "192.168.1.122"
CAMERA_PORT       = 32108   # UDP — camera's local discovery/session port
RELAY_PORT        = 32100   # UDP/TCP — relay server port
BROADCAST_ADDR    = "255.255.255.255"
DISCOVERY_PORT    = 32108

RELAY_SERVERS = [
    "146.56.226.66",    # Alibaba Cloud
    "170.106.50.82",    # Alibaba Cloud
    "35.156.204.247",   # AWS eu-central-1
]

# Probable firmware version from relay registration packet bytes 24-27
FIRMWARE_VERSION = (8, 0, 2, 1)


# ---------------------------------------------------------------------------
# Packet class
# ---------------------------------------------------------------------------

class Packet:
    """
    0xf1 protocol packet.

    Wire format:
      [0]     0xf1          magic
      [1]     cmd           command byte
      [2-3]   length        payload length, big-endian uint16
      [4+]    payload       variable-length payload
    """

    def __init__(self, cmd: int, payload: bytes = b""):
        self.magic   = MAGIC
        self.cmd     = cmd
        self.payload = payload

    def encode(self) -> bytes:
        header = bytes([self.magic, self.cmd]) + struct.pack(">H", len(self.payload))
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "Packet":
        if len(data) < 4:
            raise ValueError(f"Too short: {len(data)} bytes")
        if data[0] != MAGIC:
            raise ValueError(f"Bad magic: 0x{data[0]:02x} (expected 0x{MAGIC:02x})")
        cmd    = data[1]
        length = struct.unpack(">H", data[2:4])[0]
        if len(data) < 4 + length:
            raise ValueError(f"Truncated: have {len(data)}, need {4 + length}")
        payload = data[4 : 4 + length]
        return cls(cmd, payload)

    def __repr__(self) -> str:
        cmd_name = _CMD_NAMES.get(self.cmd, f"0x{self.cmd:02x}")
        return f"Packet({cmd_name}, payload={self.payload.hex() or 'empty'})"


# Command name lookup for display
_CMD_NAMES = {
    CMD_RELAY_REGISTER:  "RELAY_REGISTER(0x10)",
    CMD_DISCOVERY_ACK:   "DISCOVERY_ACK(0x21)",
    CMD_PING:            "PING(0x30)",
    CMD_DISCOVERY:       "DISCOVERY(0x36)",
    CMD_PING_ACK:        "PING_ACK(0x41)",
    CMD_HELLO_SPEC:      "HELLO?(0x00)",
    CMD_HELLO_ACK_SPEC:  "HELLO_ACK?(0x08)",
    CMD_P2P_RDY_SPEC:    "P2P_RDY?(0x10)",
    CMD_PUNCH_SPEC:      "PUNCH?(0x20)",
    CMD_PUNCH_ACK_SPEC:  "PUNCH_ACK?(0x28)",
    CMD_CLOSE_SPEC:      "CLOSE?(0xf0)",
}


# ---------------------------------------------------------------------------
# Packet constructors — confirmed packets
# ---------------------------------------------------------------------------

def make_discovery_packet() -> Packet:
    """
    Exact replica of the phone app's f1 36 discovery broadcast.
    Confirmed hex: f13600144654594400000000000b900e49434f534e000000
    """
    return Packet(CMD_DISCOVERY, DEVICE_IDENTITY)


def make_ping_packet() -> Packet:
    """
    Exact replica of the phone app's f1 30 keepalive.
    Confirmed hex: f1300000
    """
    return Packet(CMD_PING, b"")


# ---------------------------------------------------------------------------
# Packet parsing helpers
# ---------------------------------------------------------------------------

def parse_relay_register(pkt: Packet) -> dict:
    """
    Parse the camera's relay registration packet (cmd 0x10).
    Confirmed structure from capture.
    """
    p = pkt.payload
    if len(p) < 40:
        return {"error": f"payload too short: {len(p)}"}

    uid_field    = p[0:8]
    mac_suffix   = p[8:12]
    brand        = p[12:20]
    flags        = p[20:24]
    local_port   = struct.unpack("<H", p[26:28])[0]
    local_ip     = ".".join(str(b) for b in reversed(p[28:32]))

    return {
        "uid_field":  uid_field.hex(),
        "uid_ascii":  uid_field.decode("latin1", errors="replace").rstrip("\x00"),
        "mac_suffix": mac_suffix.hex(),
        "brand":      brand.decode("latin1", errors="replace").rstrip("\x00"),
        "flags":      flags.hex(),
        "local_port": local_port,
        "local_ip":   local_ip,
    }


def describe(data: bytes) -> str:
    """Return a human-readable description of a raw packet."""
    try:
        pkt = Packet.decode(data)
        extra = ""
        if pkt.cmd == CMD_RELAY_REGISTER and len(pkt.payload) >= 40:
            parsed = parse_relay_register(pkt)
            extra = f" ip={parsed['local_ip']} port={parsed['local_ip']} brand={parsed['brand']}"
        return f"{pkt}{extra}"
    except Exception as e:
        return f"<unparseable: {e}> raw={data.hex()}"
