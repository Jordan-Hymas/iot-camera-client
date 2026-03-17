"""
protocol.py — 0xf1 P2P packet definitions

All constants and packet formats are derived exclusively from passive capture
analysis of owned devices. See docs/protocol.md for full evidence chain.

Ground truth source: confirmed_facts.md in iot-camera-packet-analysis repo
Capture dates: 2026-03-15 (LAN), 2026-03-16 (relay probe + full iPhone handshake)
"""

import struct


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

MAGIC = 0xF1  # Magic byte — present in every observed packet

# ---------------------------------------------------------------------------
# Confirmed command codes (2026-03-15 LAN capture + 2026-03-16 iPhone capture)
# ---------------------------------------------------------------------------

CMD_RELAY_REGISTER = 0x10  # camera → relay: register local IP:port (payload: 40 bytes)
CMD_PING           = 0x30  # phone → broadcast: keepalive (no payload)
CMD_DISCOVERY      = 0x36  # phone → broadcast: LAN camera search (payload: DEVICE_IDENTITY)

# 2026-03-15 LAN session
CMD_DISCOVERY_ACK  = 0x21  # camera → phone: LAN discovery ack (payload: fc000000)
CMD_SESSION_CONF   = 0x42  # bidirectional: session confirm + DEVICE_IDENTITY

# 2026-03-16 full handshake (iPhone rvi0 capture)
CMD_PUNCH          = 0x20  # phone → relay: "connect me to this camera" (payload: DEVICE_IDENTITY)
CMD_PUNCH_ACK      = 0x21  # relay → phone: punch acknowledged (same byte as DISCOVERY_ACK)
CMD_PUNCH_TO       = 0x40  # relay → phone: peer address block (LAN, then WAN) — 16-byte payload
CMD_HOLE_PUNCH     = 0x41  # phone → camera: NAT hole-punch (payload: DEVICE_IDENTITY) ×6-8
CMD_SESSION_SETUP  = 0xe0  # bidirectional: session parameter exchange (phone sends empty → camera replies 16 zero bytes)
CMD_SESSION_ACK    = 0xe1  # bidirectional: session parameter ack   (phone sends empty → camera replies 16 zero bytes)
CMD_AV_CMD         = 0xd1  # phone → camera: AV capability negotiation + frame ACK
CMD_AV_DATA        = 0xd0  # camera → phone: AV capability response + MJPEG frame data

# Relay hello/connect (from relay probe 2026-03-16 — not used by phone app)
CMD_RELAY_HELLO      = 0x00  # client → relay: hello
CMD_RELAY_HELLO_ACK  = 0x01  # relay → client: hello ack (echoes WAN IP:port)
CMD_RELAY_CONNECT    = 0x10  # client → relay: connect request (same byte as RELAY_REGISTER)
CMD_RELAY_CONNECT_ACK = 0x11  # relay → client: connect status (00000000 = offline)

# Known payload from camera's 0x21 LAN discovery ack
DISCOVERY_ACK_PAYLOAD = bytes.fromhex("fc000000")

# ---------------------------------------------------------------------------
# AV negotiation payloads — exact bytes from iPhone capture 2026-03-16
# ---------------------------------------------------------------------------

# f1 d1 payload, phone → camera, round 1
AV_NEG1_PHONE = bytes.fromhex("d1000000010a2010a400ff0000000000")
# f1 d1 payload, phone → camera, round 2
AV_NEG2_PHONE = bytes.fromhex("d1000001010a08100400ff0053734a30")

# ---------------------------------------------------------------------------
# Camera #1 — offline unit (192.168.1.122, MAC 50:49:56:0B:90:0E)
# ---------------------------------------------------------------------------
CAMERA_UID_FIELD  = bytes.fromhex("4654594400000000")  # "FTYD" + 4 null bytes (shared prefix)
CAMERA_MAC_FIELD  = bytes.fromhex("000b900e")           # 00 + last-3 MAC bytes
CAMERA_BRAND      = bytes.fromhex("49434f534e000000")   # "ICOSN" + padding

DEVICE_IDENTITY   = CAMERA_UID_FIELD + CAMERA_MAC_FIELD + CAMERA_BRAND  # 20 bytes

# ---------------------------------------------------------------------------
# Camera #2 — working unit (192.168.1.157, MAC ...0B:9D:B1, brand "TQKYF")
# Confirmed from iPhone rvi0 capture 2026-03-16
# ---------------------------------------------------------------------------
CAMERA_MAC_FIELD_WORKING  = bytes.fromhex("000b9db1")          # 00 + last-3 MAC bytes
CAMERA_BRAND_WORKING      = bytes.fromhex("54514b5946000000")   # "TQKYF" + padding

DEVICE_IDENTITY_WORKING = (
    CAMERA_UID_FIELD + CAMERA_MAC_FIELD_WORKING + CAMERA_BRAND_WORKING
)  # 20 bytes

# Network
CAMERA_IP           = "192.168.1.122"   # offline unit
CAMERA_IP_WORKING   = "192.168.1.157"   # working unit (confirmed 2026-03-16)
CAMERA_PORT         = 32108   # UDP — camera's local discovery/session port
RELAY_PORT          = 32100   # UDP/TCP — relay server port
BROADCAST_ADDR      = "255.255.255.255"
DISCOVERY_PORT      = 32108

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
    CMD_RELAY_HELLO:       "RELAY_HELLO(0x00)",
    CMD_RELAY_HELLO_ACK:   "RELAY_HELLO_ACK(0x01)",
    CMD_RELAY_REGISTER:    "RELAY_REGISTER(0x10)",
    CMD_RELAY_CONNECT_ACK: "RELAY_CONNECT_ACK(0x11)",
    CMD_PUNCH:             "PUNCH(0x20)",
    CMD_PUNCH_ACK:         "PUNCH_ACK/DISC_ACK(0x21)",
    CMD_PING:              "PING(0x30)",
    CMD_DISCOVERY:         "DISCOVERY(0x36)",
    CMD_PUNCH_TO:          "PUNCH_TO(0x40)",
    CMD_HOLE_PUNCH:        "HOLE_PUNCH(0x41)",
    CMD_SESSION_CONF:      "SESSION_CONF(0x42)",
    CMD_SESSION_SETUP:     "SESSION_SETUP(0xe0)",
    CMD_SESSION_ACK:       "SESSION_ACK(0xe1)",
    CMD_AV_DATA:           "AV_DATA(0xd0)",
    CMD_AV_CMD:            "AV_CMD(0xd1)",
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


def parse_punch_to(payload: bytes) -> dict:
    """
    Parse a relay PUNCH_TO (cmd 0x40) or HELLO_ACK (cmd 0x01) address block.
    Format confirmed 2026-03-16:
      [0002][port_le_2][ip_le_4][zeros_8] = 16 bytes
    """
    if len(payload) < 16:
        raise ValueError(f"PUNCH_TO payload too short: {len(payload)}")
    flags = struct.unpack(">H", payload[0:2])[0]
    port  = struct.unpack("<H", payload[2:4])[0]
    ip    = ".".join(str(b) for b in reversed(payload[4:8]))
    return {"flags": flags, "port": port, "ip": ip}


def describe(data: bytes) -> str:
    """Return a human-readable description of a raw packet."""
    try:
        pkt = Packet.decode(data)
        extra = ""
        if pkt.cmd == CMD_RELAY_REGISTER and len(pkt.payload) >= 40:
            parsed = parse_relay_register(pkt)
            extra = f" ip={parsed['local_ip']} port={parsed['local_ip']} brand={parsed['brand']}"
        elif pkt.cmd in (CMD_PUNCH_TO, CMD_RELAY_HELLO_ACK) and len(pkt.payload) >= 16:
            addr = parse_punch_to(pkt.payload)
            extra = f" addr={addr['ip']}:{addr['port']}"
        return f"{pkt}{extra}"
    except Exception as e:
        return f"<unparseable: {e}> raw={data.hex()}"
