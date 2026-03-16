"""
stream.py — Video stream request (exploratory / incomplete)

Status: BLOCKED — requires session establishment data we don't yet have.

What we know:
  - Camera uses 0xf1 P2P protocol over UDP
  - No open TCP ports found — no local RTSP, no HTTP API
  - All observed video traffic routes via cloud relay (port 32100)
  - The relay protocol payload is proprietary binary with no TLS SNI observed

What we need before this can work:
  1. A confirmed session handshake sequence (session.py probe results)
  2. The AV stream request command format
  3. Authentication token or session key (if required)
  4. Video codec / framing format (H.264/H.265 RTP? custom frames?)

Next steps:
  - Run tools/connect.py and examine camera responses
  - If camera responds to f1 00 HELLO, capture the response payload —
    it will contain session parameters
  - Run a new traffic capture with phone app open during live view and
    extract the full relay traffic payload for analysis
  - Check if camera app binary contains protocol constants (future work)

This file is a placeholder. It will be implemented once session.py
successfully establishes communication.
"""

from .protocol import CAMERA_IP, CAMERA_PORT


class StreamClient:
    """Placeholder — not yet implemented."""

    def __init__(self, ip: str = CAMERA_IP, port: int = CAMERA_PORT):
        self.ip   = ip
        self.port = port

    def connect(self):
        raise NotImplementedError(
            "Stream client requires confirmed session handshake.\n"
            "Run: python3 tools/connect.py\n"
            "Then capture camera responses and update session.py."
        )
