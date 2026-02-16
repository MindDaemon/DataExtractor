from __future__ import annotations
from dataclasses import dataclass
import struct

from common.config import MAGIC, VERSION
from common.integrity import crc32_bytes

# magic(2) version(1) type(1) session(4) seq(4) total(4) payload_len(2) crc32(4)
HEADER_FMT = "!2sBBIIIHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

@dataclass
class Frame:
    msg_type: int
    session_id: int
    seq: int
    total: int
    payload: bytes

    def pack(self) -> bytes:
        crc = crc32_bytes(self.payload)
        header = struct.pack(
            HEADER_FMT,
            MAGIC,
            VERSION,
            self.msg_type,
            self.session_id,
            self.seq,
            self.total,
            len(self.payload),
            crc,
        )
        return header + self.payload

    @staticmethod
    def unpack(raw: bytes) -> "Frame":
        if len(raw) < HEADER_SIZE:
            raise ValueError("Frame too short")

        magic, version, msg_type, session_id, seq, total, plen, crc = struct.unpack(
            HEADER_FMT, raw[:HEADER_SIZE]
        )
        if magic != MAGIC:
            raise ValueError("Invalid magic")
        if version != VERSION:
            raise ValueError("Unsupported version")
        payload = raw[HEADER_SIZE : HEADER_SIZE + plen]
        if len(payload) != plen:
            raise ValueError("Truncated payload")
        if crc32_bytes(payload) != crc:
            raise ValueError("CRC mismatch")

        return Frame(
            msg_type=msg_type,
            session_id=session_id,
            seq=seq,
            total=total,
            payload=payload,
        )
