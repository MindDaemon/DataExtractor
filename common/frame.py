from __future__ import annotations
from dataclasses import dataclass
import struct

from common.config import MAGIC, VERSION, TYPE_HELLO, TYPE_DATA, TYPE_ACK, TYPE_NACK, TYPE_FIN
from common.integrity import crc32_bytes

# magic(2) version(1) type(1) session(4) seq(4) total(4) payload_len(2) crc32(4)
HEADER_FMT = "!2sBBIIIHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
VALID_TYPES = {TYPE_HELLO, TYPE_DATA, TYPE_ACK, TYPE_NACK, TYPE_FIN}


def _crc_input(msg_type: int, session_id: int, seq: int, total: int, plen: int, payload: bytes) -> bytes:
    return struct.pack("!BIIIH", msg_type, session_id, seq, total, plen) + payload

@dataclass
class Frame:
    msg_type: int
    session_id: int
    seq: int
    total: int
    payload: bytes

    def pack(self) -> bytes:
        plen = len(self.payload)
        crc = crc32_bytes(_crc_input(self.msg_type, self.session_id, self.seq, self.total, plen, self.payload))
        header = struct.pack(
            HEADER_FMT,
            MAGIC,
            VERSION,
            self.msg_type,
            self.session_id,
            self.seq,
            self.total,
            plen,
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
        if msg_type not in VALID_TYPES:
            raise ValueError("Unsupported message type")
        payload = raw[HEADER_SIZE : HEADER_SIZE + plen]
        if len(payload) != plen:
            raise ValueError("Truncated payload")
        if len(raw) != HEADER_SIZE + plen:
            raise ValueError("Unexpected trailing bytes")
        expected_crc = crc32_bytes(_crc_input(msg_type, session_id, seq, total, plen, payload))
        if expected_crc != crc:
            raise ValueError("CRC mismatch")

        return Frame(
            msg_type=msg_type,
            session_id=session_id,
            seq=seq,
            total=total,
            payload=payload,
        )
