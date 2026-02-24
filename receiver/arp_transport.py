from __future__ import annotations

import struct
from typing import Optional

from scapy.all import ARP, Ether, Padding, Raw, get_if_addr, get_if_hwaddr, sendp  # type: ignore

from common.config import TYPE_ACK, TYPE_NACK
from common.frame import Frame, HEADER_FMT, HEADER_SIZE


def _extract_payload_blob(pkt) -> bytes | None:
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    if pkt.haslayer(Padding):
        return bytes(pkt[Padding].load)
    return None


def _decode_frame_from_blob(blob: bytes) -> Optional[Frame]:
    if len(blob) < HEADER_SIZE:
        return None
    try:
        _, _, _, _, _, _, payload_len, _ = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
    except Exception:
        return None

    full_len = HEADER_SIZE + payload_len
    if len(blob) < full_len:
        return None

    try:
        return Frame.unpack(blob[:full_len])
    except Exception:
        return None


def extract_frame(pkt, peer_ip: str) -> Optional[Frame]:
    if not pkt.haslayer(ARP):
        return None
    if pkt[ARP].psrc != peer_ip:
        return None

    blob = _extract_payload_blob(pkt)
    if blob is None:
        return None

    return _decode_frame_from_blob(blob)


def send_control(
    peer_ip: str,
    iface: str,
    msg_type: int,
    session_id: int,
    seq: int,
    total: int,
    payload: bytes = b"",
) -> None:
    frame = Frame(msg_type=msg_type, session_id=session_id, seq=seq, total=total, payload=payload)
    src_mac = get_if_hwaddr(iface)
    src_ip = get_if_addr(iface)
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
        / ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=peer_ip)
        / Raw(load=frame.pack())
    )
    sendp(pkt, iface=iface, verbose=False)


def send_ack(peer_ip: str, iface: str, session_id: int, seq: int, total: int) -> None:
    send_control(peer_ip, iface, TYPE_ACK, session_id, seq, total)


def send_nack(peer_ip: str, iface: str, session_id: int, seq: int, total: int, reason: str = "CRC") -> None:
    send_control(peer_ip, iface, TYPE_NACK, session_id, seq, total, payload=reason.encode())
