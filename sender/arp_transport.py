from __future__ import annotations

import struct
from typing import Optional

from scapy.all import ARP, Ether, Padding, Raw, get_if_addr, get_if_hwaddr, sendp, sniff  # type: ignore

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


def send_frame(peer_ip: str, frame: Frame, iface: str) -> None:
    src_mac = get_if_hwaddr(iface)
    src_ip = get_if_addr(iface)
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
        / ARP(op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=peer_ip)
        / Raw(load=frame.pack())
    )
    sendp(pkt, iface=iface, verbose=False)


def _parse_control_packet(pkt, peer_ip: str) -> Optional[Frame]:
    if not pkt.haslayer(ARP):
        return None
    if pkt[ARP].psrc != peer_ip:
        return None

    blob = _extract_payload_blob(pkt)
    if blob is None:
        return None

    return _decode_frame_from_blob(blob)


def wait_for_ack(
    iface: str,
    peer_ip: str,
    session_id: int,
    seq: int,
    timeout: float,
) -> tuple[bool, str]:
    packets = sniff(
        iface=iface,
        filter=f"arp and src host {peer_ip}",
        timeout=timeout,
        count=40,
    )
    for pkt in packets:
        frame = _parse_control_packet(pkt, peer_ip=peer_ip)
        if not frame:
            continue
        if frame.session_id != session_id or frame.seq != seq:
            continue
        if frame.msg_type == TYPE_ACK:
            return True, "ACK"
        if frame.msg_type == TYPE_NACK:
            reason = frame.payload.decode("utf-8", errors="replace") if frame.payload else "NACK"
            return False, f"NACK:{reason}"
    return False, "TIMEOUT"
