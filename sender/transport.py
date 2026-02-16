from __future__ import annotations
import time
from typing import Optional

from scapy.all import IP, ICMP, Raw, send, sniff  # type: ignore

from common.config import TYPE_ACK, TYPE_NACK
from common.frame import Frame

def send_frame(peer_ip: str, frame: Frame, iface: str) -> None:
    pkt = IP(dst=peer_ip) / ICMP(type=8, code=0) / Raw(load=frame.pack())
    send(pkt, iface=iface, verbose=False)

def _parse_control_packet(pkt) -> Optional[Frame]:
    if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw):
        return None
    try:
        return Frame.unpack(bytes(pkt[Raw].load))
    except Exception:
        return None

def wait_for_ack(
    iface: str,
    peer_ip: str,
    session_id: int,
    seq: int,
    timeout: float,
) -> bool:
    '''
    Returns True for ACK, False for NACK/timeout.
    '''
    packets = sniff(
        iface=iface,
        filter=f"icmp and src host {peer_ip}",
        timeout=timeout,
        count=40,
    )
    for pkt in packets:
        frame = _parse_control_packet(pkt)
        if not frame:
            continue
        if frame.session_id != session_id or frame.seq != seq:
            continue
        if frame.msg_type == TYPE_ACK:
            return True
        if frame.msg_type == TYPE_NACK:
            return False
    return False
