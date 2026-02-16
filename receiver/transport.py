from __future__ import annotations
from scapy.all import IP, ICMP, Raw, send  # type: ignore
from common.frame import Frame
from common.config import TYPE_ACK, TYPE_NACK

def send_control(peer_ip: str, iface: str, msg_type: int, session_id: int, seq: int, total: int, payload: bytes = b"") -> None:
    frame = Frame(msg_type=msg_type, session_id=session_id, seq=seq, total=total, payload=payload)
    pkt = IP(dst=peer_ip) / ICMP(type=8, code=0) / Raw(load=frame.pack())
    send(pkt, iface=iface, verbose=False)

def send_ack(peer_ip: str, iface: str, session_id: int, seq: int, total: int) -> None:
    send_control(peer_ip, iface, TYPE_ACK, session_id, seq, total)

def send_nack(peer_ip: str, iface: str, session_id: int, seq: int, total: int, reason: str = "CRC") -> None:
    send_control(peer_ip, iface, TYPE_NACK, session_id, seq, total, payload=reason.encode())
