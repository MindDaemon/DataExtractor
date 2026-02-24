from __future__ import annotations

from typing import Optional

from scapy.all import DNS, DNSQR, IP, UDP, RandShort, send  # type: ignore

from common.config import TYPE_ACK, TYPE_NACK
from common.dns_tunnel import frame_bytes_to_qname, qname_to_frame_bytes
from common.frame import Frame


def _first_question(dns) -> Optional[DNSQR]:
    try:
        return dns.qd[0]
    except Exception:
        return dns.qd


def extract_frame(pkt, peer_ip: str, dns_domain: str, dns_port: int = 53) -> Optional[Frame]:
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP) or not pkt.haslayer(DNS):
        return None
    if pkt[IP].src != peer_ip:
        return None
    if pkt[UDP].dport != dns_port:
        return None

    dns = pkt[DNS]
    question = _first_question(dns)
    if question is None:
        return None

    qname = question.qname.decode("ascii", errors="ignore")
    raw = qname_to_frame_bytes(qname, dns_domain)
    if raw is None:
        return None

    try:
        return Frame.unpack(raw)
    except Exception:
        return None


def send_control(
    peer_ip: str,
    iface: str,
    msg_type: int,
    session_id: int,
    seq: int,
    total: int,
    dns_domain: str,
    dns_port: int = 53,
    payload: bytes = b"",
) -> None:
    frame = Frame(msg_type=msg_type, session_id=session_id, seq=seq, total=total, payload=payload)
    qname = frame_bytes_to_qname(frame.pack(), dns_domain)
    pkt = IP(dst=peer_ip) / UDP(sport=RandShort(), dport=dns_port) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
    send(pkt, iface=iface, verbose=False)


def send_ack(
    peer_ip: str,
    iface: str,
    session_id: int,
    seq: int,
    total: int,
    dns_domain: str,
    dns_port: int = 53,
) -> None:
    send_control(peer_ip, iface, TYPE_ACK, session_id, seq, total, dns_domain=dns_domain, dns_port=dns_port)


def send_nack(
    peer_ip: str,
    iface: str,
    session_id: int,
    seq: int,
    total: int,
    dns_domain: str,
    dns_port: int = 53,
    reason: str = "CRC",
) -> None:
    send_control(
        peer_ip,
        iface,
        TYPE_NACK,
        session_id,
        seq,
        total,
        dns_domain=dns_domain,
        dns_port=dns_port,
        payload=reason.encode(),
    )
