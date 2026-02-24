from __future__ import annotations

from typing import Optional

from scapy.all import DNS, DNSQR, IP, UDP, RandShort, send, sniff  # type: ignore

from common.dns_tunnel import frame_bytes_to_qname, qname_to_frame_bytes
from common.config import TYPE_ACK, TYPE_NACK
from common.frame import Frame


def _first_question(dns) -> Optional[DNSQR]:
    try:
        return dns.qd[0]
    except Exception:
        return dns.qd


def send_frame(peer_ip: str, frame: Frame, iface: str, dns_domain: str, dns_port: int = 53) -> None:
    qname = frame_bytes_to_qname(frame.pack(), dns_domain)
    pkt = IP(dst=peer_ip) / UDP(sport=RandShort(), dport=dns_port) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
    send(pkt, iface=iface, verbose=False)


def _parse_control_packet(pkt, dns_domain: str, peer_ip: str) -> Optional[Frame]:
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP) or not pkt.haslayer(DNS):
        return None
    if pkt[IP].src != peer_ip:
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


def wait_for_ack(
    iface: str,
    peer_ip: str,
    session_id: int,
    seq: int,
    timeout: float,
    dns_domain: str,
    dns_port: int = 53,
) -> tuple[bool, str]:
    packets = sniff(
        iface=iface,
        filter=f"udp and src host {peer_ip} and dst port {dns_port}",
        timeout=timeout,
        count=40,
    )
    for pkt in packets:
        frame = _parse_control_packet(pkt, dns_domain=dns_domain, peer_ip=peer_ip)
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
