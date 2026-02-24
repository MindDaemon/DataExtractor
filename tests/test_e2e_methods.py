from __future__ import annotations

from common.codec import decode_payload, encode_payload
from common.config import TYPE_DATA, TYPE_FIN, TYPE_HELLO
from common.frame import Frame
from receiver import arp_transport as receiver_arp_transport
from receiver import dns_transport as receiver_dns_transport
from receiver import snmp_transport as receiver_snmp_transport
from receiver import transport as receiver_icmp_transport
from sender import arp_transport as sender_arp_transport
from sender import dns_transport as sender_dns_transport
from sender import snmp_transport as sender_snmp_transport
from sender import transport as sender_icmp_transport


def _build_frames(plain: bytes, psk: str, chunk_size: int = 64) -> list[Frame]:
    encoded = encode_payload(plain, psk=psk)
    chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]
    total = len(chunks)
    session_id = 12345
    frames = [Frame(TYPE_HELLO, session_id, seq=0, total=total, payload=b"HELLO")]
    for seq, chunk in enumerate(chunks, start=1):
        frames.append(Frame(TYPE_DATA, session_id, seq=seq, total=total, payload=chunk))
    frames.append(Frame(TYPE_FIN, session_id, seq=total + 1, total=total, payload=b"done"))
    return frames


def test_e2e_icmp_pipeline(monkeypatch):
    plain = "E2E ICMP äöü § 202c".encode("utf-8")
    psk = "e2e-icmp-key"
    sender_ip = "10.0.0.10"
    peer_ip = sender_ip
    captured = []

    def fake_send(pkt, iface, verbose):
        pkt["IP"].src = sender_ip
        captured.append(pkt)

    monkeypatch.setattr(sender_icmp_transport, "send", fake_send)
    for frame in _build_frames(plain, psk):
        sender_icmp_transport.send_frame("10.0.0.20", frame, iface="eth0")

    data_payloads = {}
    for pkt in captured:
        frame = receiver_icmp_transport.extract_frame(pkt, peer_ip)
        assert frame is not None
        if frame.msg_type == TYPE_DATA:
            data_payloads[frame.seq] = frame.payload

    encoded = b"".join(data_payloads[i] for i in sorted(data_payloads))
    assert decode_payload(encoded, psk=psk) == plain


def test_e2e_dns_pipeline(monkeypatch):
    plain = "E2E DNS äöü § 202d".encode("utf-8")
    psk = "e2e-dns-key"
    sender_ip = "10.0.0.10"
    peer_ip = sender_ip
    domain = "exfil.lab"
    port = 5300
    captured = []

    def fake_send(pkt, iface, verbose):
        pkt["IP"].src = sender_ip
        captured.append(pkt)

    monkeypatch.setattr(sender_dns_transport, "send", fake_send)
    for frame in _build_frames(plain, psk, chunk_size=20):
        sender_dns_transport.send_frame("10.0.0.20", frame, iface="eth0", dns_domain=domain, dns_port=port)

    data_payloads = {}
    for pkt in captured:
        frame = receiver_dns_transport.extract_frame(pkt, peer_ip, dns_domain=domain, dns_port=port)
        assert frame is not None
        if frame.msg_type == TYPE_DATA:
            data_payloads[frame.seq] = frame.payload

    encoded = b"".join(data_payloads[i] for i in sorted(data_payloads))
    assert decode_payload(encoded, psk=psk) == plain


def test_e2e_arp_pipeline(monkeypatch):
    plain = "E2E ARP äöü Netz".encode("utf-8")
    psk = "e2e-arp-key"
    sender_ip = "10.0.0.10"
    peer_ip = sender_ip
    captured = []

    monkeypatch.setattr(sender_arp_transport, "get_if_hwaddr", lambda iface: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(sender_arp_transport, "get_if_addr", lambda iface: sender_ip)

    def fake_sendp(pkt, iface, verbose):
        captured.append(pkt)

    monkeypatch.setattr(sender_arp_transport, "sendp", fake_sendp)
    for frame in _build_frames(plain, psk):
        sender_arp_transport.send_frame("10.0.0.20", frame, iface="eth0")

    data_payloads = {}
    for pkt in captured:
        frame = receiver_arp_transport.extract_frame(pkt, peer_ip)
        assert frame is not None
        if frame.msg_type == TYPE_DATA:
            data_payloads[frame.seq] = frame.payload

    encoded = b"".join(data_payloads[i] for i in sorted(data_payloads))
    assert decode_payload(encoded, psk=psk) == plain


def test_e2e_snmp_pipeline(monkeypatch):
    plain = "E2E SNMP äöü Monitor".encode("utf-8")
    psk = "e2e-snmp-key"
    sender_ip = "10.0.0.10"
    peer_ip = sender_ip
    oid = "1.3.6.1.4.1.55555.1.0"
    community = "public"
    port = 161
    captured = []

    def fake_send(pkt, iface, verbose):
        pkt["IP"].src = sender_ip
        captured.append(pkt)

    monkeypatch.setattr(sender_snmp_transport, "send", fake_send)
    for frame in _build_frames(plain, psk):
        sender_snmp_transport.send_frame(
            "10.0.0.20",
            frame,
            iface="eth0",
            snmp_oid=oid,
            snmp_port=port,
            snmp_community=community,
        )

    data_payloads = {}
    for pkt in captured:
        frame = receiver_snmp_transport.extract_frame(
            pkt,
            peer_ip=peer_ip,
            snmp_oid=oid,
            snmp_port=port,
            snmp_community=community,
        )
        assert frame is not None
        if frame.msg_type == TYPE_DATA:
            data_payloads[frame.seq] = frame.payload

    encoded = b"".join(data_payloads[i] for i in sorted(data_payloads))
    assert decode_payload(encoded, psk=psk) == plain
