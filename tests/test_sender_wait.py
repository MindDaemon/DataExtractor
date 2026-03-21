from __future__ import annotations

from common.config import TYPE_ACK, TYPE_NACK
from common.frame import Frame
from sender import main as sender_main


class FakeSniffer:
    def __init__(self, iface, filter, store):
        self.iface = iface
        self.filter = filter
        self.store = store
        self.results = []
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def test_wait_for_control_reply_starts_sniffer_before_send(monkeypatch):
    events = []
    sniffer = FakeSniffer("eth0", "icmp", True)

    monkeypatch.setattr(sender_main, "AsyncSniffer", lambda iface, filter, store: sniffer)
    monkeypatch.setattr(sender_main.time, "sleep", lambda _: None)

    ack_frame = Frame(msg_type=TYPE_ACK, session_id=7, seq=3, total=9, payload=b"")

    def send_packet():
        events.append("send")
        sniffer.results = ["ack"]

    def parse_control_packet(pkt):
        events.append(f"parse:{pkt}")
        return ack_frame if pkt == "ack" else None

    ok, status = sender_main.wait_for_control_reply(
        send_packet_fn=send_packet,
        parse_control_packet_fn=parse_control_packet,
        iface="eth0",
        sniff_filter="icmp",
        session_id=7,
        seq=3,
        timeout=0.1,
    )

    assert sniffer.started is True
    assert sniffer.stopped is True
    assert events[0] == "send"
    assert ok is True
    assert status == "ACK"


def test_wait_for_control_reply_returns_nack_reason(monkeypatch):
    sniffer = FakeSniffer("eth0", "udp", True)

    monkeypatch.setattr(sender_main, "AsyncSniffer", lambda iface, filter, store: sniffer)
    monkeypatch.setattr(sender_main.time, "sleep", lambda _: None)

    nack_frame = Frame(msg_type=TYPE_NACK, session_id=11, seq=5, total=5, payload=b"MISSING:2")

    def send_packet():
        sniffer.results = ["nack"]

    def parse_control_packet(pkt):
        return nack_frame if pkt == "nack" else None

    ok, status = sender_main.wait_for_control_reply(
        send_packet_fn=send_packet,
        parse_control_packet_fn=parse_control_packet,
        iface="eth0",
        sniff_filter="udp",
        session_id=11,
        seq=5,
        timeout=0.1,
    )

    assert ok is False
    assert status == "NACK:MISSING:2"


def test_wait_for_control_reply_times_out_when_no_matching_frame(monkeypatch):
    sniffer = FakeSniffer("eth0", "arp", True)

    monkeypatch.setattr(sender_main, "AsyncSniffer", lambda iface, filter, store: sniffer)
    monkeypatch.setattr(sender_main.time, "sleep", lambda _: None)

    def send_packet():
        sniffer.results = []

    def parse_control_packet(pkt):
        return None

    ok, status = sender_main.wait_for_control_reply(
        send_packet_fn=send_packet,
        parse_control_packet_fn=parse_control_packet,
        iface="eth0",
        sniff_filter="arp",
        session_id=1,
        seq=1,
        timeout=0.1,
    )

    assert ok is False
    assert status == "TIMEOUT"
