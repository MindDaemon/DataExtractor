from __future__ import annotations

import argparse
from pathlib import Path

from common.config import POST_FIN_GRACE_PERIOD, TYPE_DATA, TYPE_FIN, TYPE_HELLO
from common.frame import Frame
from receiver import main as receiver_main


def test_receiver_fin_grace_acknowledges_duplicate_fin(monkeypatch, tmp_path: Path):
    output_path = tmp_path / "output.txt"
    frame_map = {
        "hello": Frame(TYPE_HELLO, session_id=77, seq=0, total=1, payload=b"HELLO"),
        "data": Frame(TYPE_DATA, session_id=77, seq=1, total=1, payload=b"encoded"),
        "fin": Frame(TYPE_FIN, session_id=77, seq=2, total=1, payload=b"expected-sha"),
        "fin-dup": Frame(TYPE_FIN, session_id=77, seq=2, total=1, payload=b"expected-sha"),
    }
    acked = []
    stopped = {"called": False}
    clock = {"t": 0.0}
    sniff_calls = {"count": 0}

    monkeypatch.setattr(
        receiver_main,
        "parse_args",
        lambda: argparse.Namespace(
            iface="eth0",
            peer="10.0.0.10",
            out=str(output_path),
            method="icmp",
            psk="lab-shared-key",
            dns_domain="exfil.lab",
            dns_port=53,
            snmp_community="public",
            snmp_port=161,
            snmp_oid="1.3.6.1.4.1.55555.1.0",
            pcap="captures/test_receiver.pcap",
            log_level="INFO",
        ),
    )
    monkeypatch.setattr(receiver_main, "start_capture", lambda *args, **kwargs: object())
    monkeypatch.setattr(receiver_main, "stop_capture", lambda handle: stopped.__setitem__("called", True))
    monkeypatch.setattr(receiver_main, "decode_payload", lambda encoded, psk=None: b"decoded-text")
    monkeypatch.setattr(receiver_main, "sha256_hex", lambda data: "expected-sha")
    monkeypatch.setattr(receiver_main.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(receiver_main.icmp_transport, "extract_frame", lambda pkt, peer_ip: frame_map.get(pkt))
    monkeypatch.setattr(
        receiver_main.icmp_transport,
        "send_ack",
        lambda peer_ip, iface, session_id, seq, total: acked.append((session_id, seq, total)),
    )
    monkeypatch.setattr(receiver_main.icmp_transport, "send_nack", lambda *args, **kwargs: None)

    def fake_sniff(iface, filter, prn, store, timeout):
        if sniff_calls["count"] == 0:
            for timestamp, pkt in ((0.1, "hello"), (0.2, "data"), (0.3, "fin")):
                clock["t"] = timestamp
                prn(pkt)
            clock["t"] = 0.4
        elif sniff_calls["count"] == 1:
            clock["t"] = 0.8
            prn("fin-dup")
            clock["t"] = 0.9
        else:
            clock["t"] = POST_FIN_GRACE_PERIOD + 0.4
        sniff_calls["count"] += 1

    monkeypatch.setattr(receiver_main, "sniff", fake_sniff)

    exit_code = receiver_main.main()

    assert exit_code == 0
    assert acked == [
        (77, 0, 1),
        (77, 1, 1),
        (77, 2, 1),
        (77, 2, 1),
    ]
    assert output_path.read_bytes() == b"decoded-text"
    assert stopped["called"] is True
