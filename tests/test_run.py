from __future__ import annotations

import argparse
import sys

import run


def test_build_program_argv_sender_dns_uses_short_alias_defaults():
    args = argparse.Namespace(
        role="s",
        method="d",
        iface="\\Device\\NPF_TEST",
        peer="192.168.0.30",
        psk="lab-shared-key",
        infile="data/input.txt",
        outfile=None,
        pcap=None,
        log_level="INFO",
        dns_domain="exfil.lab",
        dns_port=5300,
        snmp_community="public",
        snmp_port=1161,
        snmp_oid="1.3.6.1.4.1.55555.1.0",
    )

    role, argv = run.build_program_argv(args)

    assert role == "sender"
    assert argv == [
        "sender.main",
        "--in",
        "data/input.txt",
        "--method",
        "dns",
        "--iface",
        "\\Device\\NPF_TEST",
        "--peer",
        "192.168.0.30",
        "--psk",
        "lab-shared-key",
        "--pcap",
        "captures/sender_dns.pcap",
        "--log-level",
        "INFO",
        "--dns-domain",
        "exfil.lab",
        "--dns-port",
        "5300",
    ]


def test_build_program_argv_receiver_arp_uses_method_specific_defaults():
    args = argparse.Namespace(
        role="receiver",
        method="arp",
        iface="\\Device\\NPF_TEST",
        peer="192.168.0.20",
        psk="lab-shared-key",
        infile="data/input.txt",
        outfile=None,
        pcap=None,
        log_level="INFO",
        dns_domain="exfil.lab",
        dns_port=5300,
        snmp_community="public",
        snmp_port=1161,
        snmp_oid="1.3.6.1.4.1.55555.1.0",
    )

    role, argv = run.build_program_argv(args)

    assert role == "receiver"
    assert argv == [
        "receiver.main",
        "--out",
        "receiver/output/output_arp.txt",
        "--method",
        "arp",
        "--iface",
        "\\Device\\NPF_TEST",
        "--peer",
        "192.168.0.20",
        "--psk",
        "lab-shared-key",
        "--pcap",
        "captures/receiver_arp.pcap",
        "--log-level",
        "INFO",
    ]


def test_dispatch_routes_to_sender(monkeypatch):
    captured = {}

    def fake_sender_main():
        captured["argv"] = sys.argv[:]
        return 0

    monkeypatch.setattr(run.sender_main, "main", fake_sender_main)

    exit_code = run.dispatch("sender", ["sender.main", "--method", "icmp"])

    assert exit_code == 0
    assert captured["argv"] == ["sender.main", "--method", "icmp"]


def test_normalize_role_and_method_reject_invalid_values():
    try:
        run.normalize_role("x")
    except ValueError as exc:
        assert "Unsupported role" in str(exc)
    else:
        raise AssertionError("normalize_role should reject invalid values")

    try:
        run.normalize_method("x")
    except ValueError as exc:
        assert "Unsupported method" in str(exc)
    else:
        raise AssertionError("normalize_method should reject invalid values")
