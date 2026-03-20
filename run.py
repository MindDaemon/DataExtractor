from __future__ import annotations

import argparse
import sys

from common.cli import LOG_LEVELS
from receiver import main as receiver_main
from sender import main as sender_main

ROLE_MAP = {
    "s": "sender",
    "sender": "sender",
    "r": "receiver",
    "receiver": "receiver",
}

METHOD_MAP = {
    "i": "icmp",
    "icmp": "icmp",
    "d": "dns",
    "dns": "dns",
    "a": "arp",
    "arp": "arp",
    "s": "snmp",
    "snmp": "snmp",
}

DEFAULT_INFILE = "data/input.txt"
DEFAULT_OUTFILE_TEMPLATE = "receiver/output/output_{method}.txt"
DEFAULT_PCAP_TEMPLATE = "captures/{role}_{method}.pcap"
DEFAULT_DNS_DOMAIN = "exfil.lab"
DEFAULT_DNS_PORT = 5300
DEFAULT_SNMP_COMMUNITY = "public"
DEFAULT_SNMP_PORT = 1161
DEFAULT_SNMP_OID = "1.3.6.1.4.1.55555.1.0"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Short launcher for sender/receiver. Example: python run.py s d \"<iface>\" 192.168.0.30 my-psk"
    )
    p.add_argument("role", help="s|sender or r|receiver")
    p.add_argument("method", help="i|icmp, d|dns, a|arp, s|snmp")
    p.add_argument("iface", help="Scapy/Npcap interface name")
    p.add_argument("peer", help="Peer IPv4")
    p.add_argument("psk", help="Pre-shared key")
    p.add_argument("--in", dest="infile", default=DEFAULT_INFILE, help="Input file for sender")
    p.add_argument("--out", dest="outfile", default=None, help="Output file for receiver")
    p.add_argument("--pcap", default=None, help="Optional custom pcap path")
    p.add_argument("--log-level", choices=LOG_LEVELS, default="INFO", help="Log verbosity")
    p.add_argument("--dns-domain", default=DEFAULT_DNS_DOMAIN, help="DNS suffix for DNS mode")
    p.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT, help="DNS UDP port")
    p.add_argument("--snmp-community", default=DEFAULT_SNMP_COMMUNITY, help="SNMP community")
    p.add_argument("--snmp-port", type=int, default=DEFAULT_SNMP_PORT, help="SNMP UDP port")
    p.add_argument("--snmp-oid", default=DEFAULT_SNMP_OID, help="SNMP OID")
    return p.parse_args()


def normalize_role(value: str) -> str:
    try:
        return ROLE_MAP[value.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported role: {value}") from exc


def normalize_method(value: str) -> str:
    try:
        return METHOD_MAP[value.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported method: {value}") from exc


def build_program_argv(args: argparse.Namespace) -> tuple[str, list[str]]:
    role = normalize_role(args.role)
    method = normalize_method(args.method)
    pcap = args.pcap or DEFAULT_PCAP_TEMPLATE.format(role=role, method=method)

    common_args = [
        "--method",
        method,
        "--iface",
        args.iface,
        "--peer",
        args.peer,
        "--psk",
        args.psk,
        "--pcap",
        pcap,
        "--log-level",
        args.log_level,
    ]

    if method == "dns":
        common_args.extend(
            [
                "--dns-domain",
                args.dns_domain,
                "--dns-port",
                str(args.dns_port),
            ]
        )
    elif method == "snmp":
        common_args.extend(
            [
                "--snmp-community",
                args.snmp_community,
                "--snmp-port",
                str(args.snmp_port),
                "--snmp-oid",
                args.snmp_oid,
            ]
        )

    if role == "sender":
        return "sender", ["sender.main", "--in", args.infile, *common_args]

    outfile = args.outfile or DEFAULT_OUTFILE_TEMPLATE.format(method=method)
    return "receiver", ["receiver.main", "--out", outfile, *common_args]


def dispatch(role: str, argv: list[str]) -> int:
    old_argv = sys.argv[:]
    try:
        sys.argv = argv
        if role == "sender":
            return sender_main.main()
        return receiver_main.main()
    finally:
        sys.argv = old_argv


def main() -> int:
    try:
        role, argv = build_program_argv(parse_args())
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    return dispatch(role, argv)


if __name__ == "__main__":
    raise SystemExit(main())
