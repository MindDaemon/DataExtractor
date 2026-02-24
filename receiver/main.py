from __future__ import annotations

import argparse
import logging
import os

from scapy.all import sniff  # type: ignore

from common.capture import start_capture, stop_capture
from common.cli import (
    LOG_LEVELS,
    configure_logging,
    validate_ipv4,
    validate_non_empty,
    validate_snmp_oid,
    validate_udp_port,
)
from common.codec import decode_payload
from common.config import TYPE_DATA, TYPE_FIN, TYPE_HELLO
from common.dns_tunnel import normalize_domain
from common.frame import Frame
from common.integrity import sha256_hex
from receiver import arp_transport, dns_transport, snmp_transport, transport as icmp_transport


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Program B: covert-channel receiver")
    p.add_argument("--iface", required=True, help="Network interface (e.g., eth0)")
    p.add_argument("--peer", required=True, help="Sender IPv4")
    p.add_argument("--out", required=True, help="Output text file")
    p.add_argument("--method", choices=("icmp", "dns", "arp", "snmp"), default="icmp", help="Transport protocol")
    p.add_argument("--psk", default=None, help="Pre-shared key (or env NETSEC_PSK)")
    p.add_argument("--dns-domain", default="exfil.lab", help="Domain suffix for DNS method")
    p.add_argument("--dns-port", type=int, default=53, help="UDP port for DNS method")
    p.add_argument("--snmp-community", default="public", help="SNMP community for SNMP method")
    p.add_argument("--snmp-port", type=int, default=161, help="UDP port for SNMP method")
    p.add_argument("--snmp-oid", default="1.3.6.1.4.1.55555.1.0", help="Varbind OID for SNMP method")
    p.add_argument("--pcap", default="captures/receiver_capture.pcap")
    p.add_argument("--log-level", choices=LOG_LEVELS, default="INFO", help="Log verbosity")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    logger = logging.getLogger("receiver")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    chunks: dict[int, bytes] = {}
    session_id = None
    total_expected = None
    fin_received = False
    expected_plain_sha = None

    try:
        validate_ipv4(args.peer, "--peer")
        if args.method == "dns":
            validate_udp_port(args.dns_port, "--dns-port")
            dns_domain = normalize_domain(args.dns_domain)
        elif args.method == "snmp":
            validate_udp_port(args.snmp_port, "--snmp-port")
            validate_non_empty(args.snmp_community, "--snmp-community")
            validate_snmp_oid(args.snmp_oid)
            dns_domain = None
        else:
            dns_domain = None
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    if args.method == "icmp":
        sniff_filter = f"icmp and host {args.peer}"

        def parse_frame(pkt) -> Frame | None:
            return icmp_transport.extract_frame(pkt, args.peer)

        def send_ack_frame(frame: Frame) -> None:
            icmp_transport.send_ack(args.peer, args.iface, frame.session_id, frame.seq, frame.total)

        def send_nack_frame(frame: Frame, reason: str) -> None:
            icmp_transport.send_nack(args.peer, args.iface, frame.session_id, frame.seq, frame.total, reason=reason)
    elif args.method == "dns":
        sniff_filter = f"udp and host {args.peer} and port {args.dns_port}"

        def parse_frame(pkt) -> Frame | None:
            return dns_transport.extract_frame(pkt, args.peer, dns_domain=dns_domain, dns_port=args.dns_port)

        def send_ack_frame(frame: Frame) -> None:
            dns_transport.send_ack(
                args.peer,
                args.iface,
                frame.session_id,
                frame.seq,
                frame.total,
                dns_domain=dns_domain,
                dns_port=args.dns_port,
            )

        def send_nack_frame(frame: Frame, reason: str) -> None:
            dns_transport.send_nack(
                args.peer,
                args.iface,
                frame.session_id,
                frame.seq,
                frame.total,
                dns_domain=dns_domain,
                dns_port=args.dns_port,
                reason=reason,
            )
    elif args.method == "arp":
        sniff_filter = f"arp and host {args.peer}"

        def parse_frame(pkt) -> Frame | None:
            return arp_transport.extract_frame(pkt, args.peer)

        def send_ack_frame(frame: Frame) -> None:
            arp_transport.send_ack(args.peer, args.iface, frame.session_id, frame.seq, frame.total)

        def send_nack_frame(frame: Frame, reason: str) -> None:
            arp_transport.send_nack(args.peer, args.iface, frame.session_id, frame.seq, frame.total, reason=reason)
    else:
        sniff_filter = f"udp and host {args.peer} and port {args.snmp_port}"

        def parse_frame(pkt) -> Frame | None:
            return snmp_transport.extract_frame(
                pkt,
                args.peer,
                snmp_oid=args.snmp_oid,
                snmp_port=args.snmp_port,
                snmp_community=args.snmp_community,
            )

        def send_ack_frame(frame: Frame) -> None:
            snmp_transport.send_ack(
                args.peer,
                args.iface,
                frame.session_id,
                frame.seq,
                frame.total,
                snmp_oid=args.snmp_oid,
                snmp_port=args.snmp_port,
                snmp_community=args.snmp_community,
            )

        def send_nack_frame(frame: Frame, reason: str) -> None:
            snmp_transport.send_nack(
                args.peer,
                args.iface,
                frame.session_id,
                frame.seq,
                frame.total,
                snmp_oid=args.snmp_oid,
                snmp_port=args.snmp_port,
                snmp_community=args.snmp_community,
                reason=reason,
            )

    cap = start_capture(args.iface, args.pcap, bpf_filter=sniff_filter)
    logger.info("Listening on %s for peer %s with %s", args.iface, args.peer, args.method.upper())

    def handle_packet(pkt):
        nonlocal session_id, total_expected, fin_received, expected_plain_sha

        frame = parse_frame(pkt)
        if frame is None:
            return

        if session_id is None:
            session_id = frame.session_id
        if frame.session_id != session_id:
            return

        if frame.msg_type == TYPE_HELLO:
            total_expected = frame.total
            send_ack_frame(frame)
            logger.info("[HELLO] session=%s total=%s", session_id, total_expected)
            return

        if frame.msg_type == TYPE_DATA:
            total_expected = frame.total
            if frame.seq < 1 or frame.seq > frame.total:
                send_nack_frame(frame, "BAD_SEQ")
                return
            chunks[frame.seq] = frame.payload
            send_ack_frame(frame)
            logger.info("[DATA] seq=%s/%s stored (%sB)", frame.seq, frame.total, len(frame.payload))
            return

        if frame.msg_type == TYPE_FIN:
            try:
                expected_plain_sha = frame.payload.decode()
            except Exception:
                expected_plain_sha = None

            if total_expected is None:
                send_nack_frame(frame, "NO_HELLO")
                return

            missing = [i for i in range(1, total_expected + 1) if i not in chunks]
            if missing:
                send_nack_frame(frame, f"MISSING:{missing[0]}")
                logger.warning("[FIN] missing seq=%s -> NACK", missing[0])
                return

            send_ack_frame(frame)
            fin_received = True
            logger.info("[FIN] received + ACK")

    try:
        while not fin_received:
            sniff(
                iface=args.iface,
                filter=sniff_filter,
                prn=handle_packet,
                store=False,
                timeout=1,
            )

        if not chunks:
            logger.error("No data chunks received")
            return 2
        if total_expected is None:
            logger.error("Missing total chunk count")
            return 2

        encoded = b"".join(chunks[i] for i in range(1, total_expected + 1))
        try:
            plain = decode_payload(encoded, psk=args.psk)
        except ValueError as exc:
            logger.error("Decoding failed: %s", exc)
            return 2

        print("\n===== Reconstructed Message =====")
        try:
            print(plain.decode("utf-8"))
        except UnicodeDecodeError:
            print(plain)
        print("=================================\n")

        with open(args.out, "wb") as f:
            f.write(plain)

        got_sha = sha256_hex(plain)
        logger.info("Written: %s", args.out)
        logger.info("SHA256: %s", got_sha)
        if expected_plain_sha:
            logger.info("Expected: %s", expected_plain_sha)
            logger.info("Integrity: %s", "OK" if got_sha == expected_plain_sha else "MISMATCH")
        return 0
    finally:
        stop_capture(cap)


if __name__ == "__main__":
    raise SystemExit(main())
