from __future__ import annotations
import argparse
import math
import os
import random
import sys
import time

from common.capture import start_capture, stop_capture
from common.codec import encode_payload
from common.config import RuntimeConfig, TYPE_DATA, TYPE_FIN, TYPE_HELLO
from common.frame import Frame
from common.integrity import sha256_hex
from sender.transport import send_frame, wait_for_ack

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Program A: ICMP sender")
    p.add_argument("--iface", required=True, help="Network interface (e.g., eth0)")
    p.add_argument("--peer", required=True, help="Receiver IPv4")
    p.add_argument("--in", dest="infile", required=True, help="Input text file")
    p.add_argument("--chunk-size", type=int, default=256)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--retries", type=int, default=4)
    p.add_argument("--pcap", default="captures/sender_capture.pcap")
    return p.parse_args()

def chunkify(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

def main() -> int:
    args = parse_args()
    cfg = RuntimeConfig(
        iface=args.iface,
        peer_ip=args.peer,
        timeout=args.timeout,
        retries=args.retries,
        chunk_size=args.chunk_size,
    )

    if not os.path.isfile(args.infile):
        print(f"[!] Input file not found: {args.infile}")
        return 2

    plain = open(args.infile, "rb").read()
    encoded = encode_payload(plain)
    chunks = chunkify(encoded, cfg.chunk_size)
    total = len(chunks)
    session_id = random.randint(1, 0xFFFFFFFF)

    print(f"[+] Session: {session_id}")
    print(f"[+] Input bytes: {len(plain)} | Encoded bytes: {len(encoded)} | Chunks: {total}")
    print(f"[+] Plain SHA256: {sha256_hex(plain)}")

    cap = start_capture(cfg.iface, args.pcap, bpf_filter=f"icmp and host {cfg.peer_ip}")
    try:
        # HELLO
        hello = Frame(TYPE_HELLO, session_id, seq=0, total=total, payload=b"HELLO")
        send_frame(cfg.peer_ip, hello, cfg.iface)

        for seq, chunk in enumerate(chunks, start=1):
            frame = Frame(TYPE_DATA, session_id, seq=seq, total=total, payload=chunk)
            sent = False
            for attempt in range(1, cfg.retries + 1):
                send_frame(cfg.peer_ip, frame, cfg.iface)
                ok = wait_for_ack(
                    iface=cfg.iface,
                    peer_ip=cfg.peer_ip,
                    session_id=session_id,
                    seq=seq,
                    timeout=cfg.timeout,
                )
                if ok:
                    sent = True
                    print(f"[DATA {seq}/{total}] ACK (attempt {attempt})")
                    break
                print(f"[DATA {seq}/{total}] no ACK -> retry {attempt}/{cfg.retries}")

            if not sent:
                print(f"[!] Failed to deliver seq={seq}. Aborting.")
                return 3

        fin_payload = sha256_hex(plain).encode()
        fin = Frame(TYPE_FIN, session_id, seq=total + 1, total=total, payload=fin_payload)
        send_frame(cfg.peer_ip, fin, cfg.iface)
        print("[+] FIN sent. Transfer complete.")
        return 0
    finally:
        stop_capture(cap)

if __name__ == "__main__":
    raise SystemExit(main())
