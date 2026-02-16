from __future__ import annotations
import argparse
import os
from collections import defaultdict

from scapy.all import sniff, ICMP, Raw, IP  # type: ignore

from common.capture import start_capture, stop_capture
from common.codec import decode_payload
from common.config import TYPE_DATA, TYPE_FIN, TYPE_HELLO
from common.frame import Frame
from common.integrity import sha256_hex
from receiver.transport import send_ack, send_nack

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Program B: ICMP receiver")
    p.add_argument("--iface", required=True, help="Network interface (e.g., eth0)")
    p.add_argument("--peer", required=True, help="Sender IPv4")
    p.add_argument("--out", required=True, help="Output text file")
    p.add_argument("--pcap", default="captures/receiver_capture.pcap")
    return p.parse_args()

def main() -> int:
    args = parse_args()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    chunks: dict[int, bytes] = {}
    session_id = None
    total_expected = None
    fin_received = False
    expected_plain_sha = None

    cap = start_capture(args.iface, args.pcap, bpf_filter=f"icmp and host {args.peer}")

    print(f"[+] Listening on {args.iface} for peer {args.peer} ...")

    def handle_packet(pkt):
        nonlocal session_id, total_expected, fin_received, expected_plain_sha

        if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw) or not pkt.haslayer(IP):
            return
        if pkt[IP].src != args.peer:
            return

        raw = bytes(pkt[Raw].load)
        try:
            frame = Frame.unpack(raw)
        except Exception:
            return

        # Session bootstrap
        if session_id is None:
            session_id = frame.session_id

        if frame.session_id != session_id:
            return

        if frame.msg_type == TYPE_HELLO:
            total_expected = frame.total
            print(f"[HELLO] session={session_id} total={total_expected}")
            return

        if frame.msg_type == TYPE_DATA:
            total_expected = frame.total
            chunks[frame.seq] = frame.payload
            send_ack(args.peer, args.iface, frame.session_id, frame.seq, frame.total)
            print(f"[DATA] seq={frame.seq}/{frame.total} stored ({len(frame.payload)}B)")
            return

        if frame.msg_type == TYPE_FIN:
            fin_received = True
            try:
                expected_plain_sha = frame.payload.decode()
            except Exception:
                expected_plain_sha = None
            print("[FIN] received")
            return

    try:
        while not fin_received:
            sniff(
                iface=args.iface,
                filter=f"icmp and src host {args.peer}",
                prn=handle_packet,
                store=False,
                timeout=1,
            )

        if not chunks:
            print("[!] No data chunks received.")
            return 2

        if total_expected is None:
            print("[!] Missing total chunk count.")
            return 2

        missing = [i for i in range(1, total_expected + 1) if i not in chunks]
        if missing:
            print(f"[!] Missing chunks detected: {missing[:10]}{'...' if len(missing) > 10 else ''}")
            # minimal correction path: notify sender for first missing chunk
            send_nack(args.peer, args.iface, session_id, missing[0], total_expected, reason="MISSING")
            return 3

        encoded = b"".join(chunks[i] for i in range(1, total_expected + 1))
        plain = decode_payload(encoded)

        print("\n===== Reconstructed Message =====")
        try:
            print(plain.decode("utf-8"))
        except UnicodeDecodeError:
            print(plain)
        print("=================================\n")

        with open(args.out, "wb") as f:
            f.write(plain)

        got_sha = sha256_hex(plain)
        print(f"[+] Written: {args.out}")
        print(f"[+] SHA256:  {got_sha}")
        if expected_plain_sha:
            print(f"[+] Expected:{expected_plain_sha}")
            print("[+] Integrity: OK" if got_sha == expected_plain_sha else "[!] Integrity: MISMATCH")

        return 0
    finally:
        stop_capture(cap)

if __name__ == "__main__":
    raise SystemExit(main())
