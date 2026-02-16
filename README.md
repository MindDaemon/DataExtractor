# Network Security Lab – ICMP Covert Channel (Educational Skeleton)

> **Lab-only project scaffold** for your university module.
> The code is intentionally explicit and test-friendly (no stealth/evasion features).

## Goal
Build two programs:

- **Sender (Program A)**: read text, encode, chunk, send via ICMP payload
- **Receiver (Program B)**: receive, verify integrity, reassemble, decode, print + write file

Additional requirements covered in this skeleton:

- integrity checks (CRC32 + final SHA-256)
- basic error correction (ACK/NACK + retry)
- `.pcap` generation from **both** programs
- clear architecture for documentation

## Quick Start

1. Create venv and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Terminal 1 (Receiver):
   ```bash
   sudo python -m receiver.main --iface eth0 --peer 10.0.0.10 --out receiver/output/output.txt
   ```

3. Terminal 2 (Sender):
   ```bash
   sudo python -m sender.main --iface eth0 --peer 10.0.0.20 --in data/input.txt
   ```

> Replace interface/IPs with your lab values.
> Root rights are often required for raw capture/send operations.

## Project Layout

```text
common/
  codec.py        # encoding/decoding pipeline
  frame.py        # binary frame format
  integrity.py    # CRC32 + SHA-256
  capture.py      # start/stop pcap capture subprocess
  config.py       # constants and defaults
sender/
  main.py         # Program A entry point
  transport.py    # send + wait_for_ack logic
receiver/
  main.py         # Program B entry point
  transport.py    # sniff loop + ACK/NACK replies
tests/
  test_codec.py
  test_frame.py
docs/
  architecture.md
scripts/
  run_sender.sh
  run_receiver.sh
```

## Notes for your report

- Explain why ICMP was chosen (simplicity, observability in Wireshark, lab reliability).
- Show packet examples from both pcap files (`sender_capture.pcap`, `receiver_capture.pcap`).
- Document where integrity check fails and how retry resolves it.
