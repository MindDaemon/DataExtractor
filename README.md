# Network Security – Educational Covert Channel

> The code is intentionally explicit and test-friendly (no stealth/evasion features).

## My Goal
Build two programs:

- **Sender (Program A)**: read text, compress+encrypt, chunk, send via ICMP/DNS/ARP/SNMP payload
- **Receiver (Program B)**: receive, verify integrity, reassemble, decrypt+decode, print + write file

Additional requirements covered:

- integrity checks (CRC32 + final SHA-256)
- basic error correction (ACK/NACK + retry)
- `.pcap` generation from both programs
- clear architecture for documentation

## Quick Start

1. Create venv and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Terminal 1 (Receiver, ICMP):
   ```bash
   sudo python -m receiver.main --method icmp --iface eth0 --peer 10.0.0.10 --out receiver/output/output.txt --psk "lab-shared-key"
   ```

3. Terminal 2 (Sender, ICMP):
   ```bash
   sudo python -m sender.main --method icmp --iface eth0 --peer 10.0.0.20 --in data/input.txt --psk "lab-shared-key"
   ```

4. Optional DNS mode:
   ```bash
   sudo python -m receiver.main --method dns --iface eth0 --peer 10.0.0.10 --out receiver/output/output.txt --psk "lab-shared-key" --dns-domain exfil.lab
   sudo python -m sender.main --method dns --iface eth0 --peer 10.0.0.20 --in data/input.txt --psk "lab-shared-key" --dns-domain exfil.lab
   ```

5. Optional ARP mode:
   ```bash
   sudo python -m receiver.main --method arp --iface eth0 --peer 10.0.0.10 --out receiver/output/output.txt --psk "lab-shared-key"
   sudo python -m sender.main --method arp --iface eth0 --peer 10.0.0.20 --in data/input.txt --psk "lab-shared-key"
   ```

6. Optional SNMP mode:
   ```bash
   sudo python -m receiver.main --method snmp --iface eth0 --peer 10.0.0.10 --out receiver/output/output.txt --psk "lab-shared-key" --snmp-community public --snmp-oid 1.3.6.1.4.1.55555.1.0
   sudo python -m sender.main --method snmp --iface eth0 --peer 10.0.0.20 --in data/input.txt --psk "lab-shared-key" --snmp-community public --snmp-oid 1.3.6.1.4.1.55555.1.0
   ```

> Replace interface/IPs with lab values.
> Root rights are often required for raw capture/send operations.
> `--psk` (or environment variable `NETSEC_PSK`) is required; there is no built-in default key.
> DNS mode auto-reduces `--chunk-size` to fit DNS label limits.
> You can set `--log-level DEBUG|INFO|WARNING|ERROR` on sender/receiver.

## Current Project Layout

```text
common/
  codec.py        # encoding/decoding pipeline
  dns_tunnel.py   # DNS qname mapping helpers
  frame.py        # binary frame format
  integrity.py    # CRC32 + SHA-256
  capture.py      # start/stop pcap capture subprocess
  config.py       # constants and defaults
sender/
  main.py         # Program A entry point
  arp_transport.py# ARP send + wait_for_ack logic
  transport.py    # ICMP send + wait_for_ack logic
  dns_transport.py# DNS send + wait_for_ack logic
  snmp_transport.py# SNMP send + wait_for_ack logic
receiver/
  main.py         # Program B entry point
  arp_transport.py# ARP parsing + ACK/NACK replies
  transport.py    # ICMP parsing + ACK/NACK replies
  dns_transport.py# DNS parsing + ACK/NACK replies
  snmp_transport.py# SNMP parsing + ACK/NACK replies
tests/
  test_cli_validation.py
  test_codec.py
  test_dns_tunnel.py
  test_e2e_methods.py
  test_frame.py
  test_transport_integration.py
docs/
  architecture.md
scripts/
  run_sender.sh
  run_receiver.sh
```

## Method Packet Shapes

- ICMP: `IP / ICMP(Echo Request) / Raw(FrameBytes)`
- DNS: `IP / UDP / DNS(qname=<base32(frame)>.<domain>)`
- ARP: `Ether / ARP / Raw(FrameBytes)`
- SNMP: `IP / UDP / SNMP(SetRequest/Response, varbind.value=FrameBytes)`

## Context: Stealth vs. Transparency

### How attackers would approach this in practice (high-level)
- In real incidents, attackers generally try to make traffic blend into expected protocol behavior.
- The goal is to reduce detection likelihood by avoiding obvious, repetitive anomalies.
- This project intentionally does **not** implement such evasion behavior.

### Current project stance
- The implementation is explicit, deterministic, and test-driven.
- Protocol mappings are clear and easy to inspect in Wireshark/pcap.
- Reliability and integrity are prioritized: framing, CRC checks, ACK/NACK retries, final SHA-256 check.

### Why I chose this
- My use-case requires correct protocol-based transfer, non-plaintext coding/encryption, integrity checks, error correction, and reproducible demonstration.
- A transparent design improves technical explainability, grading clarity, and demo reliability.
- It also supports the required documentation quality (architecture, mechanism descriptions, verification evidence).

### Blue-team perspective: detection and mitigation
- Build per-protocol baselines (ICMP, DNS, ARP, SNMP) and alert on deviations.
- Apply egress controls and segmentation (restrict unnecessary protocol paths).
- Monitor DNS/SNMP/ICMP telemetry and correlate with host/network context.
- Use IDS/IPS/anomaly detection plus pcap review to identify suspicious payload patterns.
- Enforce least privilege and hardening to reduce attacker foothold and lateral movement options.
