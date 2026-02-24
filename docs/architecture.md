# Architecture Draft

## Components

- **Transport abstraction**:
  - Shared frame/retry/integrity logic for all methods
  - Selectable transport: `icmp`, `dns`, `arp`, or `snmp`

- **Program A (Sender)**:
  - Reads plaintext file
  - Encodes payload (zlib + AES-GCM, PSK-based key derivation)
  - Validates runtime args (peer IPv4, method-specific ports/options)
  - Splits into fixed-size chunks
  - Sends frames with sequence numbers over selected transport
  - Waits for ACK, retries on timeout/NACK (HELLO, DATA, FIN)
  - Sends FIN with SHA-256 of original text
  - Logs events with configurable log level

- **Program B (Receiver)**:
  - Sniffs ICMP, DNS, ARP, or SNMP packets from peer
  - Validates runtime args (peer IPv4, method-specific ports/options)
  - Validates frame integrity (CRC32)
  - Stores chunks by sequence number
  - Sends ACK/NACK for HELLO/DATA/FIN
  - Reassembles + decodes after FIN
  - Prints message and writes output file
  - Logs events with configurable log level

## ICMP Mapping
- Data/control are carried in ICMP Echo payload (`Raw(FrameBytes)`).
- Receiver filters by sender IPv4 and attempts strict frame unpacking.
- ACK/NACK reuse the same ICMP payload frame format.

## DNS Mapping
- Frames are Base32-encoded into DNS query names (`qname`) under a configurable suffix domain.
- ACK/NACK control frames use the same DNS mapping in the reverse direction.
- Sender reduces chunk size in DNS mode to satisfy DNS qname length constraints.

## ARP Mapping
- Frames are embedded in ARP payload bytes (`Raw` after ARP header).
- Sender emits ARP requests; receiver sends control replies via ARP replies.
- Receiver validates ARP sender IPv4 (`psrc`) against configured peer before unpacking frames.

## SNMP Mapping
- Frames are stored in SNMP varbind value as an octet string.
- Sender sends SNMP SetRequest PDUs; receiver returns SNMP Response PDUs for ACK/NACK.
- Receiver validates SNMP source IP, UDP port, community, and configured OID.

## Security and Robustness Notes
- PSK is mandatory (`--psk` or `NETSEC_PSK`); there is no hardcoded default key.
- Sender and receiver enforce protocol-specific validation before starting.
- Tests include transport-level and end-to-end pipeline checks for each method.

## Reliability Model
Stop-and-Wait ARQ:
1. Send `HELLO(seq=0)` and wait ACK(0)
2. Send `DATA(seq=n)` and wait ACK(n)
3. Retry on timeout up to max retries
4. Send `FIN(seq=total+1)` and wait ACK(total+1)

## Packet Capture
Both programs spawn local `tcpdump` and write pcap:
- `captures/sender_capture.pcap`
- `captures/receiver_capture.pcap`
