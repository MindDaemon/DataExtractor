# Architecture Draft

## Components

- **Program A (Sender)**:
  - Reads plaintext file
  - Encodes payload (zlib + base64)
  - Splits into fixed-size chunks
  - Sends ICMP frames with sequence numbers
  - Waits for ACK, retries on timeout/NACK
  - Sends FIN with SHA-256 of original text

- **Program B (Receiver)**:
  - Sniffs ICMP frames from peer
  - Validates frame integrity (CRC32)
  - Stores chunks by sequence number
  - Sends ACK/NACK
  - Reassembles + decodes after FIN
  - Prints message and writes output file

## Reliability Model
Stop-and-Wait ARQ:
1. Send `DATA(seq=n)`
2. Wait ACK(n)
3. Retry on timeout up to max retries

## Packet Capture
Both programs spawn local `tcpdump` and write pcap:
- `captures/sender_capture.pcap`
- `captures/receiver_capture.pcap`
