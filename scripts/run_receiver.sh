#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-eth0}"
PEER="${2:-10.0.0.10}"
OUT="${3:-receiver/output/output.txt}"
PSK="${4:-${NETSEC_PSK:-}}"

if [[ -z "$PSK" ]]; then
  echo "Missing PSK. Pass as 4th arg or set NETSEC_PSK."
  exit 2
fi

sudo python -m receiver.main --iface "$IFACE" --peer "$PEER" --out "$OUT" --psk "$PSK"
