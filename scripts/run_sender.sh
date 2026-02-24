#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-eth0}"
PEER="${2:-10.0.0.20}"
INFILE="${3:-data/input.txt}"
PSK="${4:-${NETSEC_PSK:-}}"

if [[ -z "$PSK" ]]; then
  echo "Missing PSK. Pass as 4th arg or set NETSEC_PSK."
  exit 2
fi

sudo python -m sender.main --iface "$IFACE" --peer "$PEER" --in "$INFILE" --psk "$PSK"
