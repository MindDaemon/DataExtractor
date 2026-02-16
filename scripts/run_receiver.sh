#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-eth0}"
PEER="${2:-10.0.0.10}"
OUT="${3:-receiver/output/output.txt}"

sudo python -m receiver.main --iface "$IFACE" --peer "$PEER" --out "$OUT"
