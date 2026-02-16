#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-eth0}"
PEER="${2:-10.0.0.20}"
INFILE="${3:-data/input.txt}"

sudo python -m sender.main --iface "$IFACE" --peer "$PEER" --in "$INFILE"
