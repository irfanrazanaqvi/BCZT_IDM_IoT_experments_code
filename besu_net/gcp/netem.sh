#!/usr/bin/env bash
# Optional: add artificial wide-area delay on every validator VM (e.g. ./netem.sh add 80 10). "./netem.sh del" removes it.
set -euo pipefail; cd "$(dirname "$0")"; source config.env
for i in 0 1 2 3; do
  case "$1" in
    add) CMD="IF=\$(ip route show default | awk '{print \$5}'); sudo tc qdisc replace dev \$IF root netem delay ${2:-80}ms ${3:-10}ms" ;;
    del) CMD="IF=\$(ip route show default | awk '{print \$5}'); sudo tc qdisc del dev \$IF root || true" ;;
    *) echo "usage: $0 add <delay_ms> <jitter_ms> | del"; exit 1 ;;
  esac
  gcloud compute ssh "${NODE_NAMES[$i]}" --zone="${ZONES[$i]}" --quiet --command "$CMD" &
done; wait
