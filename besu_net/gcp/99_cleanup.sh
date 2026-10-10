#!/usr/bin/env bash
# Deletes all VMs and the firewall rule so you stop paying. Run when finished.
set -euo pipefail; cd "$(dirname "$0")"; source config.env
for i in 0 1 2 3; do gcloud compute instances delete "${NODE_NAMES[$i]}" --zone="${ZONES[$i]}" --quiet & done
gcloud compute instances delete "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --quiet &
wait; gcloud compute firewall-rules delete besu-internal --quiet || true
echo "All Besu VMs deleted."
