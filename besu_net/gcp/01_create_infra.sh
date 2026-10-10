#!/usr/bin/env bash
# Run in Google Cloud Shell (or any shell with gcloud logged in). Creates 4 validator VMs + 1 load generator.
set -euo pipefail; cd "$(dirname "$0")"; source config.env
gcloud config set project "$PROJECT" >/dev/null
gcloud services enable compute.googleapis.com
# The default VPC already allows internal traffic; this rule makes it explicit and survives a deleted default network.
gcloud compute firewall-rules create besu-internal --network=default --allow=tcp:30303,udp:30303,tcp:8545 \
  --source-tags=besu --target-tags=besu 2>/dev/null || echo "firewall rule exists (ok)"
STARTUP='#!/bin/bash
apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-21-jre-headless curl unzip git tar netcat-openbsd
touch /var/lib/startup-done'
for i in 0 1 2 3; do
  gcloud compute instances create "${NODE_NAMES[$i]}" --zone="${ZONES[$i]}" --machine-type="$MACHINE" \
    --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" --boot-disk-size=30GB \
    --tags=besu --metadata=enable-oslogin=FALSE --metadata-from-file=startup-script=<(echo "$STARTUP") &
done
gcloud compute instances create "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --machine-type="$MACHINE" \
  --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" --boot-disk-size=30GB \
  --tags=besu --metadata=enable-oslogin=FALSE --metadata-from-file=startup-script=<(echo "$STARTUP") &
wait
echo "VMs created. Wait ~2 minutes for the startup script (Java install), then run 02_setup_network.sh"
gcloud compute instances list --filter="name~^besu-" --format="table(name,zone.basename(),networkInterfaces[0].networkIP,status)"
