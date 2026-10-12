#!/usr/bin/env bash
# Run in Cloud Shell. Each node should report the same block height, 3 peers, and 4 validators.
set -euo pipefail; cd "$(dirname "$0")"; source config.env
LG() { for a in 1 2 3 4 5; do gcloud compute ssh "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --quiet --command "$1" && return 0; echo "  gcloud ssh failed (attempt $a), retrying in 30 s..." >&2; sleep 30; done; return 1; }
LG 'source ~/hosts.env; for ip in "${NODE_IPS[@]}"; do
  echo "== $ip"; for m in eth_blockNumber net_peerCount; do
    curl -s -m 5 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"$m\",\"params\":[],\"id\":1}" http://$ip:8545; echo; done
  curl -s -m 5 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"qbft_getValidatorsByBlockNumber\",\"params\":[\"latest\"],\"id\":1}" http://$ip:8545 | head -c 300; echo
done'
