#!/usr/bin/env bash
# Run in Cloud Shell. Each node should report the same block height, 3 peers, and 4 validators.
set -euo pipefail; cd "$(dirname "$0")"; source config.env
# retry only when ssh itself fails (exit 255 or a gcloud API error); never re-run a command that ran and failed
LG() { for a in 1 2 3 4 5; do gcloud compute ssh "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --quiet --command "$1"; rc=$?; [ $rc -eq 0 ] && return 0; [ $rc -ne 255 ] && [ $rc -ne 1 ] && return $rc; echo "  gcloud ssh failed (rc=$rc, attempt $a), retrying in 30 s..." >&2; sleep 30; done; return 1; }
LG 'source ~/hosts.env; for ip in "${NODE_IPS[@]}"; do
  echo "== $ip"; for m in eth_blockNumber net_peerCount; do
    curl -s -m 5 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"$m\",\"params\":[],\"id\":1}" http://$ip:8545; echo; done
  curl -s -m 5 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"qbft_getValidatorsByBlockNumber\",\"params\":[\"latest\"],\"id\":1}" http://$ip:8545 | head -c 300; echo
done'
