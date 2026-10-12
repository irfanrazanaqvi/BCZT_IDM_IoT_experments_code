#!/usr/bin/env bash
# Run in Cloud Shell. Installs Node + the repo on the load generator, compiles the contracts, runs the benchmark
# (with fault test) and copies the result JSON files back into ./results_gcp. Usage: ./04_run_benchmarks.sh [tag]
set -euo pipefail; cd "$(dirname "$0")"; source config.env
TAG="${1:-gcp4region}"
# retry only when ssh itself fails (exit 255 or a gcloud API error); never re-run a command that ran and failed
LG() { for a in 1 2 3 4 5; do gcloud compute ssh "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --quiet --command "$1"; rc=$?; [ $rc -eq 0 ] && return 0; [ $rc -ne 255 ] && [ $rc -ne 1 ] && return $rc; echo "  gcloud ssh failed (rc=$rc, attempt $a), retrying in 30 s..." >&2; sleep 30; done; return 1; }
LG "command -v node >/dev/null && node -v | grep -q v20 || (curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs)
  [ -d ~/repo ] || git clone --depth 1 $REPO_URL ~/repo
  cd ~/repo && git pull -q || true
  cd ~/repo/hardhat && npm install --no-audit --no-fund >/dev/null 2>&1 && USE_SOLCJS=1 npx hardhat compile 2>&1 | tail -2
  chmod +x ~/repo/besu_net/gcp/ctl.sh"
DESC="4-validator QBFT Besu $BESU_VERSION on Google Cloud (${ZONES[*]}), blockperiodseconds=2, requesttimeoutseconds=4, zeroBaseFee"
HOSTD="$MACHINE VMs (2 vCPU, 8 GB), one validator per VM; load generator in $LOADGEN_ZONE"
# Run the benchmark in the background on the load generator (survives a dropped connection), then poll its log.
LG "source ~/hosts.env; cd ~/repo/hardhat
  export BESU_RPC=\$(printf 'http://%s:8545,' \"\${NODE_IPS[@]}\"); export BESU_RPC=\${BESU_RPC%,}
  echo \"RPC URLs: \$BESU_RPC\"
  export BESU_CTL=\$HOME/repo/besu_net/gcp/ctl.sh OUT_TAG=$TAG NET_DESC='$DESC' HOST_DESC='$HOSTD'
  mkdir -p ../results; rm -f ~/bench_$TAG.log
  nohup bash -c 'node scripts/besu_benchmark.js $([ "${SKIP_FAULT:-0}" = 1 ] && echo --skip-fault); echo EXIT:\$?' > ~/bench_$TAG.log 2>&1 &
  sleep 5; cat ~/bench_$TAG.log"
echo "Benchmark started in the background. Polling every 60 s (about 20-30 minutes)..."
while true; do
  sleep 60
  OUT=$(LG "tail -n 3 ~/bench_$TAG.log; grep -c '^EXIT:' ~/bench_$TAG.log; true" 2>/dev/null || true)
  echo "--- $(date +%H:%M:%S)"; echo "$OUT" | head -n -1 | cut -c1-200
  [ "$(echo "$OUT" | tail -n 1)" = "1" ] && break
done
LG "grep '^EXIT:' ~/bench_$TAG.log; tail -n 15 ~/bench_$TAG.log | cut -c1-200"
mkdir -p results_gcp
for a in 1 2 3; do gcloud compute scp --recurse "$LOADGEN_NAME":~/repo/results/besu_*_"$TAG".json results_gcp/ --zone="$LOADGEN_ZONE" --quiet && break; sleep 20; done
echo "Results are in $(pwd)/results_gcp -- send these files back."
