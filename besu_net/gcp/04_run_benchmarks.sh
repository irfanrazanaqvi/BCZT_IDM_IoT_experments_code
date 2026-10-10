#!/usr/bin/env bash
# Run in Cloud Shell. Installs Node + the repo on the load generator, compiles the contracts, runs the benchmark
# (with fault test) and copies the result JSON files back into ./results_gcp. Usage: ./04_run_benchmarks.sh [tag]
set -euo pipefail; cd "$(dirname "$0")"; source config.env
TAG="${1:-gcp4region}"
LG() { gcloud compute ssh "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --quiet --command "$1"; }
LG "command -v node >/dev/null && node -v | grep -q v20 || (curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs)
  [ -d ~/repo ] || git clone --depth 1 $REPO_URL ~/repo
  cd ~/repo && git pull -q || true
  cd ~/repo/hardhat && npm install --no-audit --no-fund >/dev/null 2>&1 && USE_SOLCJS=1 npx hardhat compile 2>&1 | tail -2
  chmod +x ~/repo/besu_net/gcp/ctl.sh"
DESC="4-validator QBFT Besu $BESU_VERSION on Google Cloud (${ZONES[*]}), blockperiodseconds=2, requesttimeoutseconds=4, zeroBaseFee"
HOSTD="$MACHINE VMs (2 vCPU, 8 GB), one validator per VM; load generator in $LOADGEN_ZONE"
LG "source ~/hosts.env; cd ~/repo/hardhat
  export BESU_RPC=\$(printf 'http://%s:8545,' \"\${NODE_IPS[@]}\"); export BESU_RPC=\${BESU_RPC%,}
  export BESU_CTL=\$HOME/repo/besu_net/gcp/ctl.sh OUT_TAG=$TAG NET_DESC='$DESC' HOST_DESC='$HOSTD'
  mkdir -p ../results
  node scripts/besu_benchmark.js $([ "${SKIP_FAULT:-0}" = 1 ] && echo --skip-fault)"
mkdir -p results_gcp
gcloud compute scp --recurse "$LOADGEN_NAME":~/repo/results/besu_*_"$TAG".json results_gcp/ --zone="$LOADGEN_ZONE" --quiet
echo "Results are in $(pwd)/results_gcp -- send these files back."
