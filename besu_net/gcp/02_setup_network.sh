#!/usr/bin/env bash
# Run in Cloud Shell after 01. Installs Besu on all VMs, generates the QBFT genesis + 4 validator keys on the load
# generator, copies key i to node i, installs a systemd service and starts the network.
set -euo pipefail; cd "$(dirname "$0")"; source config.env
# ssh with up to 4 attempts (the first connection to a new VM sometimes fails while the key propagates)
retry() { for a in 1 2 3 4; do "$@" && return 0; echo "  ssh attempt $a failed, retrying in 15 s..." >&2; sleep 15; done; return 1; }
ssh_n() { retry gcloud compute ssh "${NODE_NAMES[$1]}" --zone="${ZONES[$1]}" --quiet --command "$2"; }
ssh_l() { retry gcloud compute ssh "$LOADGEN_NAME" --zone="$LOADGEN_ZONE" --quiet --command "$1"; }
ip_of() { gcloud compute instances describe "$1" --zone="$2" --format='get(networkInterfaces[0].networkIP)'; }
ZONE_OF_LG="$LOADGEN_ZONE"
declare -a IPS; for i in 0 1 2 3; do IPS[$i]=$(ip_of "${NODE_NAMES[$i]}" "${ZONES[$i]}"); done
LGIP=$(ip_of "$LOADGEN_NAME" "$ZONE_OF_LG"); echo "node IPs: ${IPS[*]}  loadgen: $LGIP"

# 1. wait for Java on every VM, install Besu
INSTALL="until [ -f /var/lib/startup-done ]; do sleep 5; done; java -version 2>&1 | head -1;
  [ -d ~/besu-$BESU_VERSION ] || (curl -sSL https://github.com/hyperledger/besu/releases/download/$BESU_VERSION/besu-$BESU_VERSION.tar.gz | tar xz -C ~)"
pids=(); for i in 0 1 2 3; do ssh_n $i "$INSTALL" & pids+=($!); done; ssh_l "$INSTALL" & pids+=($!)
for p in "${pids[@]}"; do wait "$p" || { echo "ERROR: Besu install failed on one VM; rerun this script." >&2; exit 1; }; done

# 2. generate genesis + keys on the load generator
gcloud compute scp ../qbftConfigFile.json "$LOADGEN_NAME":~/qbftConfigFile.json --zone="$ZONE_OF_LG" --quiet
ssh_l "rm -rf ~/net && ~/besu-$BESU_VERSION/bin/besu operator generate-blockchain-config --config-file=\$HOME/qbftConfigFile.json --to=\$HOME/net --private-key-file-name=key >/dev/null && ls ~/net/keys"
rm -rf /tmp/besunet && mkdir -p /tmp/besunet
gcloud compute scp --recurse "$LOADGEN_NAME":~/net /tmp/besunet/ --zone="$ZONE_OF_LG" --quiet
KEYS=($(ls /tmp/besunet/net/keys)); BOOTPUB=$(cat /tmp/besunet/net/keys/${KEYS[0]}/key.pub); BOOTPUB=${BOOTPUB#0x}
BOOT="enode://$BOOTPUB@${IPS[0]}:30303"; echo "bootnode: $BOOT"

# 3. push genesis + key i to node i, install service, start (node 0 first)
for i in 0 1 2 3; do
  gcloud compute ssh "${NODE_NAMES[$i]}" --zone="${ZONES[$i]}" --quiet --command "mkdir -p ~/net ~/data"
  gcloud compute scp /tmp/besunet/net/genesis.json "${NODE_NAMES[$i]}":~/net/genesis.json --zone="${ZONES[$i]}" --quiet
  gcloud compute scp /tmp/besunet/net/keys/${KEYS[$i]}/key "${NODE_NAMES[$i]}":~/net/key --zone="${ZONES[$i]}" --quiet
  EXTRA=""; [ $i -ne 0 ] && EXTRA="--bootnodes=$BOOT"
  ssh_n $i "sudo tee /etc/systemd/system/besu.service >/dev/null <<UNIT
[Unit]
Description=Besu validator $i
After=network-online.target
[Service]
User=\$USER
Environment=JAVA_OPTS=-Xmx2g
ExecStart=\$HOME/besu-$BESU_VERSION/bin/besu --data-path=\$HOME/data --genesis-file=\$HOME/net/genesis.json --node-private-key-file=\$HOME/net/key --min-gas-price=0 --rpc-http-enabled --rpc-http-host=0.0.0.0 --rpc-http-port=8545 --rpc-http-api=ETH,NET,QBFT,WEB3,TXPOOL --host-allowlist='*' --rpc-http-cors-origins='*' --p2p-host=${IPS[$i]} --p2p-port=30303 $EXTRA
Restart=no
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload && sudo systemctl stop besu 2>/dev/null; rm -rf \$HOME/data/*; sudo systemctl enable besu && sudo systemctl restart besu"
  [ $i -eq 0 ] && sleep 15
done

# 4. SSH key for the load generator so the fault test can stop/start validators
ssh_l "[ -f ~/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 -q"
PUB=$(ssh_l "cat ~/.ssh/id_ed25519.pub")
for i in 0 1 2 3; do
  gcloud compute instances add-metadata "${NODE_NAMES[$i]}" --zone="${ZONES[$i]}" --metadata "ssh-keys=benchctl:$PUB benchctl"
done
printf 'NODE_IPS=(%s)\n' "${IPS[*]}" > /tmp/hosts.env
gcloud compute scp /tmp/hosts.env "$LOADGEN_NAME":~/hosts.env --zone="$ZONE_OF_LG" --quiet
echo "Network started. Run 03_check_network.sh"
