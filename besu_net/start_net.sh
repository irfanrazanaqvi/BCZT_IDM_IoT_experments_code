#!/usr/bin/env bash
# Starts a 4-validator QBFT Besu network on localhost (RPC 8545-8548, P2P 30303-30306).
# Usage: ./start_net.sh start | stop | stopnode <i> | startnode <i>
cd "$(dirname "$0")"; BESU=./besu-25.7.0/bin/besu
KEYS=($(ls net/keys)); mkdir -p data logs pids
BOOT=$(cat net/keys/${KEYS[0]}/key.pub); BOOT=${BOOT#0x}
startnode() { i=$1
  EXTRA=""; [ $i -ne 0 ] && EXTRA="--bootnodes=enode://$BOOT@127.0.0.1:30303"
  JAVA_OPTS="-Xmx700m" nohup $BESU --data-path=data/n$i --genesis-file=net/genesis.json \
    --node-private-key-file=net/keys/${KEYS[$i]}/key --min-gas-price=0 \
    --rpc-http-enabled --rpc-http-port=$((8545+i)) --rpc-http-api=ETH,NET,QBFT,WEB3,TXPOOL --host-allowlist="*" --rpc-http-cors-origins="*" \
    --p2p-port=$((30303+i)) --p2p-host=127.0.0.1 $EXTRA >> logs/n$i.log 2>&1 &
  echo $! > pids/n$i.pid; }
case "$1" in
  start) for i in 0 1 2 3; do startnode $i; [ $i -eq 0 ] && sleep 12; done ;;
  stop) for f in pids/*.pid; do kill $(cat $f) 2>/dev/null; done ;;
  stopnode) kill $(cat pids/n$2.pid) ;;
  startnode) startnode $2 ;;
esac
