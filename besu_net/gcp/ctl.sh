#!/usr/bin/env bash
# Control script used by besu_benchmark.js / besu_fault.js on the load generator: ctl.sh stopnode i | startnode i
source "$HOME/hosts.env"
ip="${NODE_IPS[$2]}"
case "$1" in
  stopnode)  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 benchctl@"$ip" "sudo systemctl stop besu" ;;
  startnode) ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 benchctl@"$ip" "sudo systemctl start besu" ;;
  *) echo "usage: $0 stopnode|startnode <i>"; exit 1 ;;
esac
