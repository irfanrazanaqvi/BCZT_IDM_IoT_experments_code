# Multi-host Besu test on Google Cloud

Runs the same benchmarks as the single-host test (`hardhat/scripts/besu_benchmark.js`, which includes the fault test)
on four QBFT validators in four regions plus one load-generator VM. Everything is driven from **Google Cloud Shell**
(console.cloud.google.com -> the `>_` icon), which already has `gcloud`.

Cost: five `e2-standard-2` VMs, a few hours, roughly US$1-3 on a trial account. Run `99_cleanup.sh` afterwards.

1. Open Cloud Shell, then `git clone https://github.com/irfanrazanaqvi/BCZT_IDM_IoT_experments_code && cd BCZT_IDM_IoT_experments_code/besu_net/gcp`
2. Edit `config.env`: set `PROJECT` (your project id). Change zones if a region is unavailable or over quota.
3. `./01_create_infra.sh`   -- creates the 5 VMs and a firewall rule. Wait ~2 min for Java to install.
4. `./02_setup_network.sh`  -- installs Besu, generates genesis + keys, starts the 4 validators as a systemd service.
5. `./03_check_network.sh`  -- every node must show the same block number, 3 peers and 4 validators.
6. `./04_run_benchmarks.sh gcp4region` -- takes about 20-30 minutes; copies `besu_metrics_gcp4region.json` and
   `besu_fault_gcp4region.json` into `./results_gcp`. Re-run with a different tag for repeat runs.
7. Optional extra delay: `./netem.sh add 80 10` (80 ms +/- 10 ms on every validator), then `./04_run_benchmarks.sh gcp_delay80`, then `./netem.sh del`.
8. `./99_cleanup.sh` -- deletes all VMs. Do not skip this.

Send the JSON files from `results_gcp/` back to Claude to add them to the paper.

Notes: the scripts were written without access to a Google Cloud project and have been syntax-checked only, so expect to fix small
issues (quota, a region that is unavailable, package names). If a step fails, send the error text.
