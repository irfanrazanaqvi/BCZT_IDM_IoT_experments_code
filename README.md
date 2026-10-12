# Blockchain-Enabled Zero Trust Architecture for IoT Identity Management
### Experimental environment & reference implementation (original 8-page / 19-reference version)

This package accompanies the original 8-page version of the paper
*"A Blockchain-Enabled Zero Trust Architecture for IoT Identity
Management."* It contains two complementary parts:

1. **`/contracts` and `/hardhat`** — the real, deployable Solidity smart
   contracts (`IdentityRegistry.sol`, `ZeroTrustAccess.sol`) plus a complete
   Hardhat project (config, deploy script, device-simulation script, and a
   Mocha/Chai test suite) that you can run against a local Hardhat network
   or any EVM-compatible PoA chain (e.g., Hyperledger Besu, Polygon Edge,
   Quorum).
2. **`/sim`** — a self-contained Python research prototype that reimplements
   the same registry/access-control state machine and continuous
   zero-trust trust-scoring logic as pure Python, backed by **real Ed25519
   cryptographic signing/verification** (`cryptography` library) and a
   minimal Proof-of-Authority block-sealing structure. It requires no
   network access or Node toolchain, so it is what produced the latency,
   throughput, and security-detection numbers reported in Section 5 and
   Figure 4 of the paper. Table 2 documents this dual-track setup.

## Part 1 — Solidity / Hardhat (production-representative track)

```bash
cd hardhat
npm install                      # requires network access to npm registry
npx hardhat compile
npx hardhat test                 # runs test/identity_and_access.test.js
npx hardhat node                 # in a separate terminal
npm run deploy:local             # deploy IdentityRegistry + ZeroTrustAccess
N_DEVICES=50 npm run simulate    # register devices & print gas/latency
```

`hardhat.config.js` includes a commented-out `poaTestnet` network entry;
point it at any Besu/Polygon-Edge/Quorum RPC endpoint plus a funded private
key to deploy on a real permissioned PoA network.

## Part 2 — Python prototype (used for the paper's measured results)

```bash
pip install -r requirements.txt --break-system-packages   # or use a venv
python3 -m sim.benchmark            # writes results/metrics.json
python3 -m sim.generate_figures     # writes figures/fig1..fig4 .png
```

### Directory layout

```
contracts/                  Solidity source (copied into hardhat/contracts)
hardhat/                    Complete Hardhat project
  hardhat.config.js
  package.json
  contracts/                (mirrors /contracts)
  scripts/deploy.js
  scripts/simulate_devices.js
  test/identity_and_access.test.js
sim/                        Python prototype used for paper results
  crypto_utils.py           Ed25519 keygen/sign/verify, SHA-256, Merkle root
  blockchain.py             Minimal PoA block/chain structures
  contracts.py              Python mirror of the Solidity state machines
  trust_engine.py           Continuous composite trust scoring
  iot_device.py             Legitimate + adversarial device simulators
  benchmark.py              Experiment runner (Sections 5.2-5.5)
  generate_figures.py       Produces figures/fig1..fig4 .png
results/metrics.json        Raw output of the last benchmark run
figures/                    Generated PNG figures (300 dpi)
paper/                      LaTeX source and compiled PDF of the article
```

## Notes on methodology

The Python prototype in `/sim` is a discrete-event re-implementation of the
Solidity contracts' state-transition logic (registration, revocation,
policy definition, continuous access evaluation), not an EVM interpreter.
It is used because the sandbox that produced this deliverable had no
outbound network access to fetch `npm`/Hardhat/Solidity toolchains, so it
was not possible to execute the Solidity contracts on a live node inside
that environment. All reported latency/throughput/security figures in the
paper are measured on this Python prototype and are explicitly reported as
prototype/testbed results (Section 4.1), not as a specific commercial
chain's performance. The Solidity/Hardhat track is provided so the same
experiments can be reproduced end-to-end on a real EVM PoA network by
readers with network access.

## Note on this version

This package reflects the original architecture (two smart contracts,
`IdentityRegistry` and `ZeroTrustAccess`; no decentralized
revocation-governance layer; no hyperlinks in the bibliography), now at
**9 pages with 21 references**. It was extended once from the initial
8-page/19-reference version to add three papers: Dubey et al. 2025
(cross-border DID identity management), Wang et al. 2026 (blockchain
zero-trust continuous authentication for Medical IoT), and a corrected
citation for the ZT-BlocIoT paper, which is authored by Salim, Kim, Singh,
and Park in *Future Generation Computer Systems* (an initial search-derived
citation had misattributed it to different authors/venue; this was fixed
once the actual paper was verified against the primary source). A
separately maintained, more expanded revision (10 pages, 26 references
including seven additional 2025-2026 papers, a third
`RevocationGovernance.sol` contract with a quorum-voting experiment, and
hyperlinked references throughout) also exists; this package intentionally
tracks the shorter, two-contract lineage.

## Journal-version additions (v3)
- `sim/experiments_extra.py` -> `results/extra_metrics.json`: 30-run statistics, baseline comparison (session token, PKI+CRL), trust-signal ablation.
- `hardhat/scripts/measure_gas.js` -> `results/evm_metrics.json`: real EVM gas per operation. Compile offline with
  `cd hardhat && npm install --legacy-peer-deps && USE_SOLCJS=1 npx hardhat test && USE_SOLCJS=1 npx hardhat run scripts/measure_gas.js`
  (`USE_SOLCJS=1` makes Hardhat use the npm `solc` package instead of downloading a native compiler).
- `paper/gen_tables.py` builds the LaTeX tables from the JSON results; `paper/reorder_bib.py` orders references by first citation;
  `paper/build_docx.py` produces the 2-column DOCX (run `pdflatex main.tex` twice first so `main.aux` exists).
- Requirements: see `requirements.txt` (numpy and scipy added).

## Journal version v4 (title: ...Continuous Authorization and Decentralized Revocation Governance)
- Contracts: `IdentityRegistry`, `ZeroTrustAccess`, `RevocationGovernance` (hardhat/contracts, mirrored in contracts/).
- Python: `python -m sim.benchmark` (scaling + attacks), `python -m sim.experiments_extra` (30-run CIs, baselines, ablation),
  `python -m sim.experiments_governance` (quorum latency, dissent, forced-revocation tests), then `python -m sim.generate_figures`.
- EVM: `cd hardhat && npm install --legacy-peer-deps && USE_SOLCJS=1 npx hardhat test` (8 tests) and
  `USE_SOLCJS=1 npx hardhat run scripts/measure_gas.js` / `scripts/measure_governance_gas.js`.
  `USE_SOLCJS=1` compiles with the npm `solc` package (no native compiler download needed).
- Paper: `cd paper && python gen_tables.py && python reorder_bib.py && pdflatex main.tex` (twice), then `python build_docx.py out.docx` for the 2-column DOCX.
- All numbers in the paper come from results/*.json. Latencies are compute-bound (no network or multi-node consensus).

## v5 (Industrial IoT edition)
Adds: per-resource criticality tiers, anomaly hard gate, strict mode (`ZeroTrustAccess.sol`), `revokeBatch`/`suspendBatch` and PEP root anchoring, `sim/experiments_iiot.py`, `sim/generate_iiot_figures.py`, hardhat/scripts/measure_iiot_gas.js, test/iiot_extensions.test.js (13 tests total).
```
cd hardhat && npm install --legacy-peer-deps && USE_SOLCJS=1 npx hardhat test
USE_SOLCJS=1 npx hardhat run scripts/measure_gas.js ; ...measure_governance_gas.js ; ...measure_iiot_gas.js
cd .. && pip install -r requirements.txt && python3 -m sim.experiments_iiot && python3 -m sim.generate_iiot_figures
cd paper && python3 gen_tables.py && pdflatex main.tex   # tables are generated from results/*.json
```
All timings are compute-bound and use synthetic signals (see paper Sec. 7).

## v6: real-data study (TON_IoT)
`python3 -m sim.experiments_realdata` expects the TON_IoT CSVs in `data/` (Train_Test_IoT_{Fridge,Modbus,Thermostat,Weather}.csv and Train_Test_Network.csv). The data are NOT redistributed: obtain them from the TON_IoT page (free for academic research; cite the dataset papers).


## Multi-region result
`results/besu_metrics_gcp4region.json` holds the four-region Google Cloud Besu run (europe-west3, us-east4, asia-southeast1, southamerica-east1); scripts in `besu_net/gcp/`. See Section 7.15 of the paper.
