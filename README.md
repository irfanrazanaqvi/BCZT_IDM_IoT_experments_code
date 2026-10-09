# Blockchain-Enabled Zero Trust Architecture for Industrial IoT Identity Management

Code, experiment scripts and result files for the paper *A Blockchain-Enabled Zero Trust Architecture for Industrial IoT Identity Management: Tiered Continuous Authorization and Quorum-Governed Revocation*.

- `hardhat/contracts` – IdentityRegistry, ZeroTrustAccess, RevocationGovernance (Solidity 0.8.24); `hardhat/test` – 13 tests; `hardhat/scripts` – gas, Besu benchmark and fault scripts
- `sim/` – Python testbed, synthetic IIoT experiments, TON_IoT study, figure scripts
- `besu_net/` – start script and QBFT config for the 4-validator Besu network (download Besu 25.7.0 separately)
- `results/` – JSON metrics; `paper/` – LaTeX sources
- TON_IoT data is not redistributed; obtain it from the UNSW TON_IoT page and place the CSVs in `data/`.

Research code, unit-tested but not audited.
