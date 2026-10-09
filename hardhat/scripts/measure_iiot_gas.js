// Gas for the industrial extensions: batch revocation / quarantine vs. one-by-one, strict-tier and anomaly-gate decisions.
// USE_SOLCJS=1 npx hardhat run scripts/measure_iiot_gas.js  -> ../results/evm_iiot_gas.json
const { ethers } = require("hardhat");
const fs = require("fs"), path = require("path");
const abi = ethers.AbiCoder.defaultAbiCoder();
async function main() {
  const [deployer, oracle] = await ethers.getSigners();
  const registry = await (await ethers.getContractFactory("IdentityRegistry")).deploy();
  const zta = await (await ethers.getContractFactory("ZeroTrustAccess")).deploy(await registry.getAddress(), oracle.address);
  const rid = ethers.id("plc.setpoint.write");
  const dp = await (await zta.definePolicy(rid, 7500, 1000, 300, 2500, true, ["plc"])).wait();
  const reg = async (i) => {
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fw:" + i));
    const mh = ethers.keccak256(abi.encode(["bytes32","bytes32","string","address"], [pk, ah, "plc", deployer.address]));
    await (await registry.registerDevice(pk, ah, "plc", await dev.signMessage(ethers.getBytes(mh)), dev.address)).wait();
    return ethers.solidityPackedKeccak256(["string","bytes32"], ["did:iot:", pk]);
  };
  const sig = (did, T, A, n) => oracle.signMessage(ethers.getBytes(ethers.keccak256(abi.encode(["bytes32","bytes32","uint16","uint16","uint256"], [did, rid, T, A, n]))));
  const out = { definePolicy_iiot: Number(dp.gasUsed), decisions: {}, recall: [] };
  const d0 = await reg(0);
  const dec = async (name, T, A, n) => { const r = await (await zta.evaluateAccess(d0, rid, "plc", T, A, await sig(d0, T, A, n), n)).wait(); out.decisions[name] = Number(r.gasUsed); };
  await dec("allow_strict_tier", 9500, 500, 1);
  await dec("deny_anomaly_gate", 9500, 3000, 2);
  await dec("deny_strict_borderline", 8000, 500, 3);
  await dec("deny_trust_below", 5000, 500, 4);
  const pep = (await ethers.getSigners())[5];
  await (await zta.setPEP(pep.address, true)).wait();
  const ag = [];
  for (let i = 0; i < 5; i++) ag.push(Number((await (await zta.connect(pep).anchorDecisions(ethers.id("root" + i), 1000)).wait()).gasUsed));
  out.anchor_gas = { first: ag[0], steady_mean: Math.round(ag.slice(1).reduce((a, b) => a + b, 0) / 4), per_decision_at_1000: Math.round(ag[4] / 1000) };
  console.log(out.anchor_gas);
  for (const k of [1, 10, 50, 100, 200]) {
    const A = [], B = [];
    for (let i = 0; i < k; i++) A.push(await reg(1000 + i));
    for (let i = 0; i < k; i++) B.push(await reg(2000 + i));
    let single = 0;
    for (const d of A) single += Number((await (await registry.revokeDevice(d, "firmware_recall")).wait()).gasUsed);
    const batch = Number((await (await registry.revokeBatch(B, "firmware_recall")).wait()).gasUsed);
    const C = []; for (let i = 0; i < k; i++) C.push(await reg(3000 + i));
    const q = Number((await (await registry.suspendBatch(C)).wait()).gasUsed);
    out.recall.push({ devices: k, individual_total_gas: single, batch_gas: batch, saving_pct: +(100 * (1 - batch / single)).toFixed(1), per_device_batch_gas: Math.round(batch / k), suspendBatch_gas: q });
    console.log(out.recall[out.recall.length - 1]);
  }
  fs.writeFileSync(path.join(__dirname, "..", "..", "results", "evm_iiot_gas.json"), JSON.stringify(out, null, 2));
  console.log(out.decisions);
}
main().catch(e => { console.error(e); process.exit(1); });
