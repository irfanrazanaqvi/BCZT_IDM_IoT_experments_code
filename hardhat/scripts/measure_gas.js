// Measures real EVM gas and in-process call latency for every contract operation.
// Run:  USE_SOLCJS=1 npx hardhat run scripts/measure_gas.js   (writes ../results/evm_metrics.json)
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const N = 50;
const stats = (a) => {
  const n = a.length, m = a.reduce((x, y) => x + y, 0) / n;
  const sd = n > 1 ? Math.sqrt(a.reduce((x, y) => x + (y - m) ** 2, 0) / (n - 1)) : 0;
  const s = [...a].sort((x, y) => x - y);
  return { n, mean: m, sd, min: s[0], max: s[n - 1], p50: s[Math.floor(n / 2)] };
};

async function main() {
  const [deployer, oracle, rogue] = await ethers.getSigners();
  const Reg = await ethers.getContractFactory("IdentityRegistry");
  const registry = await Reg.deploy();
  const rcpt1 = await registry.deploymentTransaction().wait();
  const ZTA = await ethers.getContractFactory("ZeroTrustAccess");
  const zta = await ZTA.deploy(await registry.getAddress(), oracle.address);
  const rcpt2 = await zta.deploymentTransaction().wait();
  const resourceId = ethers.id("telemetry.write");
  const defRc = await (await zta.definePolicy(resourceId, 5500, 1500, 300, 10000, false, ["sensor", "gateway"])).wait();

  const gas = { register: [], evalAllow: [], evalStepUp: [], denyReplay: [], denyBadOracle: [], denyRevoked: [],
                suspend: [], reinstate: [], revoke: [] };
  const lat = { register: [], evalAllow: [] };
  const abi = ethers.AbiCoder.defaultAbiCoder();
  const sign = async (signer, did, bp, nonce) => {
    const h = ethers.keccak256(abi.encode(["bytes32", "bytes32", "uint16", "uint16", "uint256"], [did, resourceId, bp, 500, nonce]));
    return signer.signMessage(ethers.getBytes(h));
  };
  const ms = () => Number(process.hrtime.bigint()) / 1e6;

  for (let i = 0; i < N; i++) {
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey);
    const ah = ethers.keccak256(ethers.toUtf8Bytes("fw:2." + i));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "sensor", deployer.address]));
    const sig = await dev.signMessage(ethers.getBytes(mh));
    let t0 = ms();
    const rc = await (await registry.registerDevice(pk, ah, "sensor", sig, dev.address)).wait();
    lat.register.push(ms() - t0); gas.register.push(Number(rc.gasUsed));
    const did = ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pk]);

    t0 = ms();
    let r = await (await zta.evaluateAccess(did, resourceId, "sensor", 9000, 500, await sign(oracle, did, 9000, 1), 1)).wait();
    lat.evalAllow.push(ms() - t0); gas.evalAllow.push(Number(r.gasUsed));
    r = await (await zta.evaluateAccess(did, resourceId, "sensor", 6500, 500, await sign(oracle, did, 6500, 2), 2)).wait();
    gas.evalStepUp.push(Number(r.gasUsed));
    r = await (await zta.evaluateAccess(did, resourceId, "sensor", 9000, 500, await sign(oracle, did, 9000, 1), 1)).wait();
    gas.denyReplay.push(Number(r.gasUsed));
    r = await (await zta.evaluateAccess(did, resourceId, "sensor", 9000, 500, await sign(rogue, did, 9000, 3), 3)).wait();
    gas.denyBadOracle.push(Number(r.gasUsed));
    r = await (await registry.suspendDevice(did)).wait(); gas.suspend.push(Number(r.gasUsed));
    r = await (await registry.reinstateDevice(did)).wait(); gas.reinstate.push(Number(r.gasUsed));
    r = await (await registry.revokeDevice(did, "key_rotation")).wait(); gas.revoke.push(Number(r.gasUsed));
    r = await (await zta.evaluateAccess(did, resourceId, "sensor", 9000, 500, await sign(oracle, did, 9000, 4), 4)).wait();
    gas.denyRevoked.push(Number(r.gasUsed));
  }

  // verify decisions on a fresh device (Effect enum: 0 DENY, 1 STEP_UP, 2 ALLOW)
  const out = {
    solc: "0.8.24 (solc-js), optimizer runs=200, evm target paris",
    network: "Hardhat in-process EVM (EDR), automine, chainId 1337",
    n_devices: N,
    deploy_gas: { IdentityRegistry: Number(rcpt1.gasUsed), ZeroTrustAccess: Number(rcpt2.gasUsed), definePolicy: Number(defRc.gasUsed) },
    gas: Object.fromEntries(Object.entries(gas).map(([k, v]) => [k, stats(v)])),
    latency_ms: Object.fromEntries(Object.entries(lat).map(([k, v]) => [k, stats(v)])),
  };
  fs.mkdirSync(path.join(__dirname, "..", "..", "results"), { recursive: true });
  fs.writeFileSync(path.join(__dirname, "..", "..", "results", "evm_metrics.json"), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
