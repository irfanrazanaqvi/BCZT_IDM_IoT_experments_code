// End-to-end benchmark on a real 4-validator QBFT Besu network (see ../besu_net). Plain node + ethers v6; no hardhat network.
// node scripts/besu_benchmark.js  [--skip-fault]   -> ../results/besu_metrics.json
const { ethers } = require("ethers");
const fs = require("fs"), path = require("path");
const abi = ethers.AbiCoder.defaultAbiCoder();
// BESU_RPC = comma-separated RPC URLs of the 4 validators (default: local network). OUT_TAG renames the result file; BESU_CTL = control script (default: ../../besu_net/start_net.sh).
const URLS = process.env.BESU_RPC ? process.env.BESU_RPC.split(",").map(x => x.trim()) : [8545, 8546, 8547, 8548].map(p => `http://127.0.0.1:${p}`);
const TAG = process.env.OUT_TAG ? "_" + process.env.OUT_TAG : "";
const CTL = process.env.BESU_CTL || path.join(__dirname, "..", "..", "besu_net", "start_net.sh");
const CHAIN = 2026;
class RP extends ethers.JsonRpcProvider {
  async send(m, p) {
    for (let a = 0; ; a++) {
      try { return await super.send(m, p); }
      catch (e) {
        const msg = String(e && (e.message || e.shortMessage) || e) + String(e && e.code);
        if (m === "eth_sendRawTransaction" && /known|already/i.test(msg)) return ethers.keccak256(p[0]);
        if (a < 6 && /ECONNRESET|socket hang up|ECONNREFUSED|fetch failed|EPIPE|TIMEOUT/i.test(msg)) { await new Promise(r => setTimeout(r, 100 * (a + 1))); continue; }
        throw e;
      }
    }
  }
}
const P = URLS.map(u => new RP(u, CHAIN, { staticNetwork: true, batchMaxCount: 1 }));
const now = () => performance.now();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const st = a => { const s = [...a].sort((x, y) => x - y), n = a.length, m = a.reduce((x, y) => x + y, 0) / n;
  const sd = n > 1 ? Math.sqrt(a.reduce((x, y) => x + (y - m) ** 2, 0) / (n - 1)) : 0; const q = p => s[Math.min(n - 1, Math.floor(p * n))];
  return { n, mean: m, sd, p50: q(.5), p95: q(.95), min: s[0], max: s[n - 1] }; };
const W = i => new ethers.Wallet(ethers.keccak256(ethers.toUtf8Bytes("zt-iiot-bench-" + i)), P[0]);
const OV = { gasPrice: 0, gasLimit: 2_500_000 };

async function waitReceipt(hash, prov = P[0], timeoutMs = 60000) {
  const t0 = now();
  while (now() - t0 < timeoutMs) { const r = await prov.getTransactionReceipt(hash); if (r) return r; await sleep(20); }
  return null;
}
async function sendWait(fn) { const t0 = now(); const tx = await fn(); const r = await waitReceipt(tx.hash); return { ms: now() - t0, r }; }
const art = n => JSON.parse(fs.readFileSync(path.join(__dirname, "..", "artifacts", "contracts", n + ".sol", n + ".json")));

async function main() {
  const deployer = W(0);
  const F = { IdentityRegistry: art("IdentityRegistry") };
  const f0 = new ethers.ContractFactory(F.IdentityRegistry.abi, F.IdentityRegistry.bytecode, deployer);
  const c0 = await f0.deploy(OV); const rr = await waitReceipt(c0.deploymentTransaction().hash);
  const registry = new ethers.Contract(rr.contractAddress, F.IdentityRegistry.abi, deployer);
  const out = {};
  const regDev = async (i) => {
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fw:" + i));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "plc", deployer.address]));
    const sig = await dev.signMessage(ethers.getBytes(mh));
    return await sendWait(() => registry.registerDevice(pk, ah, "plc", sig, dev.address, OV));
  };
  const base = await Promise.all([0,1,2,3,4,5].map(async () => 0)); void base;
  const bl = []; for (let i = 0; i < 8; i++) bl.push((await regDev(i)).ms); out.baseline_register_ms = st(bl);
  // ---- E6 fault tolerance
  {
    const { execSync } = require("child_process"); const ctl = (a) => execSync(`${CTL} ${a}`, { stdio: "ignore" });
    const f = {};
    ctl("stopnode 3"); await sleep(3000);
    const l1 = []; for (let i = 0; i < 8; i++) l1.push((await regDev(3000 + i)).ms);
    f.one_validator_down_register_ms = st(l1);
    ctl("stopnode 2"); await sleep(3000);
    const dev = ethers.Wallet.createRandom(); const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fwX"));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "plc", deployer.address]));
    const hb = await P[0].getBlockNumber(); const tx = await registry.registerDevice(pk, ah, "plc", await dev.signMessage(ethers.getBytes(mh)), dev.address, OV);
    const r2 = await waitReceipt(tx.hash, P[0], 20000); f.two_validators_down_mined_within_20s = !!r2; f.two_validators_down_blocks_produced = (await P[0].getBlockNumber()) - hb;
    const t0 = now(); ctl("startnode 2"); ctl("startnode 3");
    const r3 = await waitReceipt(tx.hash, P[0], 120000); f.recovery_ms_until_pending_tx_mined = r3 ? now() - t0 : null;
    out.fault_tolerance = f;
  }

  const p = path.join(__dirname, "..", "..", "results", `besu_fault${TAG}.json`); fs.writeFileSync(p, JSON.stringify(out, null, 2)); console.log(JSON.stringify(out, null, 1));
}
main().catch(e => { console.error(e); process.exit(1); });
