// End-to-end benchmark on a real 4-validator QBFT Besu network (see ../besu_net). Plain node + ethers v6; no hardhat network.
// node scripts/besu_benchmark.js  [--skip-fault]   -> ../results/besu_metrics.json
const { ethers } = require("ethers");
const fs = require("fs"), path = require("path");
const abi = ethers.AbiCoder.defaultAbiCoder();
// BESU_RPC = comma-separated RPC URLs of the 4 validators (default: local network). OUT_TAG renames the result file; BESU_CTL = control script (default: ../../../besu_net/start_net.sh).
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
  const skipFault = process.argv.includes("--skip-fault");
  const deployer = W(0), oracle = W(1), pep = W(2), voters = [3, 4, 5, 6, 7].map(W);
  const out = { network: process.env.NET_DESC || "4-validator QBFT Besu 25.7.0, localhost, blockperiodseconds=2, requesttimeoutseconds=4, zeroBaseFee", host: process.env.HOST_DESC || "2 vCPU / 7 GB container; all 4 nodes + load generator on one host", rpc: URLS, date: new Date().toISOString() };
  const F = {}; for (const n of ["IdentityRegistry", "ZeroTrustAccess", "RevocationGovernance"]) F[n] = art(n);
  const dep = async (n, args) => { const f = new ethers.ContractFactory(F[n].abi, F[n].bytecode, deployer); const c = await f.deploy(...args, OV); const r = await waitReceipt(c.deploymentTransaction().hash); return new ethers.Contract(r.contractAddress, F[n].abi, deployer); };
  const registry = await dep("IdentityRegistry", []);
  const zta = await dep("ZeroTrustAccess", [await registry.getAddress(), oracle.address]);
  const gov = await dep("RevocationGovernance", [await registry.getAddress(), voters.map(v => v.address), 3]);
  await waitReceipt((await registry.setRegistrar(await gov.getAddress(), true, OV)).hash);
  await waitReceipt((await zta.setPEP(pep.address, true, OV)).hash);
  const rid = ethers.id("plc.setpoint.write");
  await waitReceipt((await zta.definePolicy(rid, 5500, 1500, 300, 10000, false, ["plc"], OV)).hash);
  // read-only views on replica nodes
  const regR = P.map(p => new ethers.Contract(registry.target, F.IdentityRegistry.abi, p));
  const ztaR = P.map(p => new ethers.Contract(zta.target, F.ZeroTrustAccess.abi, p));

  let ctr = 1000;
  const regDev = async (i) => {
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fw:" + i));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "plc", deployer.address]));
    const sig = await dev.signMessage(ethers.getBytes(mh));
    const t = await sendWait(() => registry.registerDevice(pk, ah, "plc", sig, dev.address, OV));
    return { did: ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pk]), ms: t.ms, gas: Number(t.r.gasUsed) };
  };
  const oracleSig = (did, T, A, n) => oracle.signMessage(ethers.getBytes(ethers.keccak256(abi.encode(["bytes32", "bytes32", "uint16", "uint16", "uint256"], [did, rid, T, A, n]))));

  console.log('deployed', registry.target, zta.target, gov.target);
  // ---- block interval
  const h = await P[0].getBlockNumber(); const ts = [];
  for (let b = h - 40; b <= h; b++) ts.push((await P[0].getBlock(b)).timestamp);
  out.block_interval_s = st(ts.slice(1).map((t, i) => t - ts[i]));

  // ---- E1 sequential latency (submit -> receipt on the submitting node)
  const N = 40, devs = [];
  const lat = { register: [], evaluateAccess: [], revoke: [], anchor: [] };
  for (let i = 0; i < N; i++) { const d = await regDev(i); devs.push(d.did); lat.register.push(d.ms); }
  for (let i = 0; i < N; i++) { const n = ++ctr; const sig = await oracleSig(devs[i], 9000, 500, n);
    lat.evaluateAccess.push((await sendWait(() => zta.evaluateAccess(devs[i], rid, "plc", 9000, 500, sig, n, OV))).ms); }
  const ztaPep = zta.connect(pep);
  for (let i = 0; i < 20; i++) lat.anchor.push((await sendWait(() => ztaPep.anchorDecisions(ethers.id("r" + i), 1000, OV))).ms);
  out.sequential_latency_ms = Object.fromEntries(Object.entries(lat).filter(([k]) => k !== "revoke").map(([k, v]) => [k, st(v)]));

  console.log('E1 done', JSON.stringify(out.sequential_latency_ms.evaluateAccess));
  // ---- E2 revocation: receipt latency, replica visibility, decision after revocation
  const rev = { submit_to_receipt: [], receipt_to_replica: [], submit_to_replica: [], denied_after: 0, trials: 0 };
  for (let i = 0; i < 30; i++) {
    const did = devs[i]; const t0 = now(); const tx = await registry.revokeDevice(did, "bench", OV);
    let tr = null, tv = null;
    const poll = (async () => { while (tv === null) { try { if ((await regR[2].getStatus(did)) === 3n) tv = now(); else await sleep(5); } catch (e) { await sleep(10); } } })();
    const r = await waitReceipt(tx.hash); tr = now(); await poll;
    rev.submit_to_receipt.push(tr - t0); rev.submit_to_replica.push(tv - t0); rev.receipt_to_replica.push(tv - tr);
    const n = ++ctr; const sig = await oracleSig(did, 9000, 500, n);
    let eff = null; for (let a = 0; a < 5 && eff === null; a++) { try { eff = await ztaR[3].evaluateAccess.staticCall(did, rid, "plc", 9000, 500, sig, n); } catch (e) { await sleep(50); } } rev.trials++; if (eff !== null && Number(eff) === 0) rev.denied_after++;
  }
  out.revocation = { submit_to_receipt_ms: st(rev.submit_to_receipt), submit_to_replica_ms: st(rev.submit_to_replica), receipt_to_replica_ms: st(rev.receipt_to_replica),
                     decisions_after_revocation: rev.trials, denied: rev.denied_after, note: "replica = a different validator's RPC (node 3 view for status, node 4 for decision); polled every ~5 ms" };

  console.log('E2 done', JSON.stringify(out.revocation.submit_to_replica_ms));
  // ---- E3 throughput of audited decisions (pre-signed, 10 senders)
  const senders = Array.from({ length: 10 }, (_, i) => W(100 + i));
  const live = []; for (let i = 0; i < 40; i++) live.push((await regDev(500 + i)).did);   // fresh ACTIVE devices
  const iface = zta.interface; const thr = [];
  const nonces = await Promise.all(senders.map(s => P[0].getTransactionCount(s.address)));
  for (const load of [100, 300, 600]) {
    const raws = [];
    for (let k = 0; k < load; k++) {
      const s = senders[k % 10]; const did = live[k % live.length]; const n = ++ctr; const sig = await oracleSig(did, 9000, 500, n);
      const data = iface.encodeFunctionData("evaluateAccess", [did, rid, "plc", 9000, 500, sig, n]);
      raws.push({ raw: await s.signTransaction({ to: zta.target, data, nonce: nonces[k % 10]++, gasLimit: 200000, gasPrice: 0, chainId: CHAIN, type: 0 }), });
    }
    const t0 = now(); const subs = [];
    for (let i = 0; i < raws.length; i += 100) await Promise.all(raws.slice(i, i + 100).map(async x => { x.t = now(); x.hash = await P[0].send("eth_sendRawTransaction", [x.raw]); }));
    const tSub = now() - t0; let done = 0, lastT = 0; const lats = [];
    const pend = new Set(raws.map((x, i) => i));
    while (pend.size && now() - t0 < 120000) {
      await Promise.all([...pend].slice(0, 200).map(async i => { const r = await P[0].getTransactionReceipt(raws[i].hash); if (r) { pend.delete(i); lats.push(now() - raws[i].t); lastT = now() - t0; } }));
      await sleep(20);
    }
    thr.push({ offered_txs: load, mined: raws.length - pend.size, submit_window_ms: tSub, total_ms: lastT, tps: (raws.length - pend.size) / (lastT / 1000), latency_ms: st(lats) });
    console.log("load", thr[thr.length - 1].offered_txs, "tps", thr[thr.length - 1].tps.toFixed(1));
  }
  out.audited_decision_throughput = thr;

  // ---- E4 governance end-to-end (N=5, q=3)
  const gv = voters.map(v => gov.connect(v)); const gseq = [], gpar = [];
  for (let trial = 0; trial < 10; trial++) {
    for (const mode of ["seq", "par"]) {
      const did = (await regDev(900 + trial * 2 + (mode === "seq" ? 0 : 1))).did; const t0 = now();
      const ptx = await gv[0].propose(did, "bench", OV); const pr = await waitReceipt(ptx.hash);
      const pid = pr.logs.map(l => { try { return gov.interface.parseLog(l); } catch { return null; } }).find(x => x && x.name === "ProposalCreated").args[0];
      if (mode === "seq") { for (let i = 0; i < 3; i++) await waitReceipt((await gv[i].castVote(pid, true, OV)).hash); }
      else { const txs = await Promise.all([0, 1, 2].map(i => gv[i].castVote(pid, true, OV))); await Promise.all(txs.map(t => waitReceipt(t.hash))); }
      const ok = (await regR[1].getStatus(did)) === 3n; (mode === "seq" ? gseq : gpar).push({ ms: now() - t0, ok });
    }
  }
  out.governance_N5_q3 = { sequential_votes_ms: st(gseq.map(x => x.ms)), parallel_votes_ms: st(gpar.map(x => x.ms)), all_revoked: gseq.every(x => x.ok) && gpar.every(x => x.ok), trials_each: 10 };

  console.log('E4 done');
  // ---- E5 batch recall
  const recall = [];
  for (const k of [50, 200]) {
    const ds = []; const t0 = now(); for (let i = 0; i < k; i++) ds.push((await regDev(2000 + i)).did); const regMs = now() - t0;
    const t1 = now(); const t = await sendWait(() => registry.revokeBatch(ds, "firmware_recall", { gasPrice: 0, gasLimit: 30_000_000 }));
    let allRev = true; for (const d of ds.slice(0, 10)) if ((await regR[3].getStatus(d)) !== 3n) allRev = false;
    recall.push({ devices: k, register_all_ms: regMs, revokeBatch_receipt_ms: t.ms, gas: Number(t.r.gasUsed), sampled_revoked_on_other_node: allRev });
  }
  out.batch_recall = recall;

  // ---- E6 fault tolerance
  if (!skipFault) {
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
  fs.writeFileSync(path.join(__dirname, "..", "..", "results", `besu_metrics${TAG}.json`), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 1));
}
main().catch(e => { console.error(e); process.exit(1); });
