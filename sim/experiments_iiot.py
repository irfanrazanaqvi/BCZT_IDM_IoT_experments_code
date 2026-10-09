"""
experiments_iiot.py -- industrial-setting experiments (all synthetic, compute-bound; see paper Sec. 6).

  X1  Tiered policy on a mixed industrial fleet: legit acceptance vs. attack blocking per criticality tier,
      threshold-only versus threshold + anomaly hard gate + strict mode.
  X2  Anomaly-gate sweep: the gate level trades false denials of legitimate process upsets against mimicry blocking.
  X3  Hybrid enforcement: fast path (PEP-local, replicated state, Merkle-anchored log) vs. per-request on-chain path.
  X4  Firmware-recall capacity derived from measured gas (batch vs. single revocations) under a block gas limit.
  X5  Controller-outage degraded mode: availability vs. unsafe acceptance as the chain/replica becomes unreachable.

Run: python3 -m sim.experiments_iiot  -> results/iiot_metrics.json
"""
import json, os, random, statistics, time, hashlib
import numpy as np
from scipy import stats as sps

from .contracts import IdentityRegistryContract, ZeroTrustAccessContract, Effect
from .crypto_utils import verify, generate_keypair, merkle_root
from .iot_device import IoTDevice
from .trust_engine import TrustEngine

SEED = 20261004
OUT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results", "iiot_metrics.json")
now = time.perf_counter

# Purdue-style criticality tiers: resource -> (min_trust, margin, max_anomaly, strict, classes)
FIELD = ["sensor", "plc", "hmi", "robot", "gateway", "legacy"]
TIERS = {
    "telemetry.read":       dict(tier=0, t=0.50, m=0.10, g=1.00, strict=False, classes=FIELD),
    "historian.write":      dict(tier=1, t=0.55, m=0.10, g=0.60, strict=False, classes=["sensor", "plc", "gateway", "robot", "legacy"]),
    "plc.setpoint.write":   dict(tier=2, t=0.70, m=0.05, g=0.30, strict=True,  classes=["hmi", "plc", "robot"]),
    "plc.firmware.update":  dict(tier=3, t=0.78, m=0.04, g=0.20, strict=True,  classes=["plc", "robot"]),
}
CLASS_MIX = {"sensor": .40, "plc": .15, "hmi": .08, "robot": .07, "gateway": .15, "legacy": .15}

def draw(cls, rng, upset=0.0):
    if cls == "legacy":   # brownfield device behind a protocol-translating gateway: weak posture evidence
        p, a, n = rng.uniform(.55, .75), rng.uniform(0, .20), rng.uniform(.6, .9)
    else:
        p, a, n = rng.uniform(.75, 1), rng.uniform(0, .15), rng.uniform(.7, 1)
    if upset and rng.random() < upset:       # legitimate process upset (start-up, batch change): behaviour deviates
        a = rng.uniform(.15, .45)
    return p, a, n

ATTACK = {
    "naive compromise": lambda r: (r.uniform(.2, .5), r.uniform(.5, .9), r.uniform(.1, .4)),
    "partial mimicry":  lambda r: (r.uniform(.75, 1), r.uniform(.3, .7), r.uniform(.7, 1)),
    "stealthy mimicry": lambda r: (r.uniform(.75, 1), r.uniform(.15, .40), r.uniform(.7, 1)),
    "full spoof (P,N,R=1)": lambda r: (1.0, r.uniform(.3, .7), 1.0),
}

def score(te, did, p, a, n):
    return te.score(did, p, a, n)

def decide(res, T, A, cfg, gate=True, strict=True):
    """Policy decision on a trust score (no crypto): returns Effect."""
    g = cfg["g"] if gate else 1.0
    if A > g: return Effect.DENY
    if T < cfg["t"]: return Effect.DENY
    if T < cfg["t"] + cfg["m"]: return Effect.DENY if (cfg["strict"] and strict) else Effect.STEP_UP
    return Effect.ALLOW

def pop_scores(gen, rng, n=4000, warm=3, upset=0.0, cls_mix=None):
    te = TrustEngine(); out = []
    classes = list(CLASS_MIX); probs = list(CLASS_MIX.values())
    for i in range(n):
        did = f"d{i}"; cls = rng.choices(classes, probs)[0] if cls_mix else "plc"
        for _ in range(warm):
            te.score(did, *draw(cls, rng))
        if gen == "legit": p, a, nn = draw(cls, rng, upset)
        else: p, a, nn = ATTACK[gen](rng)
        out.append((cls, score(te, did, p, a, nn), a))
    return out

def x1_tiers():
    rng = random.Random(SEED)
    legit = pop_scores("legit", rng, upset=0.05, cls_mix=True)
    res = {}
    for rname, cfg in TIERS.items():
        elig = [x for x in legit if x[0] in cfg["classes"]]
        row = {"tier": cfg["tier"], "min_trust": cfg["t"], "margin": cfg["m"], "anomaly_gate": cfg["g"], "strict": cfg["strict"],
               "legit_eligible": len(elig)}
        for mode, kw in (("threshold_only", dict(gate=False, strict=False)), ("full_policy", dict(gate=True, strict=True))):
            eff = [decide(rname, T, A, cfg, **kw) for _, T, A in elig]
            row[mode] = {"legit_allow_pct": 100 * np.mean([e == Effect.ALLOW for e in eff]),
                         "legit_stepup_pct": 100 * np.mean([e == Effect.STEP_UP for e in eff]),
                         "legit_denied_pct": 100 * np.mean([e == Effect.DENY for e in eff])}
        # legacy devices attempting a tier they are not eligible for are denied by class check
        for aname in ATTACK:
            atk = pop_scores(aname, random.Random(SEED + 7), cls_mix=True)
            atk = [x for x in atk if x[0] in cfg["classes"]]
            for mode, kw in (("threshold_only", dict(gate=False, strict=False)), ("full_policy", dict(gate=True, strict=True))):
                acc = np.mean([decide(rname, T, A, cfg, **kw) == Effect.ALLOW for _, T, A in atk])
                row.setdefault("attack_accepted_pct", {}).setdefault(aname, {})[mode] = 100 * acc
        res[rname] = row
    return {"n_per_population": 4000, "process_upset_rate": 0.05, "class_mix": CLASS_MIX, "results": res}

def x2_gate_sweep():
    rng = random.Random(SEED + 1)
    out = {}
    for upset in (0.0, 0.05, 0.15):
        legit = pop_scores("legit", rng, upset=upset)
        stealth = pop_scores("stealthy mimicry", random.Random(SEED + 2))
        full = pop_scores("full spoof (P,N,R=1)", random.Random(SEED + 3))
        rows = []
        for g in (0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.60, 1.0):
            rows.append({"gate": g,
                         "legit_denied_pct": 100 * np.mean([a > g for _, _, a in legit]),
                         "stealthy_blocked_pct": 100 * np.mean([a > g for _, _, a in stealth]),
                         "full_spoof_blocked_pct": 100 * np.mean([a > g for _, _, a in full])})
        out[f"upset_rate_{upset}"] = rows
    return out

# ----------------------------------------------------------- X3 hybrid enforcement
class FastPathPEP:
    """Decides locally against replicated chain state: device signature + oracle attestation (two Ed25519
    verifications), monotonic per-device counter, tiered policy, Merkle-anchored decision log."""
    def __init__(self, registry, oracle_pub, batch=1000):
        self.reg = registry; self.opk = oracle_pub; self.last = {}; self.log = []; self.batch = batch; self.roots = []
        self.pol = TIERS
    def decide(self, did, res, cls, T, A, ctr, msg, sig, att):
        rec = self.reg.devices.get(did)
        if rec is None or rec.status.value != 1: return Effect.DENY, "status"
        cfg = self.pol[res]
        if cls not in cfg["classes"]: return Effect.DENY, "class"
        if ctr <= self.last.get(did, 0): return Effect.DENY, "replay"
        if not verify(rec.pub_hex, msg, sig): return Effect.DENY, "bad_sig"
        if not verify(self.opk, att[0], att[1]): return Effect.DENY, "bad_attestation"
        self.last[did] = ctr
        eff = decide(res, T, A, cfg)
        self.log.append(hashlib.sha256(f"{did}|{res}|{eff.value}|{ctr}".encode()).digest())
        if len(self.log) % self.batch == 0: self.roots.append(merkle_root([x.hex() for x in self.log[-self.batch:]]))
        return eff, "ok"

def x3_hybrid(runs=10, n_dev=300, n_req=2000):
    onchain_lat, fast_lat = [], []
    oracle = generate_keypair()
    for r in range(runs):
        rng = random.Random(SEED + 100 + r)
        reg = IdentityRegistryContract(); zt = ZeroTrustAccessContract(reg)
        for res, c in TIERS.items():
            zt.define_policy(res, c["t"], c["classes"], 300, c["g"], c["strict"], c["m"])
        devs = [IoTDevice(device_class=rng.choice(["plc", "robot"])) for _ in range(n_dev)]
        for d in devs:
            m = d.registration_message(); reg.register_device(d.pub_hex, d.owner, d.device_class, d.attributes, d.sign(m), m)
        pep = FastPathPEP(reg, oracle.pub_hex()); te = TrustEngine()
        reqs = []
        for i in range(n_req):
            d = devs[i % n_dev]; res = "plc.setpoint.write" if i % 5 == 0 else "telemetry.read"
            nonce = d.next_nonce(); msg = d.access_message(res, nonce)
            p, a, nn = d.posture_signal(), d.anomaly_signal(), d.network_signal()
            T = te.score(d.did, p, a, nn)
            att_msg = f"{d.did}|{res}|{T:.4f}|{a:.4f}|{nonce}".encode()
            reqs.append((d, res, nonce, msg, d.sign(msg), T, a, att_msg, oracle.sign(att_msg), d.nonce_counter))
        t0 = now()
        for d, res, nonce, msg, sig, T, a, am, asig, ctr in reqs:
            zt.evaluate_access(d.did, res, T, nonce, sig, msg, a)
        onchain_lat.append(1000 * (now() - t0) / n_req)
        t0 = now()
        for d, res, nonce, msg, sig, T, a, am, asig, ctr in reqs:
            pep.decide(d.did, res, d.device_class, T, a, ctr, msg, sig, (am, asig))
        fast_lat.append(1000 * (now() - t0) / n_req)
    def ci(xs):
        m = statistics.mean(xs); sd = statistics.stdev(xs); h = sps.t.ppf(.975, len(xs) - 1) * sd / len(xs) ** .5
        return {"mean": m, "sd": sd, "ci95": [m - h, m + h], "runs": len(xs)}
    gas = json.load(open(os.path.join(os.path.dirname(OUT), "evm_iiot_gas.json")))
    return {"requests_per_run": n_req, "devices": n_dev,
            "model_onchain_path_ms": ci(onchain_lat),
            "fast_path_ms": ci(fast_lat),
            "anchor_gas_first": gas["anchor_gas"]["first"], "anchor_gas_steady": gas["anchor_gas"]["steady_mean"],
            "anchor_gas_per_decision_at_1000": gas["anchor_gas"]["per_decision_at_1000"],
            "per_request_onchain_gas_allow": json.load(open(os.path.join(os.path.dirname(OUT), "evm_metrics.json")))["gas"]["evalAllow"]["mean"]}

# ----------------------------------------------------------- X4 firmware recall capacity
def x4_recall(block_gas=30_000_000, fleet=(1000, 10000, 50000)):
    g = json.load(open(os.path.join(os.path.dirname(OUT), "evm_iiot_gas.json")))["recall"]
    single = [r for r in g if r["devices"] == 1][0]["individual_total_gas"]
    batch = [r for r in g if r["devices"] == 200][0]["per_device_batch_gas"]
    rows = []
    for f in fleet:
        rows.append({"devices_recalled": f, "blocks_single": int(np.ceil(f * single / block_gas)),
                     "blocks_batch": int(np.ceil(f * batch / block_gas)),
                     "gas_single": f * single, "gas_batch": f * batch})
    return {"block_gas_limit_assumed": block_gas, "single_revoke_gas": single, "batch_per_device_gas": batch, "rows": rows,
            "note": "derived from measured gas; ignores other traffic and per-tx overhead; block interval not modelled"}

# ----------------------------------------------------------- X5 outage / degraded mode
def x5_outage(n_dev=400, horizon=600, start=200, revoke_frac=0.10, seed=SEED):
    out = []
    for dur in (10, 30, 60, 120, 300):
        rng = random.Random(seed + dur)
        t_rev = {i: (rng.uniform(start, start + dur) if rng.random() < revoke_frac else None) for i in range(n_dev)}
        tier2 = {i: rng.random() < 0.25 for i in range(n_dev)}   # 25% of requests concern a tier-2 resource
        res = {"fail_closed": dict(legit_ok=0, legit_total=0, unsafe=0), "degraded_cache": dict(legit_ok=0, legit_total=0, unsafe=0, t2_denied=0, t2_total=0)}
        for t in range(horizon):
            part = start <= t < start + dur
            for i in range(n_dev):
                revoked = t_rev[i] is not None and t >= t_rev[i]
                is_t2 = tier2[i] and (t % 4 == 0)
                if not revoked:
                    res["fail_closed"]["legit_total"] += 1
                    res["fail_closed"]["legit_ok"] += 0 if part else 1
                    res["degraded_cache"]["legit_total"] += 1
                    if part and is_t2:
                        res["degraded_cache"]["t2_total"] += 1; res["degraded_cache"]["t2_denied"] += 1
                    else:
                        res["degraded_cache"]["legit_ok"] += 1
                else:
                    # cache is stale during partition: revoked devices still look ACTIVE for tier 0/1
                    if part and not is_t2: res["degraded_cache"]["unsafe"] += 1
        # fail-closed never accepts a revoked device (no state -> deny); degraded accepts tier 0/1 from stale cache
        for k, v in res.items():
            v["availability_pct"] = 100 * v["legit_ok"] / v["legit_total"]
        res["degraded_cache"]["tier2_denied_pct"] = 100 * res["degraded_cache"]["t2_denied"] / max(1, res["degraded_cache"]["t2_total"])
        out.append({"outage_s": dur, "revoked_devices": sum(v is not None for v in t_rev.values()), **res})
    return {"devices": n_dev, "horizon_s": horizon, "outage_start_s": start, "revoke_frac": revoke_frac, "results": out}

def main():
    out = {"seed": SEED}
    for k, f in (("X1_tiers", x1_tiers), ("X2_gate_sweep", x2_gate_sweep), ("X3_hybrid", x3_hybrid), ("X4_recall", x4_recall), ("X5_outage", x5_outage)):
        print(k, "..."); out[k] = f(); print(json.dumps(out[k], indent=1)[:1800])
    json.dump(out, open(OUT, "w"), indent=2); print("saved", OUT)

if __name__ == "__main__":
    main()
