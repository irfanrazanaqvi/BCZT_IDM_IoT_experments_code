"""
experiments_extra.py
--------------------
Additional experiments added for the journal version:

  E1  Repeated-run statistics: 30 independent runs at n=400 (mean, std, 95% CI)
      and per-operation latency percentiles over 20,000 sequential decisions.
  E2  Baseline comparison: (a) session-token auth, (b) centralized PKI + CRL,
      (c) identity-only blockchain registry (no continuous trust), vs. the
      proposed design -- per-request compute latency and revocation exposure
      (requests wrongly accepted after revocation) on a logical clock.
  E3  Trust-signal ablation: ROC-AUC and TPR@FPR=1% for the full score and
      for each signal removed, against three compromised-device behaviours.

Run:  python3 -m sim.experiments_extra     ->  results/extra_metrics.json
"""
import hashlib, hmac, json, os, random, statistics, time

import numpy as np
from scipy import stats as sps

from .contracts import IdentityRegistryContract, ZeroTrustAccessContract, Effect
from .crypto_utils import verify
from .iot_device import IoTDevice
from .trust_engine import TrustEngine, TrustWeights

SEED = 20261004
RESULTS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results", "extra_metrics.json")
now = time.perf_counter


def build():
    reg = IdentityRegistryContract()
    zt = ZeroTrustAccessContract(reg)
    zt.define_policy("telemetry.write", 0.55, ["sensor", "actuator", "gateway", "camera", "controller"])
    return reg, zt


def register(reg, d):
    msg = d.registration_message()
    reg.register_device(d.pub_hex, d.owner, d.device_class, d.attributes, d.sign(msg), msg)


def ci95(xs):
    n = len(xs); m = statistics.mean(xs); sd = statistics.stdev(xs)
    h = sps.t.ppf(0.975, n - 1) * sd / n ** 0.5
    return {"n": n, "mean": m, "sd": sd, "ci95_low": m - h, "ci95_high": m + h}


# ---------------------------------------------------------------- E1
def e1_repeated(runs=30, n=400):
    reg_lat, authz_lat, reg_tps, authz_tps = [], [], [], []
    for r in range(runs):
        random.seed(SEED + r)
        reg, zt = build(); te = TrustEngine()
        devs = [IoTDevice() for _ in range(n)]
        t0 = now()
        for d in devs: register(reg, d)
        reg_t = now() - t0
        reqs = []
        for d in devs:
            nonce = d.next_nonce(); msg = d.access_message("telemetry.write", nonce)
            reqs.append((d, nonce, msg, d.sign(msg), d.posture_signal(), d.anomaly_signal(), d.network_signal()))
        t0 = now()
        for d, nonce, msg, sig, p, a, nt in reqs:
            s = te.score(d.did, p, a, nt)
            zt.evaluate_access(d.did, "telemetry.write", s, nonce, sig, msg)
        az_t = now() - t0
        reg_lat.append(1000 * reg_t / n); authz_lat.append(1000 * az_t / n)
        reg_tps.append(n / reg_t); authz_tps.append(n / az_t)
    # percentile run: 20,000 sequential decisions (fresh nonce each)
    random.seed(SEED)
    reg, zt = build(); te = TrustEngine()
    devs = [IoTDevice() for _ in range(200)]
    for d in devs: register(reg, d)
    lat = []
    for i in range(20000):
        d = devs[i % len(devs)]
        nonce = d.next_nonce(); msg = d.access_message("telemetry.write", nonce); sig = d.sign(msg)
        p, a, nt = d.posture_signal(), d.anomaly_signal(), d.network_signal()
        t0 = now()
        s = te.score(d.did, p, a, nt)
        zt.evaluate_access(d.did, "telemetry.write", s, nonce, sig, msg)
        lat.append(1000 * (now() - t0))
    q = np.percentile(lat, [50, 95, 99, 99.9])
    return {"runs": runs, "fleet_size": n,
            "reg_latency_ms": ci95(reg_lat), "authz_latency_ms": ci95(authz_lat),
            "reg_tps": ci95(reg_tps), "authz_tps": ci95(authz_tps),
            "authz_latency_percentiles_ms": {"ops": len(lat), "p50": q[0], "p95": q[1], "p99": q[2], "p999": q[3],
                                              "max": max(lat)}}


# ---------------------------------------------------------------- E2
class SessionTokenAuth:
    """Authenticate once with a signature, then accept an HMAC bearer token until TTL expiry."""
    def __init__(self, ttl): self.ttl = ttl; self.key = os.urandom(32); self.reg = {}; self.tok = {}; self.revoked = set()
    def enroll(self, d): self.reg[d.did] = d.pub_hex
    def login(self, d, msg, sig, t):
        if d.did in self.revoked or not verify(self.reg[d.did], msg, sig): return None
        exp = t + self.ttl
        tag = hmac.new(self.key, f"{d.did}|{exp}".encode(), hashlib.sha256).digest()
        self.tok[d.did] = (exp, tag); return True
    def request(self, did, t):
        tk = self.tok.get(did)
        if tk is None or t >= tk[0]: return False
        return hmac.compare_digest(tk[1], hmac.new(self.key, f"{did}|{tk[0]}".encode(), hashlib.sha256).digest())


class PKICRL:
    """Per-request signature check + CRL snapshot refreshed every `refresh` seconds."""
    def __init__(self, refresh): self.refresh = refresh; self.reg = {}; self.crl = set(); self.master = set(); self.last = 0.0
    def enroll(self, d): self.reg[d.did] = d.pub_hex
    def revoke(self, did): self.master.add(did)
    def request(self, did, msg, sig, t):
        if t - self.last >= self.refresh: self.crl = set(self.master); self.last = t
        return did not in self.crl and verify(self.reg[did], msg, sig)


def e2_baselines(n_dev=60, horizon=600):
    random.seed(SEED)
    devs = [IoTDevice() for _ in range(n_dev)]
    rng = random.Random(SEED)
    t_rev = {d.did: rng.uniform(100, 500) for d in devs}
    out = {}

    def run(name, mk, step):
        # time-major loop: one shared logical clock, every device issues 1 request/s
        sys_ = mk()
        for d in devs: sys_["enroll"](d)
        acc = {d.did: 0 for d in devs}; revoked = set(); lat = []
        for t in range(horizon):
            for d in devs:
                if d.did not in revoked and t >= t_rev[d.did]:
                    sys_["revoke"](d); revoked.add(d.did)
                nonce = d.next_nonce(); msg = d.access_message("telemetry.write", nonce); sig = d.sign(msg)
                t0 = now(); ok = step(sys_, d, t, msg, sig, nonce); lat.append(1000 * (now() - t0))
                if d.did in revoked and ok: acc[d.did] += 1
        exposure = list(acc.values())
        out[name] = {"mean_requests_accepted_after_revocation": statistics.mean(exposure),
                     "max_requests_accepted_after_revocation": max(exposure),
                     "mean_decision_latency_ms": statistics.mean(lat),
                     "p95_decision_latency_ms": float(np.percentile(lat, 95))}

    for ttl in (60, 300):
        def mk(ttl=ttl):
            s = SessionTokenAuth(ttl)
            return {"obj": s, "enroll": s.enroll, "revoke": lambda d, s=s: s.revoked.add(d.did)}
        def step(s, d, t, msg, sig, nonce):
            o = s["obj"]
            if not o.request(d.did, t): o.login(d, msg, sig, t)       # re-login on expiry/absence
            return o.request(d.did, t)
        run(f"Session token (TTL {ttl} s)", mk, step)
    for rf in (60, 300):
        def mk(rf=rf):
            s = PKICRL(rf)
            return {"obj": s, "enroll": s.enroll, "revoke": lambda d, s=s: s.revoke(d.did)}
        run(f"PKI + CRL (refresh {rf} s)", mk, lambda s, d, t, msg, sig, nonce: s["obj"].request(d.did, msg, sig, t))

    def mk_chain(trust):
        reg, zt = build(); te = TrustEngine()
        return {"reg": reg, "zt": zt, "te": te, "enroll": lambda d: register(reg, d),
                "revoke": lambda d: reg.revoke_device(d.did, "test"), "trust": trust}
    def step_chain(s, d, t, msg, sig, nonce):
        sc = s["te"].score(d.did, d.posture_signal(), d.anomaly_signal(), d.network_signal()) if s["trust"] else 1.0
        return s["zt"].evaluate_access(d.did, "telemetry.write", sc, nonce, sig, msg) != Effect.DENY
    run("Proposed (continuous, per-request)", lambda: mk_chain(True), step_chain)
    return {"devices": n_dev, "horizon_s": horizon, "request_rate_hz": 1, "revocation_time_s": "U(100,500)", "results": out}


# ---------------------------------------------------------------- E3
POPS = {
    "naive compromise":   dict(p=(0.2, 0.5),  a=(0.5, 0.9),  n=(0.1, 0.4)),
    "partial mimicry":    dict(p=(0.75, 1.0), a=(0.3, 0.7),  n=(0.7, 1.0)),
    "stealthy mimicry":   dict(p=(0.75, 1.0), a=(0.15, 0.40), n=(0.7, 1.0)),
}
LEGIT = dict(p=(0.75, 1.0), a=(0.0, 0.15), n=(0.7, 1.0))
CONFIGS = {
    "Full (P,B,N,R)":     TrustWeights(0.30, 0.30, 0.20, 0.20),
    "w/o posture":        TrustWeights(0.0, 0.375, 0.25, 0.25),
    "w/o behaviour":      TrustWeights(0.375, 0.0, 0.25, 0.25),
    "w/o network":        TrustWeights(0.375, 0.375, 0.0, 0.25),
    "w/o reliability":    TrustWeights(0.375, 0.375, 0.25, 0.0),
}


def scores(pop, w, rng, n=4000, warm=3):
    te = TrustEngine(w); out = []
    for i in range(n):
        did = f"d{i}"
        for _ in range(warm):  # clean history for every device (compromise starts at the evaluated request)
            te.score(did, rng.uniform(*LEGIT["p"]), rng.uniform(*LEGIT["a"]), rng.uniform(*LEGIT["n"]))
        out.append(te.score(did, rng.uniform(*pop["p"]), rng.uniform(*pop["a"]), rng.uniform(*pop["n"])))
    return np.array(out)


def auc(pos_scores_attack, legit_scores):
    # AUC = P(legit score > attack score)  (+0.5 ties) via Mann-Whitney U
    u = sps.mannwhitneyu(legit_scores, pos_scores_attack, alternative="greater").statistic
    return u / (len(legit_scores) * len(pos_scores_attack))


def e3_ablation():
    res = {}
    for cname, w in CONFIGS.items():
        rng = random.Random(SEED)
        legit = scores(LEGIT, w, rng)
        thr1 = np.percentile(legit, 1)               # threshold giving 1% FPR on legit devices
        row = {}
        for pname, pop in POPS.items():
            atk = scores(pop, w, rng)
            row[pname] = {"auc": float(auc(atk, legit)), "tpr_at_fpr1": float(np.mean(atk < thr1))}
        # operating point of the deployed policy: DENY if <0.55 ; STEP_UP if <0.70
        row["policy_operating_point"] = {
            "legit_denied_pct": float(100 * np.mean(legit < 0.55)),
            "legit_stepup_pct": float(100 * np.mean((legit >= 0.55) & (legit < 0.70))),
            **{f"{p}_blocked_pct": float(100 * np.mean(scores(pop, w, random.Random(SEED + 1)) < 0.55)) for p, pop in POPS.items()},
        }
        res[cname] = row
    res["Identity-only (no trust score)"] = {p: {"auc": 0.5, "tpr_at_fpr1": 0.0} for p in POPS}
    res["Identity-only (no trust score)"]["policy_operating_point"] = {
        "legit_denied_pct": 0.0, "legit_stepup_pct": 0.0, **{f"{p}_blocked_pct": 0.0 for p in POPS}}
    return {"n_per_population": 4000, "history_warmup_requests": 3, "results": res}


def main():
    out = {"seed": SEED}
    print("E1 ..."); out["E1_repeated"] = e1_repeated(); print(json.dumps(out["E1_repeated"], indent=1)[:800])
    print("E2 ..."); out["E2_baselines"] = e2_baselines(); print(json.dumps(out["E2_baselines"], indent=1))
    print("E3 ..."); out["E3_ablation"] = e3_ablation(); print(json.dumps(out["E3_ablation"], indent=1)[:2500])
    with open(RESULTS, "w") as f: json.dump(out, f, indent=2)
    print("saved", RESULTS)


if __name__ == "__main__":
    main()
