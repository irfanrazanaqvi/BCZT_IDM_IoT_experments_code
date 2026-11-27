"""
experiments_prior.py -- architecture-class baselines and weight sensitivity (answers reviewer concerns).

  P1  Blockchain registry + authenticate-once session (class model of schemes that check the ledger at login and
      then issue a session), session lifetimes 60/300/900 s, same logical clock as sim.experiments_baselines2.
  P2  Smart-contract policy with ONE static trust threshold for every resource (class model of on-chain ABAC /
      threshold schemes: no criticality tiers, no anomaly gate, no strict mode), evaluated with the same signal
      generators as sim.experiments_iiot (synthetic; tier-2 and tier-3 eligible classes).
  P3  Sensitivity of the full policy to the trust-score weights: each weight moved by +/-0.10 (others rescaled to sum
      to 1) and 200 random Dirichlet perturbations around the default weights.

These are CLASS MODELS built from the published description of each family, not re-implementations of named systems.
Run: python3 -m sim.experiments_prior -> results/prior_baselines.json
"""
import json, os, random, statistics
import numpy as np
from .contracts import Effect
from .trust_engine import TrustEngine, TrustWeights
from .experiments_iiot import TIERS, ATTACK, CLASS_MIX, draw, decide

SEED = 20261004
OUT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results", "prior_baselines.json")
N, H, REPS = 60, 600, 30

# ---------------------------------------------------------------- P1
def session_run(S, rep):
    rng = random.Random(SEED + rep)
    t_rev = [rng.uniform(100, 500) for _ in range(N)]
    start = [rng.uniform(0, S) for _ in range(N)]          # session start phase (ledger checked at start)
    exp = [0] * N
    for t in range(H):
        for i in range(N):
            if t < start[i]: continue
            k = int((t - start[i]) // S); s0 = start[i] + k * S      # latest (re-)login instant
            ok = (s0 < t_rev[i]) and (t < s0 + S)                    # login succeeds only if not revoked at s0
            if t >= t_rev[i] and ok: exp[i] += 1
    return statistics.mean(exp), max(exp)

def p1():
    out = {}
    for S in (60, 300):
        rs = [session_run(S, r) for r in range(REPS)]
        out[f"session {S} s"] = {"mean_exposure": round(statistics.mean(r[0] for r in rs), 1), "max_exposure": max(r[1] for r in rs)}
    return out

# ---------------------------------------------------------------- shared population generator
def pop(gen, rng, w, n=4000, warm=3, upset=0.0):
    te = TrustEngine(w); out = []
    classes = list(CLASS_MIX); probs = list(CLASS_MIX.values())
    for i in range(n):
        did = f"d{i}"; cls = rng.choices(classes, probs)[0]
        for _ in range(warm): te.score(did, *draw(cls, rng))
        if gen == "legit": p, a, nn = draw(cls, rng, upset)
        else: p, a, nn = ATTACK[gen](rng)
        out.append((cls, te.score(did, p, a, nn), a))
    return out

STATIC = dict(t=0.55, m=0.0, g=1.0, strict=False)

def evaluate(w, rname, mode):
    cfg = TIERS[rname] if mode == "full" else STATIC
    kw = dict(gate=True, strict=True) if mode == "full" else dict(gate=False, strict=False)
    legit = [x for x in pop("legit", random.Random(SEED), w, upset=0.05) if x[0] in TIERS[rname]["classes"]]
    row = {"legit_denied_pct": 100 * np.mean([decide(rname, T, A, cfg, **kw) != Effect.ALLOW for _, T, A in legit])}
    for a in ("partial mimicry", "stealthy mimicry", "full spoof (P,N,R=1)"):
        atk = [x for x in pop(a, random.Random(SEED + 7), w) if x[0] in TIERS[rname]["classes"]]
        row[a] = 100 * np.mean([decide(rname, T, A, cfg, **kw) == Effect.ALLOW for _, T, A in atk])
    return row

def p2():
    w = TrustWeights()
    return {r: {"static_threshold_0.55": evaluate(w, r, "static"), "full_policy": evaluate(w, r, "full")}
            for r in ("plc.setpoint.write", "plc.firmware.update")}

# ---------------------------------------------------------------- P3
def p3():
    base = np.array([.30, .30, .20, .20]); names = ["posture", "behavior", "network", "reliability"]
    variants = [("default", base)]
    for i, nm in enumerate(names):
        for d in (-.10, .10):
            v = base.copy(); v[i] = max(0.02, v[i] + d)
            others = [j for j in range(4) if j != i]; v[others] *= (1 - v[i]) / v[others].sum()
            variants.append((f"{nm} {d:+.2f}", v))
    rng = np.random.default_rng(SEED)
    for k in range(200): variants.append((f"dirichlet{k}", rng.dirichlet(base * 40)))
    rows = []
    for nm, v in variants:
        w = TrustWeights(*[float(x) for x in v]); r = {"variant": nm, "weights": [round(float(x), 3) for x in v]}
        for rname in ("plc.setpoint.write", "plc.firmware.update"):
            r[rname] = evaluate(w, rname, "full")
        rows.append(r)
    summ = {}
    for rname in ("plc.setpoint.write", "plc.firmware.update"):
        s = {}
        for key in ("legit_denied_pct", "partial mimicry", "stealthy mimicry", "full spoof (P,N,R=1)"):
            vals = [r[rname][key] for r in rows[1:]]
            s[key] = {"default": rows[0][rname][key], "min": min(vals), "median": float(np.median(vals)), "max": max(vals)}
        summ[rname] = s
    return {"n_variants": len(rows) - 1, "summary": summ, "rows": rows[:9]}

if __name__ == "__main__":
    out = {"seed": SEED, "P1_session_baseline": p1(), "P2_static_threshold": p2(), "P3_weight_sensitivity": p3()}
    json.dump(out, open(OUT, "w"), indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "P3_weight_sensitivity"}, indent=1))
    print(json.dumps(out["P3_weight_sensitivity"]["summary"], indent=1))
