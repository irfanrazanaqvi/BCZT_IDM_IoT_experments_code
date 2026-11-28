"""
experiments_review.py -- experiments added in response to referee comments.

  R1  Component ablation on the synthetic fleet: threshold only, gate only, strict only, gate + strict, a
      "just raise the threshold" baseline, and a non-linear (min-of-signals) score. Reports attacker acceptance
      both as ALLOW and as ALLOW-or-STEP-UP (the latter is what strict mode removes).
  R2  Revocation exposure counted from the moment the revocation is DECIDED (submission), using the measured
      Besu submission-to-finality and submission-to-replica times, for the audited and the fast path.
  R3  Real traffic with (a) a source-host-grouped split on TON_IoT (no host is in both train and test) and
      (b) gates calibrated on a held-out half of the legitimate scores instead of the hand-tuned synthetic values.

Run: python3 -m sim.experiments_review      Output: results/review_metrics.json
"""
import copy, json, os, random
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.metrics import roc_auc_score

from .experiments_iiot import TIERS, ATTACK, CLASS_MIX, draw, SEED
from .trust_engine import TrustEngine, TrustWeights
from . import experiments_realdata as rd
from .experiments_wustl import F as WF, calib

B = os.path.dirname(os.path.dirname(__file__)); D = os.path.join(B, "data"); RES = os.path.join(B, "results")
OUT = os.path.join(RES, "review_metrics.json")
W = TrustWeights()


# ------------------------------------------------------------------ R1 ablation
def population(kind, rng, n=4000, warm=3, upset=0.0):
    """(class, T, A, P, N, R) for n requests; mirrors experiments_iiot.pop_scores but keeps the four signals."""
    te = TrustEngine(); out = []
    classes = list(CLASS_MIX); probs = list(CLASS_MIX.values())
    for i in range(n):
        did = f"d{i}"; cls = rng.choices(classes, probs)[0]
        for _ in range(warm): te.score(did, *draw(cls, rng))
        p, a, nn = draw(cls, rng, upset) if kind == "legit" else ATTACK[kind](rng)
        R = te._reliability(did); T = te.score(did, p, a, nn)
        out.append((cls, T, a, p, nn, R))
    return out


def allow(policy, cfg, x):
    """Return (ALLOW, STEP_UP) booleans for one request under the named policy."""
    _, T, A, P, N, R = x
    if policy == "threshold_only":
        deny_gate = False; strict = False; th, m = cfg["t"], cfg["m"]; S = T
    elif policy == "gate_only":
        deny_gate = A > cfg["g"]; strict = False; th, m = cfg["t"], cfg["m"]; S = T
    elif policy == "strict_only":
        deny_gate = False; strict = cfg["strict"]; th, m = cfg["t"], cfg["m"]; S = T
    elif policy == "gate_strict":
        deny_gate = A > cfg["g"]; strict = cfg["strict"]; th, m = cfg["t"], cfg["m"]; S = T
    elif policy == "min_score":           # non-linear aggregation, threshold tau is set elsewhere (cfg["tau"])
        deny_gate = False; strict = False; th, m = cfg["tau"], 0.0; S = min(P, 1 - A, N, R)
    elif policy == "raised_threshold":    # linear score, threshold raised until legitimate allowance matches the full policy
        deny_gate = False; strict = False; th, m = cfg["theta2"], 0.0; S = T
    if deny_gate or S < th: return False, False
    if S < th + m: return False, (not strict)
    return True, False


def fit_threshold(policy, cfg, legit_elig, target_allow):
    """Smallest threshold for which the policy still allows at least target_allow of legitimate requests."""
    lo, hi = 0.0, 1.0
    for _ in range(40):
        mid = (lo + hi) / 2; c = dict(cfg, tau=mid, theta2=mid)
        a = np.mean([allow(policy, c, x)[0] for x in legit_elig])
        if a >= target_allow: lo = mid
        else: hi = mid
    return lo


def r1_ablation():
    rng = random.Random(SEED + 11)
    legit = population("legit", rng, upset=0.05)
    atk = {k: population(k, random.Random(SEED + 17), n=4000) for k in ("partial mimicry", "stealthy mimicry", "full spoof (P,N,R=1)")}
    out = {}
    for rname in ("historian.write", "plc.setpoint.write", "plc.firmware.update"):
        cfg = TIERS[rname]; el = [x for x in legit if x[0] in cfg["classes"]]
        full_allow = np.mean([allow("gate_strict", cfg, x)[0] for x in el])
        tau = fit_threshold("min_score", cfg, el, full_allow); th2 = fit_threshold("raised_threshold", cfg, el, full_allow)
        c2 = dict(cfg, tau=tau, theta2=th2)
        rows = {}
        for pol in ("threshold_only", "gate_only", "strict_only", "gate_strict", "raised_threshold", "min_score"):
            r = {"legit_allow_pct": 100 * float(np.mean([allow(pol, c2, x)[0] for x in el]))}
            for k, pop in atk.items():
                pe = [x for x in pop if x[0] in cfg["classes"]]
                a = [allow(pol, c2, x) for x in pe]
                r[k] = {"allow_pct": 100 * float(np.mean([u for u, _ in a])), "allow_or_stepup_pct": 100 * float(np.mean([u or s for u, s in a]))}
            rows[pol] = r
        rows["_matched_threshold"] = {"raised_theta": th2, "min_score_tau": tau, "target_legit_allow_pct": 100 * float(full_allow)}
        out[rname] = rows
    return out


# ------------------------------------------------------------------ R2 exposure from decision time
def r2_exposure(runs=30, n_dev=60, seed=SEED + 21):
    g = json.load(open(os.path.join(RES, "besu_metrics_gcp4region.json")))["revocation"]
    h = json.load(open(os.path.join(RES, "besu_metrics.json")))["revocation"]
    def window(stats, rng):
        x = rng.gauss(stats["mean"], stats["sd"]); return min(max(x, stats["min"]), stats["max"]) / 1000.0
    out = {}
    for name, S in (("four_regions", g), ("one_host", h)):
        for path, key in (("audited_until_receipt", "submit_to_receipt_ms"), ("fast_until_replica_visible", "submit_to_replica_ms")):
            rng = random.Random(seed); per_run = []; worst = 0
            for r in range(runs):
                cnt = []
                for d in range(n_dev):
                    t_rev = rng.uniform(100, 500); L = window(S[key], rng); phase = rng.random()   # 1 request/s
                    first = np.ceil(t_rev - phase) + phase                                          # first request time >= t_rev
                    n = int(max(0, np.floor((t_rev + L - first)) + 1)) if first < t_rev + L else 0
                    cnt.append(n)
                per_run.append(np.mean(cnt)); worst = max(worst, max(cnt))
            out[f"{name}:{path}"] = {"window_stats_ms": {k: S[key][k] for k in ("mean", "sd", "min", "max")},
                                     "mean_exposure_requests": float(np.mean(per_run)), "max_exposure_requests": int(worst), "runs": runs}
    return {"definition": "requests accepted per device at 1 request/s after the revocation transaction was SUBMITTED "
                          "(decision time), i.e. including the block period; window sampled from the measured Besu distribution (clipped to observed min/max)",
            "results": out}


# ------------------------------------------------------------------ R3 real traffic
def load_ton_with_hosts():
    n = pd.read_csv(os.path.join(D, "Train_Test_Network.csv"), encoding="utf-8-sig", low_memory=False)
    n = n.drop_duplicates().reset_index(drop=True)
    X = n[rd.FEATS].copy()
    for c in ['proto', 'service', 'conn_state']: X[c] = X[c].astype('category').cat.codes
    for c in ['duration', 'src_bytes', 'dst_bytes']: X[c] = pd.to_numeric(X[c], errors='coerce').fillna(0)
    return X.astype(float), n.label.values, n.type.values, n.src_ip.values


def with_gates(gates):
    t = copy.deepcopy(TIERS)
    for k, g in gates.items(): t[k]["g"] = g
    return t


def policy_summary(A_leg, A_atk, tiers, rng_seed, evasion=1.0, n_req=2000):
    rd.TIERS = tiers
    try:
        res = rd.policy_eval(A_leg, A_atk, np.random.default_rng(rng_seed), n_req=n_req, evasion=evasion)
    finally:
        rd.TIERS = TIERS
    s = {}
    for rname in ("historian.write", "plc.setpoint.write", "plc.firmware.update"):
        r = res[rname]; ks = list(r["attack_accepted"])
        s[rname] = {"legit_allow_full": r["legit_allow_full"], "gate": tiers[rname]["g"],
                    "attack_full_mean": float(np.mean([r["attack_accepted"][k]["full_policy"] for k in ks])),
                    "attack_full_worst": float(np.max([r["attack_accepted"][k]["full_policy"] for k in ks])),
                    "attack_thr_mean": float(np.mean([r["attack_accepted"][k]["threshold_only"] for k in ks])), "types": len(ks)}
    return s


def calibrated_gates(A_leg, q=0.99, seed=0):
    """Gate = q-quantile of one half of the legitimate scores; the other half is used for evaluation."""
    rng = np.random.default_rng(seed); idx = rng.permutation(len(A_leg)); h = len(A_leg) // 2
    g = float(np.quantile(A_leg[idx[:h]], q)); g = max(g, 0.05)
    return g, A_leg[idx[h:]]


def r3_real():
    out = {}
    X, y, t, host = load_ton_with_hosts()
    types = sorted(set(t) - {"normal"})
    # (a) host-grouped split
    seeds = rd.SEEDS; sup_auc, if_auc, seen_by_seed = [], [], []
    for s in seeds:
        tr, te = next(GroupShuffleSplit(n_splits=1, test_size=.3, random_state=s).split(X, y, groups=host))
        Xtr, Xte, ytr, yte, tte = X.iloc[tr], X.iloc[te], y[tr], y[te], t[te]
        if ytr.min() == ytr.max() or yte.min() == yte.max(): continue
        sup = HistGradientBoostingClassifier(random_state=s).fit(Xtr, ytr); p = sup.predict_proba(Xte)[:, 1]
        iso = IsolationForest(n_estimators=200, random_state=s).fit(Xtr[ytr == 0]); sc = -iso.score_samples(Xte)
        sup_auc.append(roc_auc_score(yte, p)); if_auc.append(roc_auc_score(yte, sc))
        if s == seeds[0]: first = (p, sc, yte, tte, len(np.unique(host[tr])), len(np.unique(host[te])))
    p, sc, yte, tte, nh_tr, nh_te = first
    present = {k: int((tte == k).sum()) for k in types if (tte == k).sum() >= 50}
    lo, hi = np.quantile(sc[yte == 0], .5), np.quantile(sc[yte == 0], .999)
    A_if = np.clip((sc - lo) / (hi - lo), 0, 1)
    grp = {"hosts_train_test": [int(nh_tr), int(nh_te)], "sup_auc_mean": float(np.mean(sup_auc)), "sup_auc_sd": float(np.std(sup_auc)),
           "iforest_auc_mean": float(np.mean(if_auc)), "iforest_auc_sd": float(np.std(if_auc)), "splits_used": len(sup_auc),
           "attack_types_with_>=50_test_flows": present}
    for name, A in (("supervised", p), ("iforest", A_if)):
        leg = A[yte == 0]; atk = {k: A[tte == k] for k in present}
        g_cal, leg_eval = calibrated_gates(leg)
        hand = TIERS
        cal = with_gates({"historian.write": g_cal, "plc.setpoint.write": g_cal, "plc.firmware.update": g_cal})
        grp[name] = {"hand_tuned_gates": policy_summary(leg, atk, hand, 21),
                     "calibrated_gate_q99": {"gate": g_cal, "policy": policy_summary(leg_eval, atk, cal, 22),
                                             "legit_denied_by_gate_pct_on_eval_half": float((leg_eval > g_cal).mean() * 100),
                                             "evasion_best10pct": policy_summary(leg_eval, atk, cal, 23, evasion=0.10, n_req=1500)}}
        grp[name]["legit_A_quantiles"] = {q: float(np.quantile(leg, q)) for q in (.5, .9, .99, .999)}
    out["ton_iot_host_grouped"] = grp
    # (b) calibrated gates on the original stratified split (seen types and held-out types)
    s0 = rd.SEEDS[0]
    Xtr, Xte, ytr, yte, ttr, tte = train_test_split(X, y, t, test_size=.3, stratify=t, random_state=s0)
    sup = HistGradientBoostingClassifier(random_state=s0).fit(Xtr, ytr); p = sup.predict_proba(Xte)[:, 1]
    A_leg = p[yte == 0]; seen = {k: p[tte == k] for k in types}
    held = {}
    for k in types:
        g = HistGradientBoostingClassifier(random_state=s0).fit(Xtr[ttr != k], ytr[ttr != k]); held[k] = g.predict_proba(Xte[tte == k])[:, 1]
    g_cal, leg_eval = calibrated_gates(A_leg)
    cal = with_gates({"historian.write": g_cal, "plc.setpoint.write": g_cal, "plc.firmware.update": g_cal})
    out["ton_iot_stratified_supervised"] = {
        "hand_tuned_gates": {"seen": policy_summary(A_leg, seen, TIERS, 31), "held_out": policy_summary(A_leg, held, TIERS, 32)},
        "calibrated_gate_q99": {"gate": g_cal, "seen": policy_summary(leg_eval, seen, cal, 33), "held_out": policy_summary(leg_eval, held, cal, 34),
                                "held_out_evasion_best10pct": policy_summary(leg_eval, held, cal, 35, evasion=0.10, n_req=1500)}}
    # (c) WUSTL-2018, isolation forest (the case where hand-tuned gates cost the most legitimate traffic)
    d = pd.read_csv(os.path.join(D, "wustl-scada-2018.csv")).drop_duplicates().reset_index(drop=True)
    Xw, yw = d[WF], d["Target"].values
    Xtr, Xte, ytr, yte = train_test_split(Xw, yw, test_size=.3, stratify=yw, random_state=s0)
    iso = IsolationForest(n_estimators=200, random_state=s0).fit(Xtr[ytr == 0]); f = calib(-iso.score_samples(Xtr[ytr == 0]))
    A = f(-iso.score_samples(Xte)); leg, atk = A[yte == 0], {"attack": A[yte == 1]}
    g_cal, leg_eval = calibrated_gates(leg)
    cal = with_gates({"historian.write": g_cal, "plc.setpoint.write": g_cal, "plc.firmware.update": g_cal})
    out["wustl2018_iforest"] = {"hand_tuned_gates": policy_summary(leg, atk, TIERS, 41),
                                "calibrated_gate_q99": {"gate": g_cal, "policy": policy_summary(leg_eval, atk, cal, 42),
                                                        "evasion_best10pct": policy_summary(leg_eval, atk, cal, 43, evasion=0.10, n_req=1500)}}
    return out


def main():
    out = {"seed": SEED}
    print("R1 ablation ..."); out["R1_ablation"] = r1_ablation(); print(json.dumps(out["R1_ablation"]["plc.setpoint.write"], indent=1)[:1500])
    print("R2 exposure ..."); out["R2_exposure"] = r2_exposure(); print(json.dumps(out["R2_exposure"]["results"], indent=1)[:1200])
    json.dump(out, open(OUT, "w"), indent=2)
    print("R3 real traffic ..."); out["R3_real"] = r3_real()
    json.dump(out, open(OUT, "w"), indent=2); print("saved", OUT)


if __name__ == "__main__":
    main()
