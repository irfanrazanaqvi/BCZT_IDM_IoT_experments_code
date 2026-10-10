"""
experiments_wustl2021.py -- third real-traffic study: WUSTL-IIoT-2021 (labelled attack types on an industrial testbed).

Real:      Argus flow records, 1,194,464 rows, types normal / DoS / Reconn / CommInj / Backdoor (data/wustl_iiot_2021.csv).
Excluded:  timestamps, IP addresses, source port, IdleTime (epoch-like, separates attack types by capture time) and the
           IP-ID fields; exact duplicates among the remaining columns are removed before splitting.
Synthetic: posture P, network context N, reliability warm-up (as in the TON_IoT study); flow-to-device pairing arbitrary.
Run: python3 -m sim.experiments_wustl2021    Output: results/wustl2021_metrics.json
"""
import json, os
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from .experiments_realdata import policy_eval

B = os.path.dirname(os.path.dirname(__file__)); D = os.path.join(B, "data"); OUT = os.path.join(B, "results", "wustl2021_metrics.json")
SEEDS = [11, 12, 13, 14, 15]
DROP = ["StartTime", "LastTime", "SrcAddr", "DstAddr", "Sport", "IdleTime", "sIpId", "dIpId"]


def calib(s_norm_train):
    lo, hi = np.quantile(s_norm_train, .5), np.quantile(s_norm_train, .999)
    return lambda s: np.clip((s - lo) / (hi - lo), 0, 1)


def main():
    d = pd.read_csv(os.path.join(D, "wustl_iiot_2021.csv"), low_memory=False); raw = len(d)
    d = d.drop(columns=DROP).drop_duplicates().reset_index(drop=True)
    t = d["Traffic"].values; y = d["Target"].values
    X = d.drop(columns=["Traffic", "Target"]); feats = list(X.columns)
    types = sorted(set(t) - {"normal"})
    out = {"rows_raw": int(raw), "rows_dedup": int(len(d)), "type_counts": {k: int((t == k).sum()) for k in ["normal"] + types},
           "n_features": len(feats), "excluded": DROP}
    det = {"sup": [], "iso": [], "sup_nottl": []}; per_type = {k: [] for k in types}
    for s in SEEDS:
        Xtr, Xte, ytr, yte, ttr, tte = train_test_split(X, y, t, test_size=.3, stratify=t, random_state=s)
        sup = HistGradientBoostingClassifier(random_state=s).fit(Xtr, ytr); p = sup.predict_proba(Xte)[:, 1]
        iso = IsolationForest(n_estimators=200, random_state=s).fit(Xtr[ytr == 0]); sc = -iso.score_samples(Xte)
        det["sup"].append(roc_auc_score(yte, p)); det["iso"].append(roc_auc_score(yte, sc))
        nt = [c for c in feats if c not in ("sTtl", "dTtl")]
        g2 = HistGradientBoostingClassifier(random_state=s).fit(Xtr[nt], ytr); det["sup_nottl"].append(roc_auc_score(yte, g2.predict_proba(Xte[nt])[:, 1]))
        for k in types:
            m = (tte == k) | (yte == 0); per_type[k].append(roc_auc_score(yte[m], sc[m]))
        if s == SEEDS[0]:
            p0, y0, t0 = p, yte, tte; Xtr0, ytr0, ttr0, Xte0 = Xtr, ytr, ttr, Xte
            sc0 = sc; fcal = calib(-iso.score_samples(Xtr[ytr == 0]))
    # leave-one-type-out with a supervised model (zero-day proxy)
    loto, loto_scores = {}, {}
    pn_all = None
    for k in types:
        g = HistGradientBoostingClassifier(random_state=SEEDS[0]).fit(Xtr0[ttr0 != k], ytr0[ttr0 != k])
        pk = g.predict_proba(Xte0[t0 == k])[:, 1]; pn = g.predict_proba(Xte0[y0 == 0])[:, 1]; loto_scores[k] = pk
        loto[k] = {"auc_vs_normal": float(roc_auc_score(np.r_[np.zeros(len(pn)), np.ones(len(pk))], np.r_[pn, pk])),
                   "detect_at_0.5": float((pk > .5).mean()), "mean_A": float(pk.mean()), "n_test": int(len(pk))}
    out["detectors"] = {"sup_auc_mean": float(np.mean(det["sup"])), "sup_auc_sd": float(np.std(det["sup"])),
                        "sup_auc_no_ttl_mean": float(np.mean(det["sup_nottl"])),
                        "iforest_auc_mean": float(np.mean(det["iso"])), "iforest_auc_sd": float(np.std(det["iso"])),
                        "iforest_auc_by_type": {k: [float(np.mean(v)), float(np.std(v))] for k, v in per_type.items()},
                        "loto_by_type": loto, "seeds": SEEDS, "split": "70/30 stratified by type after de-duplication"}
    A_leg = p0[y0 == 0]; A_seen = {k: p0[t0 == k] for k in types}
    A_leg_if = fcal(sc0[y0 == 0]); A_if = {k: fcal(sc0[t0 == k]) for k in types}
    print("policy ..."); rng = lambda o: np.random.default_rng(SEEDS[0] + o)
    out["policy_seen"] = policy_eval(A_leg, A_seen, rng(0))
    out["policy_loto"] = policy_eval(A_leg, loto_scores, rng(1))
    out["policy_iforest"] = policy_eval(A_leg_if, A_if, rng(2))
    out["evasion_loto"] = {str(b): policy_eval(A_leg, loto_scores, rng(3), n_req=1500, evasion=b) for b in (0.10, 0.01)}
    out["evasion_iforest"] = {str(b): policy_eval(A_leg_if, A_if, rng(4), n_req=1500, evasion=b) for b in (0.10, 0.01)}
    sweep = []
    allseen = np.concatenate(list(A_seen.values())); allloto = np.concatenate(list(loto_scores.values())); allif = np.concatenate(list(A_if.values()))
    for g in (0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9):
        sweep.append({"gate": g, "legit_denied_pct_sup": float((A_leg > g).mean() * 100), "blocked_seen_pct": float((allseen > g).mean() * 100),
                      "blocked_heldout_pct": float((allloto > g).mean() * 100),
                      "legit_denied_pct_if": float((A_leg_if > g).mean() * 100), "blocked_if_pct": float((allif > g).mean() * 100)})
    out["gate_sweep"] = sweep
    json.dump(out, open(OUT, "w"), indent=2); print("saved", OUT)


if __name__ == "__main__":
    main()
