"""
experiments_wustl.py -- second real-traffic check of the anomaly gate using WUSTL-IIOT-2018 (SCADA testbed).

Real:      flow records (7 features, binary label) from data/wustl-scada-2018.csv.
Caveats:   99.1% of the 7.04 M rows are exact duplicates (62,959 unique); only a binary label exists, so there are no
           attack types to hold out; the data are trivially separable by a supervised model. We therefore report the
           supervised detector AND an unsupervised Isolation Forest trained on normal flows only (a zero-day proxy),
           whose score is calibrated on normal data only. Posture/network context remain synthetic (as in the TON_IoT study).
Run: python3 -m sim.experiments_wustl      Output: results/wustl_metrics.json
"""
import json, os
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from .experiments_realdata import policy_eval

B = os.path.dirname(os.path.dirname(__file__)); D = os.path.join(B, "data"); OUT = os.path.join(B, "results", "wustl_metrics.json")
SEEDS = [11, 12, 13, 14, 15]
F = ["TotPkts", "TotBytes", "SrcPkts", "DstPkts", "SrcBytes"]


def calib(s_norm_train):
    lo, hi = np.quantile(s_norm_train, .5), np.quantile(s_norm_train, .999)
    return lambda s: np.clip((s - lo) / (hi - lo), 0, 1)


def main():
    d = pd.read_csv(os.path.join(D, "wustl-scada-2018.csv")); raw = len(d)
    u = d.drop_duplicates().reset_index(drop=True)
    X, y = u[F], u["Target"].values
    out = {"rows_raw": int(raw), "rows_unique": int(len(u)), "duplicate_pct": float(100 * (1 - len(u) / raw)),
           "normal_unique": int((y == 0).sum()), "attack_unique": int((y == 1).sum()),
           "features": F, "label": "binary (0 normal, 1 attack); no attack types available", "excluded": "Sport (source port), as in the TON_IoT study"}
    sup, iso_auc = [], []
    for s in SEEDS:
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.3, stratify=y, random_state=s)
        g = HistGradientBoostingClassifier(random_state=s).fit(Xtr, ytr); sup.append(roc_auc_score(yte, g.predict_proba(Xte)[:, 1]))
        iso = IsolationForest(n_estimators=200, random_state=s).fit(Xtr[ytr == 0]); iso_auc.append(roc_auc_score(yte, -iso.score_samples(Xte)))
        if s == SEEDS[0]:
            p_sup = g.predict_proba(Xte)[:, 1]; s_iso = -iso.score_samples(Xte); ytest = yte
            f = calib(-iso.score_samples(Xtr[ytr == 0])); A_iso = f(s_iso)
    out["detectors"] = {"sup_auc_mean": float(np.mean(sup)), "sup_auc_sd": float(np.std(sup)),
                        "iforest_auc_mean": float(np.mean(iso_auc)), "iforest_auc_sd": float(np.std(iso_auc)), "seeds": SEEDS,
                        "split": "70/30 stratified on de-duplicated unique rows"}
    for name, A in (("supervised", p_sup), ("iforest_normal_only", A_iso)):
        leg, atk = A[ytest == 0], A[ytest == 1]
        r = {"legit_A_quantiles": {q: float(np.quantile(leg, q)) for q in (.5, .9, .99, .999)},
             "attack_A_quantiles": {q: float(np.quantile(atk, q)) for q in (.01, .1, .5)}}
        r["policy"] = policy_eval(leg, {"attack": atk}, np.random.default_rng(SEEDS[0]))
        r["evasion"] = {str(b): policy_eval(leg, {"attack": atk}, np.random.default_rng(SEEDS[0] + 2), n_req=1500, evasion=b) for b in (0.10, 0.01)}
        r["gate_sweep"] = [{"gate": g, "legit_denied_pct": float((leg > g).mean() * 100), "attack_blocked_pct": float((atk > g).mean() * 100)} for g in (.05, .1, .2, .3, .5, .7, .9)]
        out[name] = r
    json.dump(out, open(OUT, "w"), indent=2); print("saved", OUT)


if __name__ == "__main__":
    main()
