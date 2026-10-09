"""
experiments_realdata.py -- policy evaluation driven by REAL traffic labels from the TON_IoT datasets.

Real:      the behavioural anomaly signal A comes from detectors trained on TON_IoT network flows
           (Train_Test_Network.csv), and telemetry detectability is measured on four TON_IoT IoT files.
Synthetic: posture P, network context N and the reliability warm-up (TON_IoT has no such fields); the pairing of a
           flow-derived A with a device identity is arbitrary (no join key exists), and attackers spoof P=N=1.

Data location: data/ (IoT CSVs) and data/Train_Test_Network.csv. Output: results/realdata_metrics.json
Run: python3 -m sim.experiments_realdata
"""
import glob, json, os, random
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

from .trust_engine import TrustEngine
from .experiments_iiot import TIERS, decide
from .contracts import Effect

B = os.path.dirname(os.path.dirname(__file__)); D = os.path.join(B, "data"); OUT = os.path.join(B, "results", "realdata_metrics.json")
SEEDS = [11, 12, 13, 14, 15]
FEATS = ['proto', 'service', 'duration', 'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes', 'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dst_port']


def load_network():
    n = pd.read_csv(os.path.join(D, "Train_Test_Network.csv"), encoding="utf-8-sig", low_memory=False)
    raw = len(n); n = n.drop_duplicates().reset_index(drop=True)
    X = n[FEATS].copy()
    for c in ['proto', 'service', 'conn_state']: X[c] = X[c].astype('category').cat.codes
    for c in ['duration', 'src_bytes', 'dst_bytes']: X[c] = pd.to_numeric(X[c], errors='coerce').fillna(0)
    return X.astype(float), n.label.values, n.type.values, raw


def telemetry_table():
    rows = []
    for f in sorted(glob.glob(os.path.join(D, "Train_Test_IoT_*.csv"))):
        d = pd.read_csv(f); raw = len(d)
        for c in d.select_dtypes(include=['object', 'string']).columns: d[c] = d[c].astype(str).str.strip()  # Fridge: padded strings leak the label
        d = d.drop_duplicates().reset_index(drop=True)
        feats = [c for c in d.columns if c not in ('date', 'time', 'label', 'type')]
        X = pd.get_dummies(d[feats]).astype(float)
        aucs_sup, aucs_if = [], []
        for s in SEEDS:
            Xtr, Xte, ytr, yte = train_test_split(X, d.label, test_size=.3, stratify=d.type, random_state=s)
            sup = HistGradientBoostingClassifier(random_state=s).fit(Xtr, ytr)
            iso = IsolationForest(n_estimators=200, random_state=s).fit(Xtr[ytr == 0])
            aucs_sup.append(roc_auc_score(yte, sup.predict_proba(Xte)[:, 1])); aucs_if.append(roc_auc_score(yte, -iso.score_samples(Xte)))
        rows.append({"file": os.path.basename(f), "rows_raw": raw, "rows_dedup": len(d), "normal": int((d.label == 0).sum()), "attack": int((d.label == 1).sum()),
                     "features": feats, "fridge_whitespace_note": "temp_condition strings carry label-specific padding in the raw file (AUC 1.0 if unstripped)", "sup_auc_mean": float(np.mean(aucs_sup)), "sup_auc_sd": float(np.std(aucs_sup)),
                     "iforest_auc_mean": float(np.mean(aucs_if)), "iforest_auc_sd": float(np.std(aucs_if))})
    return rows


def policy_eval(A_leg, A_atk_by_type, rng, n_req=3000, evasion=1.0):
    """Run requests through the four tiers. Legit: native-device P,N (synthetic) with real A. Attacker: P=N=1 (spoofed), real A."""
    res = {}
    for rname, cfg in TIERS.items():
        te = TrustEngine()
        def run(Apool, attack):
            acc = []
            for i in range(n_req):
                did = f"{rname}-{attack}-{i}"
                for _ in range(3): te.score(did, rng.uniform(.75, 1), float(rng.choice(A_leg)), rng.uniform(.7, 1))
                a = float(rng.choice(Apool))
                p, nn = (1.0, 1.0) if attack else (rng.uniform(.75, 1), rng.uniform(.7, 1))
                T = te.score(did, p, a, nn)
                acc.append((T, a))
            return acc
        leg = run(A_leg, False)
        e_leg_full = np.mean([decide(rname, T, a, cfg) == Effect.ALLOW for T, a in leg]) * 100
        e_leg_thr = np.mean([decide(rname, T, a, cfg, gate=False, strict=False) == Effect.ALLOW for T, a in leg]) * 100
        row = {"legit_allow_threshold": e_leg_thr, "legit_allow_full": e_leg_full, "attack_accepted": {}}
        for k, pool in A_atk_by_type.items():
            pool = np.sort(pool)[: max(1, int(len(pool) * evasion))] if evasion < 1 else pool
            atk = run(pool, True)
            row["attack_accepted"][k] = {"threshold_only": np.mean([decide(rname, T, a, cfg, gate=False, strict=False) == Effect.ALLOW for T, a in atk]) * 100,
                                         "full_policy": np.mean([decide(rname, T, a, cfg) == Effect.ALLOW for T, a in atk]) * 100}
        res[rname] = row
    return res


def main():
    X, y, t, raw = load_network()
    out = {"network_rows_raw": int(raw), "network_rows_dedup": int(len(y)), "attack_types": sorted(set(t) - {"normal"})}
    print("telemetry ..."); out["telemetry"] = telemetry_table()
    # --- detector quality on flows (5 seeds)
    det = {"sup_auc": [], "iforest_auc": []}; per_type = {k: [] for k in out["attack_types"]}; loto = {k: [] for k in out["attack_types"]}
    seen_scores = None
    for s in SEEDS:
        Xtr, Xte, ytr, yte, ttr, tte = train_test_split(X, y, t, test_size=.3, stratify=t, random_state=s)
        sup = HistGradientBoostingClassifier(random_state=s).fit(Xtr, ytr); p = sup.predict_proba(Xte)[:, 1]
        iso = IsolationForest(n_estimators=200, random_state=s).fit(Xtr[ytr == 0]); sc = -iso.score_samples(Xte)
        det["sup_auc"].append(roc_auc_score(yte, p)); det["iforest_auc"].append(roc_auc_score(yte, sc))
        for k in per_type:
            m = (tte == k) | (yte == 0); per_type[k].append(roc_auc_score(yte[m], sc[m]))
        if s == SEEDS[0]: seen_scores = (p, yte, tte)
    # leave-one-attack-type-out (zero-day proxy), seed 0
    loto_scores = {}
    Xtr0, Xte0, ytr0, yte0, ttr0, tte0 = train_test_split(X, y, t, test_size=.3, stratify=t, random_state=SEEDS[0])
    for k in out["attack_types"]:
        trm = ttr0 != k
        g = HistGradientBoostingClassifier(random_state=SEEDS[0]).fit(Xtr0[trm], ytr0[trm])
        pk = g.predict_proba(Xte0[tte0 == k])[:, 1]; loto_scores[k] = pk
        pn = g.predict_proba(Xte0[yte0 == 0])[:, 1]
        loto[k] = {"auc_vs_normal": float(roc_auc_score(np.r_[np.zeros(len(pn)), np.ones(len(pk))], np.r_[pn, pk])), "detect_at_0.5": float((pk > .5).mean()), "mean_A": float(pk.mean())}
    out["detectors"] = {"sup_auc_mean": float(np.mean(det["sup_auc"])), "sup_auc_sd": float(np.std(det["sup_auc"])),
                        "iforest_auc_mean": float(np.mean(det["iforest_auc"])), "iforest_auc_sd": float(np.std(det["iforest_auc"])),
                        "iforest_auc_by_type": {k: [float(np.mean(v)), float(np.std(v))] for k, v in per_type.items()}, "loto_by_type": loto,
                        "seeds": SEEDS, "train_test": "70/30 stratified by type after de-duplication; src_ip/dst_ip/src_port excluded from features"}
    p, yte, tte = seen_scores
    A_leg_seen = p[yte == 0]; A_atk_seen = {k: p[tte == k] for k in out["attack_types"]}
    pg, yg, tg = loto_scores, None, None
    A_leg_loto = HistGradientBoostingClassifier(random_state=SEEDS[0])  # placeholder (legit scores from the all-types model)
    A_leg_loto = A_leg_seen
    print("policy (seen types) ..."); rng = np.random.default_rng(SEEDS[0])
    out["policy_seen"] = policy_eval(A_leg_seen, A_atk_seen, rng)
    print("policy (held-out types) ..."); out["policy_loto"] = policy_eval(A_leg_loto, loto_scores, np.random.default_rng(SEEDS[0] + 1))
    print("adaptive evasion ...")
    out["evasion_seen"] = {str(b): policy_eval(A_leg_seen, A_atk_seen, np.random.default_rng(SEEDS[0] + 2), n_req=1500, evasion=b) for b in (0.10, 0.01)}
    out["evasion_loto"] = {str(b): policy_eval(A_leg_loto, loto_scores, np.random.default_rng(SEEDS[0] + 3), n_req=1500, evasion=b) for b in (0.10, 0.01)}
    # gate sweep on real A (legit denied vs attack blocked)
    sweep = []
    allatk_seen = np.concatenate(list(A_atk_seen.values())); allatk_loto = np.concatenate(list(loto_scores.values()))
    for g in (0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9):
        sweep.append({"gate": g, "legit_denied_pct": float((A_leg_seen > g).mean() * 100), "attack_blocked_seen_pct": float((allatk_seen > g).mean() * 100), "attack_blocked_heldout_pct": float((allatk_loto > g).mean() * 100)})
    out["gate_sweep"] = sweep
    out["legit_A_quantiles"] = {q: float(np.quantile(A_leg_seen, q)) for q in (0.5, 0.9, 0.99, 0.999)}
    json.dump(out, open(OUT, "w"), indent=2); print("saved", OUT)


if __name__ == "__main__":
    main()
