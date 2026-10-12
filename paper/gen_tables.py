"""Generate LaTeX table bodies from results/*.json so every number in the paper is traceable."""
import json, os
B = os.path.join(os.path.dirname(__file__), "..", "results")
m = json.load(open(f"{B}/metrics.json")); x = json.load(open(f"{B}/extra_metrics.json")); e = json.load(open(f"{B}/evm_metrics.json"))
def fmt(n): return f"{n:,.0f}".replace(",", "{,}")
# Table: scaling
L = ["\\begin{tabular}{@{}rrrrrr@{}}", "\\toprule", "$n$ & Reg.\\ lat. & AuthZ lat. & AuthZ p95 & Reg.\\ tput & AuthZ tput \\\\", "\\midrule"]
for r in m["scaling_results"]:
    L.append(f"{fmt(r['fleet_size'])} & {r['reg_latency_ms_mean']:.3f} & {r['authz_latency_ms_mean']:.3f} & {r['authz_latency_ms_p95']:.3f} & {fmt(r['registration_throughput_tps'])} & {fmt(r['authorization_throughput_tps'])} \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open(os.path.join(os.path.dirname(__file__), "tab_scaling.tex"), "w").write("\n".join(L))
# Table: gas
names = [("register","\\texttt{registerDevice}"),("suspend","\\texttt{suspendDevice}"),("reinstate","\\texttt{reinstateDevice}"),("revoke","\\texttt{revokeDevice}"),
         ("evalAllow","\\texttt{evaluateAccess} (ALLOW)"),("evalStepUp","\\texttt{evaluateAccess} (STEP\\_UP)"),("denyBadOracle","\\texttt{evaluateAccess} (DENY, bad oracle sig.)"),
         ("denyReplay","\\texttt{evaluateAccess} (DENY, replay)"),("denyRevoked","\\texttt{evaluateAccess} (DENY, revoked)")]
L = ["\\begin{tabular}{@{}lrr@{}}", "\\toprule", "\\textbf{Operation} & \\textbf{Mean gas} & \\textbf{Std.} \\\\", "\\midrule"]
for k, n in names:
    g = e["gas"][k]; L.append(f"{n} & {fmt(g['mean'])} & {g['sd']:.1f} \\\\")
d = e["deploy_gas"]
L += ["\\midrule", f"Deploy \\texttt{{IdentityRegistry}} & {fmt(d['IdentityRegistry'])} & -- \\\\", f"Deploy \\texttt{{ZeroTrustAccess}} & {fmt(d['ZeroTrustAccess'])} & -- \\\\", f"\\texttt{{definePolicy}} (2 classes) & {fmt(d['definePolicy'])} & -- \\\\", "\\bottomrule", "\\end{tabular}"]
open(os.path.join(os.path.dirname(__file__), "tab_gas.tex"), "w").write("\n".join(L))
# Table: baselines
r = x["E2_baselines"]["results"]
L = ["\\begin{tabular}{@{}lrrr@{}}", "\\toprule", "\\textbf{Scheme} & \\textbf{Mean exp.} & \\textbf{Max exp.} & \\textbf{Lat. (ms)} \\\\", "\\midrule"]
for k, v in r.items():
    k2 = k.replace("Proposed (continuous, per-request)", "\\textbf{Proposed (per-request)}").replace("PKI + CRL", "PKI$+$CRL")
    L.append(f"{k2} & {v['mean_requests_accepted_after_revocation']:.1f} & {v['max_requests_accepted_after_revocation']} & {v['mean_decision_latency_ms']:.3f} \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open(os.path.join(os.path.dirname(__file__), "tab_base.tex"), "w").write("\n".join(L))
# Table: ablation
a = x["E3_ablation"]["results"]
L = ["\\begin{tabular}{@{}lrrrr@{}}", "\\toprule", "& \\multicolumn{2}{c}{Partial mimicry} & \\multicolumn{2}{c}{Stealthy mimicry} \\\\", "\\textbf{Score variant} & AUC & TPR & AUC & TPR \\\\", "\\midrule"]
for k, v in a.items():
    if k.startswith("Identity"): continue
    p, s = v["partial mimicry"], v["stealthy mimicry"]
    L.append(f"{k.replace('w/o','w/o')} & {p['auc']:.3f} & {p['tpr_at_fpr1']*100:.1f}\\% & {s['auc']:.3f} & {s['tpr_at_fpr1']*100:.1f}\\% \\\\")
L.append("Identity-only (no trust) & 0.500 & 0.0\\% & 0.500 & 0.0\\% \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open(os.path.join(os.path.dirname(__file__), "tab_ablate.tex"), "w").write("\n".join(L))
gv = json.load(open(f"{B}/governance_metrics.json"))["results"]; gg = {r["N"]: r for r in json.load(open(f"{B}/evm_governance_gas.json"))}
L = ["\\begin{tabular}{@{}rrrrrrr@{}}", "\\toprule", "$N$ & $q$ & Coop. & Dissent & Appr.\\% & Forced\\% & Total gas \\\\", "\\midrule"]
for r in gv:
    n = r["N"]; G = gg[n]
    L.append(f"{n} & {r['quorum']} & {r['cooperative_latency_ms']['mean']:.3f} & {r['dissent_latency_ms']['mean']:.3f} & {r['correct_approval_under_max_dissent_pct']:.0f} & {100-r['forced_revocation_blocked_pct']:.0f} & {fmt(G['total_gas_to_revoke'])} \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open(os.path.join(os.path.dirname(__file__), "tab_gov.tex"), "w").write("\n".join(L))
print("tables written")

# ---------------- industrial tables
ii = json.load(open(f"{B}/iiot_metrics.json")); ig = json.load(open(f"{B}/evm_iiot_gas.json"))
T = ii["X1_tiers"]["results"]
nm = {"telemetry.read": "telemetry.read", "historian.write": "historian.write", "plc.setpoint.write": "plc.setpoint.write", "plc.firmware.update": "plc.firmware.update"}
L = ["\\begin{tabular}{@{}lccrrr@{}}", "\\toprule", "\\textbf{Resource} & $\\theta$ & $g$ & Legit. & Stealthy & Spoof \\\\", "\\midrule"]
for k, v in T.items():
    a, b = v["threshold_only"]["legit_allow_pct"], v["full_policy"]["legit_allow_pct"]
    s = v["attack_accepted_pct"]["stealthy mimicry"]; f = v["attack_accepted_pct"]["full spoof (P,N,R=1)"]
    L.append(f"{nm[k]} (T{v['tier']}) & {v['min_trust']:.2f} & {v['anomaly_gate']:.2f} & {a:.1f}$\\to${b:.1f} & {s['threshold_only']:.1f}$\\to${s['full_policy']:.1f} & {f['threshold_only']:.1f}$\\to${f['full_policy']:.1f} \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open("tab_tiers.tex", "w").write("\n".join(L))
L = ["\\begin{tabular}{@{}rrrrr@{}}", "\\toprule", "Devices & One tx each & \\texttt{revokeBatch} & Saving & \\texttt{suspendBatch} \\\\", "\\midrule"]
for r in ig["recall"]:
    L.append(f"{r['devices']} & {fmt(r['individual_total_gas'])} & {fmt(r['batch_gas'])} & {r['saving_pct']:.1f}\\% & {fmt(r['suspendBatch_gas'])} \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open("tab_recall.tex", "w").write("\n".join(L))
print("industrial tables written")
L = ["\\begin{tabular}{@{}rrrrrr@{}}", "\\toprule", "Outage & Revoked & \\multicolumn{2}{c}{Avail.\\ (\\%)} & Unsafe & T2--T3 \\\\", "(s) & devices & closed & degr. & accepts & denied \\\\", "\\midrule"]
for r in ii["X5_outage"]["results"]:
    fc, dg = r["fail_closed"], r["degraded_cache"]
    L.append(f"{r['outage_s']} & {r['revoked_devices']} & {fc['availability_pct']:.1f} & {dg['availability_pct']:.1f} & {fmt(dg['unsafe'])} & {dg['tier2_denied_pct']:.0f}\\% \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open("tab_outage.tex", "w").write("\n".join(L))

# ---------------- real-data tables (TON_IoT)
rd = json.load(open(f"{B}/realdata_metrics.json"))
L = ["\\begin{tabular}{@{}lrrrr@{}}", "\\toprule", "File & Rows & Att.\\% & Sup. AUC & IF AUC \\\\", "\\midrule"]
for r in rd["telemetry"]:
    nmf = r["file"].replace("Train_Test_IoT_", "").replace(".csv", "")
    L.append(f"{nmf} & {fmt(r['rows_dedup'])} & {100*r['attack']/r['rows_dedup']:.0f} & {r['sup_auc_mean']:.3f} & {r['iforest_auc_mean']:.3f} \\\\")
L += ["\\bottomrule", "\\end{tabular}"]
open("tab_telemetry.tex", "w").write("\n".join(L))
import numpy as _np
def agg(pol, tier, key):
    v = [a[key] for a in pol[tier]["attack_accepted"].values()]; return _np.mean(v), max(v)
rows = [("Seen types", rd["policy_seen"]), ("Held-out types", rd["policy_loto"]),
        ("Held-out, best 10\\%", rd["evasion_loto"]["0.1"]), ("Held-out, best 1\\%", rd["evasion_loto"]["0.01"])]
L = ["\\begin{tabular}{@{}llrrrr@{}}", "\\toprule", "Scenario & Tier & Thr.\\ mean & Full mean & Thr.\\ worst & Full worst \\\\", "\\midrule"]
for name, pol in rows:
    for tier, tl in (("historian.write", "T1"), ("plc.setpoint.write", "T2"), ("plc.firmware.update", "T3")):
        tm, tw = agg(pol, tier, "threshold_only"); fm, fw = agg(pol, tier, "full_policy")
        L.append(f"{name if tl=='T1' else ''} & {tl} & {tm:.1f} & {fm:.1f} & {tw:.1f} & {fw:.1f} \\\\")
    L.append("\\midrule") if name != rows[-1][0] else None
L += ["\\bottomrule", "\\end{tabular}"]
open("tab_realpolicy.tex", "w").write("\n".join(L))
print("real-data tables written")

# ---- additional baselines (validity-window schemes and a central PDP)
b2 = json.load(open("../results/baselines2.json"))["results"]
L = [r"\begin{tabular}{@{}lrrr@{}}", r"\toprule",
     r"\textbf{Scheme} & \textbf{Mean exp.} & \textbf{Max exp.} & \textbf{Avail. (\%)} \\", r"\midrule"]
for k, v in b2.items():
    name = k.replace("&", r"\&")
    L.append(f"{name} & {v['mean_exposure']:.1f} & {v['max_exposure']} & {v['legit_availability_pct']:.1f} \\\\")
L += [r"\bottomrule", r"\end{tabular}"]
open("tab_base2.tex", "w").write("\n".join(L))

# ---- WUSTL-IIOT-2018 table
wu = json.load(open(f"{B}/wustl_metrics.json"))
names = {"telemetry.read": "T0", "historian.write": "T1", "plc.setpoint.write": "T2", "plc.firmware.update": "T3"}
L = [r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
     r" & \multicolumn{3}{c}{Supervised $A$} & \multicolumn{3}{c}{Isolation Forest $A$} \\",
     r"\cmidrule(lr){2-4}\cmidrule(lr){5-7}",
     r"Tier & Legit & Att.\ thr. & Att.\ full & Legit & Att.\ thr. & Att.\ full \\", r"\midrule"]
for rn, tn in names.items():
    cells = []
    for key in ("supervised", "iforest_normal_only"):
        v = wu[key]["policy"][rn]; a = v["attack_accepted"]["attack"]
        cells += [f"{v['legit_allow_full']:.1f}", f"{a['threshold_only']:.1f}", f"{a['full_policy']:.1f}"]
    L.append(f"{tn} & " + " & ".join(cells) + r" \\")
L += [r"\bottomrule", r"\end{tabular}"]
open("tab_wustl.tex", "w").write("\n".join(L))

# ---- WUSTL-IIoT-2021 table
w21 = json.load(open(f"{B}/wustl2021_metrics.json"))
def mean_full(pol, rn):
    a = pol[rn]["attack_accepted"]; return sum(v["full_policy"] for v in a.values()) / len(a)
def mean_thr(pol, rn):
    a = pol[rn]["attack_accepted"]; return sum(v["threshold_only"] for v in a.values()) / len(a)
L = [r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
     r" & \multicolumn{3}{c}{Supervised $A$} & \multicolumn{2}{c}{Isolation Forest $A$} & \\",
     r"\cmidrule(lr){2-4}\cmidrule(lr){5-6}",
     r"Tier & Legit & Seen & Held-out & Legit & Attack & Thr.-only$^{a}$ \\", r"\midrule"]
for rn, tn in names.items():
    ps, pl, pi = w21["policy_seen"], w21["policy_loto"], w21["policy_iforest"]
    L.append(f"{tn} & {ps[rn]['legit_allow_full']:.1f} & {mean_full(ps, rn):.1f} & {mean_full(pl, rn):.1f} & {pi[rn]['legit_allow_full']:.1f} & {mean_full(pi, rn):.1f} & {mean_thr(pl, rn):.1f} \\\\")
L += [r"\bottomrule", r"\end{tabular}"]
open("tab_wustl21.tex", "w").write("\n".join(L))

# ---- Multi-region Google Cloud vs single-host Besu table
g1 = json.load(open(f"{B}/besu_metrics.json")); g4 = json.load(open(f"{B}/besu_metrics_gcp4region.json"))
def ms(x, d=0): return f"{x['mean']:.{d}f} $\\pm$ {x['sd']:.{d}f}"
def sec(x): return f"{x['mean']/1000:.2f} $\\pm$ {x['sd']/1000:.2f}"
rows = [
 ("Block interval (s)", lambda g: ms(g['block_interval_s'])),
 ("\\texttt{register}, submit$\\to$receipt (ms)", lambda g: ms(g['sequential_latency_ms']['register'])),
 ("\\texttt{evaluateAccess}, submit$\\to$receipt (ms)", lambda g: ms(g['sequential_latency_ms']['evaluateAccess'])),
 ("\\texttt{anchorDecisions}, submit$\\to$receipt (ms)", lambda g: ms(g['sequential_latency_ms']['anchor'])),
 ("Revocation, submit$\\to$receipt (ms)", lambda g: ms(g['revocation']['submit_to_receipt_ms'])),
 ("Revocation, submit$\\to$visible on replica (ms)", lambda g: ms(g['revocation']['submit_to_replica_ms'])),
 ("Replica minus receipt (ms)", lambda g: ms(g['revocation']['receipt_to_replica_ms'])),
 ("Quorum revocation $N{=}5,q{=}3$, sequential (s)", lambda g: sec(g['governance_N5_q3']['sequential_votes_ms'])),
 ("Quorum revocation $N{=}5,q{=}3$, parallel (s)", lambda g: sec(g['governance_N5_q3']['parallel_votes_ms'])),
 ("\\texttt{revokeBatch}, 50 devices, receipt (s)", lambda g: f"{g['batch_recall'][0]['revokeBatch_receipt_ms']/1000:.2f}"),
 ("\\texttt{revokeBatch}, 200 devices, receipt (s)", lambda g: f"{g['batch_recall'][1]['revokeBatch_receipt_ms']/1000:.2f}"),
]
for i, off in enumerate((100, 300, 600)):
    rows.append((f"Throughput, {off} offered (tx/s)", (lambda i: lambda g: f"{g['audited_decision_throughput'][i]['tps']:.1f}")(i)))
rows.append(("Mean latency at 600 offered (s)", lambda g: f"{g['audited_decision_throughput'][2]['latency_ms']['mean']/1000:.1f}"))
L = [r"\begin{tabular}{@{}lrr@{}}", r"\toprule", r"Measurement & One host & Four regions \\", r"\midrule"]
for name, f in rows: L.append(f"{name} & {f(g1)} & {f(g4)} \\\\")
L += [r"\bottomrule", r"\end{tabular}"]
open("tab_gcp.tex", "w").write("\n".join(L))
