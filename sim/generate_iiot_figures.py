"""Figures for the Industrial-IoT paper: fig7_iiot_arch.png and fig8_iiot_results.png (from results/*.json)."""
import json, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

B = os.path.dirname(os.path.dirname(__file__)); F = os.path.join(B, "figures"); R = os.path.join(B, "results")
BLUE, LB, OR, GR, LG, GN = "#1f4e79", "#cfe2f3", "#e07b00", "#5b5b5b", "#eeeeee", "#2e7d32"

def box(ax, x, y, w, h, t, fc=LB, ec=BLUE, fs=7.5, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.012", lw=1.1, ec=ec, fc=fc))
    ax.text(x + w / 2, y + h / 2, t, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal")

def arrow(ax, a, b, c=GR, ls="-"):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=9, lw=1.0, color=c, ls=ls))

def arch():
    fig, ax = plt.subplots(figsize=(7.2, 4.3)); ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    zones = [(0.00, 0.64, 1.0, 0.34, "Field zone (Purdue levels 0–1)", "#fff8e8"),
             (0.00, 0.30, 1.0, 0.32, "Site operations zone (levels 2–3)", "#eef5fb"),
             (0.00, 0.00, 1.0, 0.28, "Consortium zone (OEM, operator, auditor)", "#eef7ee")]
    for x, y, w, h, t, c in zones:
        ax.add_patch(FancyBboxPatch((x + .003, y + .005), w - .006, h - .01, boxstyle="round,pad=0.003,rounding_size=0.01", fc=c, ec="#aaaaaa", lw=0.8, ls="--"))
        ax.text(x + .012, y + h - .035, t, fontsize=7.5, fontweight="bold", color=GR, va="center")
    for i, t in enumerate(["Sensor /\nactuator", "PLC /\nrobot", "Legacy device\n(no keys)"]):
        box(ax, .03 + i * .15, .68, .13, .16, t, fc="#fff1cc" if i < 2 else "#ffe0cc", ec=OR, fs=7)
    box(ax, .50, .68, .20, .16, "Protocol gateway\n(identity proxy for\nlegacy devices)", fc="#ffe0cc", ec=OR, fs=7)
    box(ax, .76, .68, .21, .16, "Zone PEP\nverify, enforce, log\n(fast path + audited path)", fs=7, bold=False)
    box(ax, .03, .36, .20, .16, "HMI / engineering\nworkstation", fs=7)
    box(ax, .28, .36, .22, .16, "Trust engine (PDP)\nP, A, N, R signals\nper-tier policy", fs=7)
    box(ax, .55, .36, .18, .16, "Trust oracle\nsigns (DID, res., T, A,\nnonce)", fs=7)
    box(ax, .78, .36, .19, .16, "Local replica of\nchain state +\ndecision log", fs=7)
    box(ax, .03, .05, .26, .16, "IdentityRegistry\nstatus FSM, key blacklist,\nbatch revoke / quarantine", fc="#dff0df", ec=GN, fs=7)
    box(ax, .33, .05, .26, .16, "ZeroTrustAccess\ntier policy, anomaly gate,\nstrict mode, root anchoring", fc="#dff0df", ec=GN, fs=7)
    box(ax, .63, .05, .34, .16, "RevocationGovernance\nquorum q = floor(N/2)+1;\nvendor, operator, auditor vote", fc="#dff0df", ec=GN, fs=7)
    arrow(ax, (.46, .76), (.50, .76)); arrow(ax, (.70, .76), (.76, .76))
    arrow(ax, (.86, .68), (.45, .52), c=BLUE); arrow(ax, (.50, .44), (.55, .44)); arrow(ax, (.73, .44), (.78, .44))
    arrow(ax, (.60, .36), (.46, .21), c=GN); arrow(ax, (.88, .21), (.88, .36), c=GN, ls="--")
    ax.text(.895, .285, "sync (events)", fontsize=6.5, color=GN)
    fig.savefig(os.path.join(F, "fig7_iiot_arch.png"), dpi=220, bbox_inches="tight"); plt.close(fig)

def results():
    d = json.load(open(os.path.join(R, "iiot_metrics.json"))); ev = json.load(open(os.path.join(R, "evm_iiot_gas.json")))
    fig, ax = plt.subplots(1, 3, figsize=(7.4, 2.5))
    # (a) attacker acceptance by tier
    tiers = list(d["X1_tiers"]["results"]); lab = ["T0", "T1", "T2", "T3"]
    import numpy as np
    x = np.arange(4); w = .2
    for j, (atk, col) in enumerate([("stealthy mimicry", OR), ("full spoof (P,N,R=1)", "#8e24aa")]):
        a1 = [d["X1_tiers"]["results"][t]["attack_accepted_pct"][atk]["threshold_only"] for t in tiers]
        a2 = [d["X1_tiers"]["results"][t]["attack_accepted_pct"][atk]["full_policy"] for t in tiers]
        ax[0].bar(x + (j * 2) * w - 1.5 * w, a1, w, color=col, alpha=.45, label=f"{atk}, threshold")
        ax[0].bar(x + (j * 2 + 1) * w - 1.5 * w, a2, w, color=col, label=f"{atk}, full policy")
    ax[0].set_xticks(x); ax[0].set_xticklabels(lab); ax[0].set_ylabel("attacker requests accepted (%)"); ax[0].set_title("(a) by criticality tier", fontsize=8)
    ax[0].legend(fontsize=5.2, loc="upper right"); ax[0].set_ylim(0, 175)
    # (b) gate sweep
    rows = d["X2_gate_sweep"]["upset_rate_0.05"]; g = [r["gate"] for r in rows if r["gate"] < 1]
    ax[1].plot(g, [r["stealthy_blocked_pct"] for r in rows if r["gate"] < 1], "o-", color=OR, label="stealthy mimicry blocked")
    ax[1].plot(g, [r["full_spoof_blocked_pct"] for r in rows if r["gate"] < 1], "s-", color="#8e24aa", label="full spoof blocked")
    for u, ls in (("upset_rate_0.05", "--"), ("upset_rate_0.15", ":")):
        ax[1].plot(g, [r["legit_denied_pct"] for r in d["X2_gate_sweep"][u] if r["gate"] < 1], ls, color=BLUE, label=f"legit denied ({u.split('_')[-1]} upsets)")
    ax[1].set_xlabel("anomaly gate level"); ax[1].set_ylabel("%"); ax[1].set_title("(b) gate trade-off", fontsize=8); ax[1].legend(fontsize=5.2, loc="center right")
    # (c) recall
    r = ev["recall"]; k = [x_["devices"] for x_ in r]
    ax[2].plot(k, [x_["individual_total_gas"] / 1e6 for x_ in r], "o-", color=GR, label="one tx per device")
    ax[2].plot(k, [x_["batch_gas"] / 1e6 for x_ in r], "s-", color=GN, label="revokeBatch")
    ax[2].set_xscale("log"); ax[2].set_yscale("log"); ax[2].set_xlabel("devices recalled"); ax[2].set_ylabel("gas (millions)"); ax[2].set_title("(c) firmware-recall gas", fontsize=8); ax[2].legend(fontsize=6)
    for a in ax: a.tick_params(labelsize=6.5); a.xaxis.label.set_size(7); a.yaxis.label.set_size(7); a.grid(alpha=.25)
    fig.tight_layout(); fig.savefig(os.path.join(F, "fig8_iiot_results.png"), dpi=220); plt.close(fig)

if __name__ == "__main__":
    arch(); results(); print("ok")
