"""
generate_figures.py
--------------------
Produces the four figures used in the paper:
  fig1_architecture.png       - overall system architecture (schematic)
  fig2_smart_contract.png     - smart-contract module architecture (schematic)
  fig3_zero_trust_workflow.png- zero-trust request evaluation sequence (schematic)
  fig4_results.png            - real measured results from results/metrics.json
"""

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

BASE = os.path.dirname(os.path.dirname(__file__))
FIG_DIR = os.path.join(BASE, "figures")
RESULTS = os.path.join(BASE, "results", "metrics.json")
os.makedirs(FIG_DIR, exist_ok=True)

BLUE = "#1f4e79"
LBLUE = "#cfe2f3"
GREY = "#5b5b5b"
LGREY = "#eeeeee"
ORANGE = "#e07b00"


def box(ax, xy, w, h, text, fc=LBLUE, ec=BLUE, fs=9, textcolor="black"):
    b = FancyBboxPatch(xy, w, h, boxstyle="round,pad=0.02,rounding_size=0.04",
                        linewidth=1.4, edgecolor=ec, facecolor=fc)
    ax.add_patch(b)
    ax.text(xy[0] + w / 2, xy[1] + h / 2, text, ha="center", va="center",
             fontsize=fs, color=textcolor, wrap=True)
    return b


def arrow(ax, p1, p2, text=None, color=GREY, style="-|>"):
    a = FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=14,
                         linewidth=1.3, color=color)
    ax.add_patch(a)
    if text:
        mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
        ax.text(mx, my + 0.15, text, fontsize=7.5, ha="center", color=color)


# ---------------------------------------------------------------- Figure 1
def fig1_architecture():
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    ax.set_xlim(0, 12); ax.set_ylim(0, 8); ax.axis("off")

    box(ax, (0.3, 6.2), 2.6, 1.3, "IoT Device Layer\n(sensors, actuators,\ngateways, cameras)", fc="#fce5cd", ec=ORANGE)
    box(ax, (3.4, 6.2), 2.6, 1.3, "Edge / Gateway\nAgent\n(PEP: policy\nenforcement point)", fc=LBLUE)
    box(ax, (6.5, 6.2), 2.6, 1.3, "Zero Trust\nControl Plane\n(PDP: trust engine +\npolicy evaluation)", fc=LBLUE)
    box(ax, (9.6, 6.2), 2.1, 1.3, "Application /\nCloud Services\n(protected resources)", fc="#fce5cd", ec=ORANGE)

    box(ax, (2.6, 3.6), 6.8, 1.6,
        "Permissioned Blockchain (PoA)\nIdentityRegistry.sol  |  ZeroTrustAccess.sol  |  Revocation Registry",
        fc="#d9ead3", ec="#38761d", fs=10)

    box(ax, (0.3, 1.0), 3.0, 1.6, "Off-chain DID /\nCredential Store\n(IPFS / encrypted DB)", fc=LGREY, ec=GREY)
    box(ax, (3.7, 1.0), 3.2, 1.6, "Continuous Trust\nScoring Engine\n(posture, behavior,\nnetwork, reliability)", fc=LGREY, ec=GREY)
    box(ax, (7.3, 1.0), 4.4, 1.6, "Security Monitoring &\nRevocation Service\n(anomaly detection, key\ncompromise response)", fc=LGREY, ec=GREY)

    arrow(ax, (1.6, 6.2), (1.6, 5.2), "provision / mTLS")
    arrow(ax, (4.7, 6.2), (4.7, 5.2))
    arrow(ax, (7.8, 6.2), (7.8, 5.2), "verify / evaluateAccess()")
    arrow(ax, (9.6, 6.85), (9.1, 6.85), "grant / deny")
    arrow(ax, (5.0, 3.6), (2.0, 2.6), "resolve DID doc")
    arrow(ax, (5.6, 3.6), (5.3, 2.6), "trust score feed")
    arrow(ax, (7.0, 3.6), (9.0, 2.6), "revoke() / suspend()")

    ax.set_title("Fig. 1. Overall architecture of the blockchain-enabled zero trust IoT identity system",
                 fontsize=9.5, loc="left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig1_architecture.png"), dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- Figure 2
def fig2_smart_contracts():
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    ax.set_xlim(0, 12); ax.set_ylim(0, 8); ax.axis("off")

    box(ax, (0.4, 5.6), 5.2, 2.0,
        "IdentityRegistry.sol\n\n"
        "+ registerDevice(pubKey, class, attrHash, sig)\n"
        "+ revokeDevice(did, reason)\n"
        "+ suspendDevice(did)\n"
        "+ getStatus(did) -> Status\n"
        "mapping(bytes32 => DeviceRecord) devices",
        fc=LBLUE, fs=8.3)

    box(ax, (6.4, 5.6), 5.2, 2.0,
        "ZeroTrustAccess.sol\n\n"
        "+ definePolicy(resource, minTrust, classes)\n"
        "+ evaluateAccess(did, resource, trustScore,\n"
        "                  nonce, sig) -> Effect\n"
        "+ ALLOW / STEP_UP_AUTH / DENY\n"
        "mapping(bytes32 => Policy) policies",
        fc="#d9ead3", ec="#38761d", fs=8.3)

    box(ax, (2.2, 2.9), 3.4, 1.4, "RevocationRegistry\n(nested in IdentityRegistry)\nrevokedKeys, event log", fc=LGREY, ec=GREY, fs=8)
    box(ax, (6.8, 2.9), 3.6, 1.4, "TrustOracle Adapter\n(off-chain trust engine ->\nsigned trust-score attestation)", fc=LGREY, ec=GREY, fs=8)

    box(ax, (3.0, 0.4), 6.4, 1.4,
        "Events: DeviceRegistered, DeviceRevoked, AccessGranted,\nAccessDenied, PolicyUpdated  (indexed for off-chain SIEM ingestion)",
        fc="#fff2cc", ec="#bf9000", fs=8.3)

    arrow(ax, (3.0, 5.6), (3.0, 4.3))
    arrow(ax, (9.0, 5.6), (9.0, 4.3))
    arrow(ax, (2.9, 5.6), (8.6, 5.6), "onlyRegistry\nmodifier", color=BLUE)
    arrow(ax, (3.9, 2.9), (5.6, 1.8))
    arrow(ax, (8.6, 2.9), (6.9, 1.8))

    ax.set_title("Fig. 2. Smart-contract architecture (IdentityRegistry + ZeroTrustAccess)",
                 fontsize=9.5, loc="left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig2_smart_contract.png"), dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- Figure 3
def fig3_zero_trust_workflow():
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.set_xlim(0, 12); ax.set_ylim(0, 10); ax.axis("off")

    lanes = [("IoT\nDevice", 1.0), ("Gateway\n(PEP)", 4.0), ("Trust\nEngine", 7.0), ("Blockchain\n(PDP/registry)", 10.0)]
    for name, x in lanes:
        box(ax, (x - 0.9, 8.6), 1.8, 0.9, name, fc=LBLUE, fs=8)
        ax.plot([x, x], [0.4, 8.6], color=GREY, linewidth=0.8, linestyle="--")

    steps = [
        (1.0, 4.0, 8.0, "1. Signed request\n(DID, nonce, sig)"),
        (4.0, 7.0, 7.1, "2. Forward + context\n(posture, network)"),
        (7.0, 10.0, 6.2, "3. Fetch identity\nstatus & policy"),
        (10.0, 7.0, 5.3, "4. Status=ACTIVE,\npolicy params"),
        (7.0, 7.0, 4.4, "5. Compute composite\ntrust score"),
        (7.0, 10.0, 3.5, "6. evaluateAccess()\n(verify sig, nonce,\ntrust, policy)"),
        (10.0, 4.0, 2.6, "7. Effect: ALLOW /\nSTEP_UP / DENY"),
        (4.0, 1.0, 1.7, "8. Enforce decision\n+ log event"),
    ]
    for x1, x2, y, label in steps:
        arrow(ax, (x1, y), (x2, y), label, color=BLUE if x2 != x1 else GREY)

    ax.text(6.0, 0.6,
            "No implicit trust: every access request re-verifies identity, device status, and context before authorization.",
            ha="center", fontsize=8, style="italic", color=GREY)

    ax.set_title("Fig. 3. Zero Trust continuous verification workflow for an access request",
                 fontsize=9.5, loc="left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig3_zero_trust_workflow.png"), dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- Figure 4
def fig4_results():
    with open(RESULTS) as f:
        data = json.load(f)
    scaling = data["scaling_results"]
    security = data["security_detection_rates_pct"]

    n = [r["fleet_size"] for r in scaling]
    reg = [r["reg_latency_ms_mean"] for r in scaling]
    authz = [r["authz_latency_ms_mean"] for r in scaling]
    authz_tps = [r["authorization_throughput_tps"] for r in scaling]
    rss = [r["process_rss_mb"] for r in scaling]

    fig, axs = plt.subplots(2, 2, figsize=(7.4, 5.6))

    axs[0, 0].plot(n, reg, marker="o", color=BLUE, label="Registration")
    axs[0, 0].plot(n, authz, marker="s", color=ORANGE, label="Authorization")
    axs[0, 0].set_xlabel("Fleet size (devices)")
    axs[0, 0].set_ylabel("Mean latency (ms)")
    axs[0, 0].set_title("(a) Per-operation latency", fontsize=9)
    axs[0, 0].legend(fontsize=7)
    axs[0, 0].grid(alpha=0.3)

    axs[0, 1].plot(n, authz_tps, marker="^", color="#38761d")
    axs[0, 1].set_xlabel("Fleet size (devices)")
    axs[0, 1].set_ylabel("Throughput (decisions/s)")
    axs[0, 1].set_title("(b) Zero-trust authorization throughput", fontsize=9)
    axs[0, 1].grid(alpha=0.3)

    axs[1, 0].plot(n, rss, marker="d", color="#674ea7")
    axs[1, 0].set_xlabel("Fleet size (devices)")
    axs[1, 0].set_ylabel("Process RSS (MB)")
    axs[1, 0].set_title("(c) Memory footprint vs. fleet size", fontsize=9)
    axs[1, 0].grid(alpha=0.3)

    labels = ["Replay", "Forged\nsignature", "Revoked\ndevice", "Credential\nstuffing"]
    vals = [security["replay_detected"], security["forged_sig_detected"],
            security["revoked_device_blocked"], security["credential_stuffing_blocked"]]
    bars = axs[1, 1].bar(labels, vals, color=[BLUE, ORANGE, "#38761d", "#674ea7"])
    axs[1, 1].set_ylim(0, 110)
    axs[1, 1].set_ylabel("Detection rate (%)")
    axs[1, 1].set_title("(d) Attack detection rate (n=500 trials/class)", fontsize=9)
    for b, v in zip(bars, vals):
        axs[1, 1].text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontsize=7.5)
    axs[1, 1].grid(alpha=0.3, axis="y")

    fig.suptitle("Fig. 4. Main experimental results on the local PoA prototype", fontsize=10)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(os.path.join(FIG_DIR, "fig4_results.png"), dpi=300)
    plt.close(fig)


def fig5_extended():
    base = os.path.dirname(RESULTS)
    ex = json.load(open(os.path.join(base, "extra_metrics.json")))
    evm = json.load(open(os.path.join(base, "evm_metrics.json")))
    fig, axs = plt.subplots(1, 3, figsize=(7.4, 2.9))

    b = ex["E2_baselines"]["results"]
    names = ["Token\n60 s", "Token\n300 s", "CRL\n60 s", "CRL\n300 s", "Proposed"]
    keys = ["Session token (TTL 60 s)", "Session token (TTL 300 s)", "PKI + CRL (refresh 60 s)",
            "PKI + CRL (refresh 300 s)", "Proposed (continuous, per-request)"]
    vals = [b[k]["mean_requests_accepted_after_revocation"] for k in keys]
    bars = axs[0].bar(names, vals, color=[GREY, GREY, "#999999", "#999999", BLUE])
    for r, v in zip(bars, vals):
        axs[0].text(r.get_x() + r.get_width() / 2, v + 3, f"{v:.0f}", ha="center", fontsize=7)
    axs[0].set_ylabel("Requests accepted after revocation")
    axs[0].set_title("(a) Revocation exposure", fontsize=8.5)
    axs[0].tick_params(labelsize=6.5); axs[0].grid(alpha=0.3, axis="y")

    ab = ex["E3_ablation"]["results"]
    cfgs = ["Full (P,B,N,R)", "w/o posture", "w/o behaviour", "w/o network", "w/o reliability"]
    short = ["Full", "-P", "-B", "-N", "-R"]
    w = 0.38
    for i, (pop, col) in enumerate([("partial mimicry", BLUE), ("stealthy mimicry", ORANGE)]):
        v = [ab[c][pop]["auc"] for c in cfgs]
        xs = [j + (i - 0.5) * w for j in range(len(cfgs))]
        axs[1].bar(xs, v, w, label=pop, color=col)
    axs[1].set_xticks(range(len(cfgs))); axs[1].set_xticklabels(short, fontsize=7)
    axs[1].set_ylim(0.4, 1.02); axs[1].axhline(0.5, color="k", lw=0.6, ls=":")
    axs[1].set_ylabel("ROC-AUC"); axs[1].set_title("(b) Trust-signal ablation", fontsize=8.5)
    axs[1].legend(fontsize=6); axs[1].tick_params(labelsize=6.5); axs[1].grid(alpha=0.3, axis="y")

    g = evm["gas"]
    ops = [("register", "register"), ("evalAllow", "eval\nALLOW"), ("denyReplay", "deny\nreplay"),
           ("denyRevoked", "deny\nrevoked"), ("suspend", "suspend"), ("revoke", "revoke")]
    vals = [g[k]["mean"] / 1000 for k, _ in ops]
    bars = axs[2].bar([l for _, l in ops], vals, color=BLUE)
    for r, v in zip(bars, vals):
        axs[2].text(r.get_x() + r.get_width() / 2, v + 3, f"{v:.0f}", ha="center", fontsize=6.5)
    axs[2].set_ylabel("Gas (thousands)"); axs[2].set_title("(c) Measured EVM gas / call", fontsize=8.5)
    axs[2].tick_params(labelsize=5.5); axs[2].grid(alpha=0.3, axis="y")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig5_extended.png"), dpi=300)
    plt.close(fig)


def fig6_governance():
    base = os.path.dirname(RESULTS)
    gv = json.load(open(os.path.join(base, "governance_metrics.json")))["results"]
    gg = json.load(open(os.path.join(base, "evm_governance_gas.json")))
    N = [r["N"] for r in gv]
    fig, axs = plt.subplots(1, 3, figsize=(7.4, 2.5))
    for key, lab, col, mk in [("cooperative_latency_ms", "cooperative", BLUE, "o"), ("dissent_latency_ms", "max dissent (N-q)", ORANGE, "s")]:
        m = [r[key]["mean"] for r in gv]; lo = [r[key]["ci95_low"] for r in gv]; hi = [r[key]["ci95_high"] for r in gv]
        axs[0].errorbar(N, m, yerr=[[a - b for a, b in zip(m, lo)], [b - a for a, b in zip(m, hi)]], marker=mk, color=col, label=lab, capsize=2)
    axs[0].set_xlabel("Voters N"); axs[0].set_ylabel("Quorum latency (ms)"); axs[0].set_title("(a) Testbed quorum latency", fontsize=8.5)
    axs[0].legend(fontsize=6.5); axs[0].grid(alpha=0.3); axs[0].tick_params(labelsize=7)
    q = [r["quorum"] for r in gv]; d = [r["max_dissent"] for r in gv]
    axs[1].bar([x - 0.9 for x in N], q, 1.8, color=BLUE, label="quorum q")
    axs[1].bar([x + 0.9 for x in N], d, 1.8, color=ORANGE, label="tolerated dissent N-q")
    axs[1].set_xlabel("Voters N"); axs[1].set_ylabel("Voters"); axs[1].set_title("(b) Quorum vs. dissent", fontsize=8.5)
    axs[1].legend(fontsize=6.5); axs[1].grid(alpha=0.3, axis="y"); axs[1].tick_params(labelsize=7)
    axs[2].plot([r["N"] for r in gg], [r["total_gas_to_revoke"] / 1000 for r in gg], marker="d", color="#38761d")
    axs[2].set_xlabel("Voters N"); axs[2].set_ylabel("Gas (thousands)"); axs[2].set_title("(c) EVM gas for one revocation", fontsize=8.5)
    axs[2].grid(alpha=0.3); axs[2].tick_params(labelsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig6_governance.png"), dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    fig1_architecture()
    fig2_smart_contracts()
    fig3_zero_trust_workflow()
    fig4_results()
    fig5_extended()
    fig6_governance()
    print("Figures written to", FIG_DIR)
