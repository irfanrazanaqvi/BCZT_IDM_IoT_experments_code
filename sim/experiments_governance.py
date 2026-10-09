"""
experiments_governance.py
-------------------------
Decentralized revocation-governance experiments (Section 7.6 of the paper).

For voter-group sizes N in {5,7,9,11,15,21} and quorum q = floor(N/2)+1:
  G1  cooperative group: latency to reach quorum
  G2  maximal tolerated dissent (N-q voters vote DENY): latency and outcome
  G3  forced-revocation attempt: only q-1 voters APPROVE (colluding minority
      cannot reach quorum) -> the revocation must NOT be executed
Every vote is a real Ed25519 signature that is verified before counting.

Run:  python3 -m sim.experiments_governance  ->  results/governance_metrics.json
"""
import json, os, random, statistics

from scipy import stats as sps

from .governance import DecentralizedVoterGroup

SIZES = [5, 7, 9, 11, 15, 21]
TRIALS = 200
SEED = 20261004
OUT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results", "governance_metrics.json")


def ci(xs):
    m = statistics.mean(xs); sd = statistics.stdev(xs); h = sps.t.ppf(0.975, len(xs) - 1) * sd / len(xs) ** 0.5
    return {"mean": m, "sd": sd, "ci95_low": m - h, "ci95_high": m + h}


def main():
    random.seed(SEED)
    rows = []
    for n in SIZES:
        q = n // 2 + 1
        coop, dis = [], []
        dis_ok = forced_blocked = 0
        for t in range(TRIALS):
            g = DecentralizedVoterGroup(n, q, 0.0)
            o = g.cast_votes_and_finalize(g.propose(f"did:iot:t{t}", "key_rotation")); coop.append(o["quorum_latency_ms"])
            g = DecentralizedVoterGroup(n, q, (n - q) / n)
            o = g.cast_votes_and_finalize(g.propose(f"did:iot:t{t}", "key_rotation")); dis.append(o["quorum_latency_ms"]); dis_ok += o["approved"]
            g = DecentralizedVoterGroup(n, q, (n - q + 1) / n)          # only q-1 approvals
            o = g.cast_votes_and_finalize(g.propose(f"did:iot:t{t}", "malicious")); forced_blocked += (not o["approved"])
        rows.append({"N": n, "quorum": q, "max_dissent": n - q, "trials": TRIALS,
                     "cooperative_latency_ms": ci(coop), "dissent_latency_ms": ci(dis),
                     "correct_approval_under_max_dissent_pct": 100.0 * dis_ok / TRIALS,
                     "forced_revocation_blocked_pct": 100.0 * forced_blocked / TRIALS})
        print(n, q, round(statistics.mean(coop), 3), round(statistics.mean(dis), 3), dis_ok, forced_blocked)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({"seed": SEED, "results": rows}, open(OUT, "w"), indent=2)


if __name__ == "__main__":
    main()
