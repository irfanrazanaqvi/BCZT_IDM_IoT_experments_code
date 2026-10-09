"""Additional revocation baselines on the same logical clock as E2:
short-lived certificates, OCSP stapling, and a centralised online PDP (with/without outage).
Pure logic simulation (no crypto): exposure depends only on validity windows."""
import json, random, statistics, sys
SEED = 20261004
N, H, REPS = 60, 600, 30

def run(kind, param, rep, pdp_outage=None, fail_open=False):
    rng = random.Random(SEED + rep)
    t_rev = [rng.uniform(100, 500) for _ in range(N)]
    phase = [rng.uniform(0, param or 1) for _ in range(N)]   # renewal phase offset
    exp = [0] * N; legit_ok = legit_tot = 0
    for t in range(H):
        for i in range(N):
            revoked = t >= t_rev[i]
            if kind in ("shortcert", "ocsp"):
                # credential last (re)issued at the latest renewal instant <= t; renewal fails once revoked
                k = int((t - phase[i]) // param) if t >= phase[i] else -1
                last = phase[i] + k * param if k >= 0 else phase[i] - param
                # renewal at 'last' succeeded iff device not yet revoked at that instant
                valid_until = last + param
                ok = (t < valid_until) and (last < t_rev[i])
            else:  # central PDP, online per request
                down = pdp_outage and pdp_outage[0] <= t < pdp_outage[1]
                if down:
                    ok = fail_open
                else:
                    ok = not revoked
            if revoked and ok: exp[i] += 1
            if not revoked:
                legit_tot += 1; legit_ok += ok
    return statistics.mean(exp), max(exp), 100 * legit_ok / legit_tot

def agg(kind, param, **kw):
    rs = [run(kind, param, r, **kw) for r in range(REPS)]
    return {"mean_exposure": round(statistics.mean(r[0] for r in rs), 1),
            "max_exposure": max(r[1] for r in rs),
            "legit_availability_pct": round(statistics.mean(r[2] for r in rs), 2)}

out = {"runs": REPS, "devices": N, "horizon_s": H, "results": {}}
for L in (60, 300):
    out["results"][f"Short-lived cert (lifetime {L} s)"] = agg("shortcert", L)
for V in (60, 300):
    out["results"][f"OCSP stapling (validity {V} s)"] = agg("ocsp", V)
out["results"]["Central PDP (online, no outage)"] = agg("pdp", None)
out["results"]["Central PDP, 60 s outage, fail-closed"] = agg("pdp", None, pdp_outage=(200, 260))
out["results"]["Central PDP, 60 s outage, fail-open"] = agg("pdp", None, pdp_outage=(200, 260), fail_open=True)
json.dump(out, open("../results/baselines2.json", "w"), indent=1)
print(json.dumps(out, indent=1))
