"""
benchmark.py
------------
Runs the experiments reported in Section 5 of the paper:

  5.2 Authentication performance      -> registration + signature-verify latency
  5.3 Authorization performance       -> zero-trust policy evaluation latency
  5.4 Throughput & resource use       -> tx/s and process RSS memory vs. fleet size
  5.5 Security evaluation             -> detection rate for 4 attack classes

All numbers are measured on the actual Python state machines in
contracts.py / trust_engine.py running on this host; they are reported
as prototype/testbed results (Section 4.1, Table 2), not as figures for
a specific commercial chain. Run with:

    python3 -m sim.benchmark

Output: results/metrics.json (+ printed summary table).
"""

import json
import os
import platform
import statistics
import time

import psutil

from .blockchain import PoAChain, Transaction
from .contracts import IdentityRegistryContract, ZeroTrustAccessContract, Effect
from .crypto_utils import now_ms
from .iot_device import IoTDevice, AdversarialDevice
from .trust_engine import TrustEngine

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")
FLEET_SIZES = [50, 100, 200, 400, 800, 1600]
SECURITY_TRIALS = 500


def build_system():
    registry = IdentityRegistryContract()
    zt = ZeroTrustAccessContract(registry)
    zt.define_policy(resource="telemetry.write", min_trust=0.55,
                      allowed_classes=["sensor", "actuator", "gateway", "camera", "controller"])
    zt.define_policy(resource="firmware.update", min_trust=0.80,
                      allowed_classes=["gateway", "controller"])
    trust_engine = TrustEngine()
    chain = PoAChain(validators=["validator-a", "validator-b", "validator-c"])
    return registry, zt, trust_engine, chain


def run_scaling_experiment():
    results = []
    for n in FLEET_SIZES:
        registry, zt, trust_engine, chain = build_system()
        devices = [IoTDevice() for _ in range(n)]

        # ---- registration / "authentication of enrollment" latency ----
        reg_latencies = []
        t_batch_start = now_ms()
        for d in devices:
            t0 = now_ms()
            msg = d.registration_message()
            sig = d.sign(msg)
            did = registry.register_device(d.pub_hex, d.owner, d.device_class,
                                            d.attributes, sig, msg)
            tx = Transaction(tx_type="REGISTER", payload={"did": did}, sender_pub=d.pub_hex,
                              signature=sig.hex())
            chain.submit(tx)
            reg_latencies.append(now_ms() - t0)
        chain.seal_block()
        t_batch_end = now_ms()
        registration_throughput = n / ((t_batch_end - t_batch_start) / 1000.0)

        # ---- authorization (zero trust decision) latency ----
        authz_latencies = []
        t_authz_start = now_ms()
        for d in devices:
            nonce = d.next_nonce()
            msg = d.access_message("telemetry.write", nonce)
            sig = d.sign(msg)
            posture, anomaly, net = d.posture_signal(), d.anomaly_signal(), d.network_signal()
            t0 = now_ms()
            score = trust_engine.score(d.did, posture, anomaly, net)
            effect = zt.evaluate_access(d.did, "telemetry.write", score, nonce, sig, msg)
            authz_latencies.append(now_ms() - t0)
        t_authz_end = now_ms()
        authz_throughput = n / ((t_authz_end - t_authz_start) / 1000.0)

        mem_mb = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

        results.append({
            "fleet_size": n,
            "reg_latency_ms_mean": statistics.mean(reg_latencies),
            "reg_latency_ms_p95": _p95(reg_latencies),
            "authz_latency_ms_mean": statistics.mean(authz_latencies),
            "authz_latency_ms_p95": _p95(authz_latencies),
            "registration_throughput_tps": registration_throughput,
            "authorization_throughput_tps": authz_throughput,
            "process_rss_mb": mem_mb,
            "chain_height": chain.height(),
            "chain_valid": chain.verify_chain(),
        })
        print(f"[scaling] n={n:5d}  reg={statistics.mean(reg_latencies):.3f}ms  "
              f"authz={statistics.mean(authz_latencies):.3f}ms  "
              f"authz_tps={authz_throughput:.1f}  rss={mem_mb:.1f}MB")
    return results


def run_security_experiment():
    registry, zt, trust_engine, chain = build_system()

    legit_devices = [IoTDevice() for _ in range(200)]
    for d in legit_devices:
        msg = d.registration_message()
        sig = d.sign(msg)
        registry.register_device(d.pub_hex, d.owner, d.device_class, d.attributes, sig, msg)

    revoked = legit_devices[:20]
    for d in revoked:
        registry.revoke_device(d.did, reason="rotation_test")

    outcomes = {"replay_detected": 0, "forged_sig_detected": 0,
                "revoked_device_blocked": 0, "credential_stuffing_blocked": 0}

    # 1) Replay attack: resubmit a previously valid (message, signature) pair
    victim = legit_devices[30]
    nonce = victim.next_nonce()
    msg = victim.access_message("telemetry.write", nonce)
    sig = victim.sign(msg)
    score = trust_engine.score(victim.did, *_(victim), )
    zt.evaluate_access(victim.did, "telemetry.write", score, nonce, sig, msg)  # legit first use
    for _t in range(SECURITY_TRIALS):
        r = zt.evaluate_access(victim.did, "telemetry.write", score, nonce, sig, msg)  # replay
        if r == Effect.DENY:
            outcomes["replay_detected"] += 1

    # 2) Forged signature (impersonation with unrelated key)
    for _t in range(SECURITY_TRIALS):
        target = legit_devices[_t % len(legit_devices)]
        atk = AdversarialDevice(owner="attacker")
        n2 = f"forge-{_t}"
        msg2 = target.access_message("telemetry.write", n2)
        _msg_unused, forged_sig = atk.forged_signature("telemetry.write", n2)
        r = zt.evaluate_access(target.did, "telemetry.write", 0.9, n2, forged_sig, msg2)
        if r == Effect.DENY:
            outcomes["forged_sig_detected"] += 1

    # 3) Revoked device reuse
    for _t in range(SECURITY_TRIALS):
        d = revoked[_t % len(revoked)]
        n3 = d.next_nonce()
        msg3 = d.access_message("telemetry.write", n3)
        sig3 = d.sign(msg3)
        r = zt.evaluate_access(d.did, "telemetry.write", 0.9, n3, sig3, msg3)
        if r == Effect.DENY:
            outcomes["revoked_device_blocked"] += 1

    # 4) Credential stuffing: unregistered / never-seen DIDs
    for _t in range(SECURITY_TRIALS):
        ghost = IoTDevice()
        n4 = ghost.next_nonce()
        msg4 = ghost.access_message("telemetry.write", n4)
        sig4 = ghost.sign(msg4)
        r = zt.evaluate_access(ghost.did, "telemetry.write", 0.9, n4, sig4, msg4)
        if r == Effect.DENY:
            outcomes["credential_stuffing_blocked"] += 1

    detection_rates = {k: 100.0 * v / SECURITY_TRIALS for k, v in outcomes.items()}
    return detection_rates


def _(device):
    return device.posture_signal(), device.anomaly_signal(), device.network_signal()


def _p95(values):
    s = sorted(values)
    idx = max(0, int(round(0.95 * (len(s) - 1))))
    return s[idx]


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("== Running scaling experiment (5.2-5.4) ==")
    scaling = run_scaling_experiment()
    print("\n== Running security experiment (5.5) ==")
    security = run_security_experiment()
    for k, v in security.items():
        print(f"  {k}: {v:.1f}%")

    out = {
        "host": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        },
        "scaling_results": scaling,
        "security_detection_rates_pct": security,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(os.path.join(RESULTS_DIR, "metrics.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved results to {os.path.join(RESULTS_DIR, 'metrics.json')}")


if __name__ == "__main__":
    main()
