"""
trust_engine.py
----------------
Computes a continuous, per-request composite trust score in [0, 1] from
four context signals, following common zero-trust device-trust models
(e.g., posture, behavioral, network, and historical-reliability signals
as surveyed in Azad et al. 2024 and Nahar et al. 2024 - see references.bib).

score = w1*posture + w2*(1-anomaly) + w3*network_ctx + w4*reliability
"""

import random
from dataclasses import dataclass


@dataclass
class TrustWeights:
    posture: float = 0.30
    behavior: float = 0.30
    network: float = 0.20
    reliability: float = 0.20


class TrustEngine:
    def __init__(self, weights: TrustWeights = TrustWeights()):
        self.w = weights
        self.history = {}  # did -> list of past scores

    def score(self, did: str, posture: float, anomaly: float,
              network_ctx: float, adversarial: bool = False) -> float:
        reliability = self._reliability(did)
        raw = (self.w.posture * posture
               + self.w.behavior * (1 - anomaly)
               + self.w.network * network_ctx
               + self.w.reliability * reliability)
        if adversarial:
            # adversarial devices attempt to spoof posture/network signals
            raw = min(raw + random.uniform(0.0, 0.05), 1.0)
        raw = max(0.0, min(1.0, raw))
        self.history.setdefault(did, []).append(raw)
        return raw

    def _reliability(self, did: str) -> float:
        hist = self.history.get(did, [])
        if not hist:
            return 0.6  # neutral prior for a newly seen device
        return sum(hist[-10:]) / len(hist[-10:])
