"""
contracts.py
------------
Python state machines that mirror, function-for-function, the on-chain
logic of contracts/IdentityRegistry.sol and contracts/ZeroTrustAccess.sol.
Each public method below corresponds 1:1 to a Solidity function of the
same name, so results measured here are representative of the state
transition logic that actually executes on-chain (excluding EVM gas
metering, which is reported separately from real `solc`/Hardhat gas
estimates documented in Table 2 and Section 4.1).
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .crypto_utils import verify, derive_did, sha256


class DeviceStatus(Enum):
    UNKNOWN = 0
    ACTIVE = 1
    SUSPENDED = 2
    REVOKED = 3


@dataclass
class DeviceRecord:
    did: str
    pub_hex: str
    owner: str
    device_class: str
    status: DeviceStatus = DeviceStatus.ACTIVE
    trust_score: float = 0.7
    registered_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    attribute_hash: str = ""
    nonce: int = 0


class IdentityRegistryContract:
    """Equivalent of IdentityRegistry.sol: DID-based device identity registry."""

    def __init__(self):
        self.devices: Dict[str, DeviceRecord] = {}   # did -> record
        self.revoked_pubkeys: set = set()
        self.event_log: List[dict] = []

    def register_device(self, pub_hex: str, owner: str, device_class: str,
                         attributes: dict, signature: bytes, message: bytes) -> str:
        """require(): signature must be valid over the registration message."""
        if not verify(pub_hex, message, signature):
            raise PermissionError("InvalidSignature: registration rejected")
        did = derive_did(pub_hex)
        if did in self.devices:
            raise ValueError("DeviceAlreadyRegistered")
        attr_hash = sha256(str(sorted(attributes.items())).encode())
        record = DeviceRecord(did=did, pub_hex=pub_hex, owner=owner,
                               device_class=device_class, attribute_hash=attr_hash)
        self.devices[did] = record
        self.event_log.append({"event": "DeviceRegistered", "did": did, "ts": time.time()})
        return did

    def revoke_device(self, did: str, reason: str):
        if did not in self.devices:
            raise KeyError("UnknownDevice")
        self.devices[did].status = DeviceStatus.REVOKED
        self.revoked_pubkeys.add(self.devices[did].pub_hex)
        self.event_log.append({"event": "DeviceRevoked", "did": did, "reason": reason, "ts": time.time()})

    def suspend_device(self, did: str):
        if did not in self.devices:
            raise KeyError("UnknownDevice")
        self.devices[did].status = DeviceStatus.SUSPENDED

    def get_status(self, did: str) -> DeviceStatus:
        return self.devices[did].status if did in self.devices else DeviceStatus.UNKNOWN

    def touch(self, did: str):
        if did in self.devices:
            self.devices[did].last_seen = time.time()


class Effect(Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP_AUTH"
    DENY = "DENY"


@dataclass
class Policy:
    resource: str
    min_trust: float
    allowed_classes: List[str]
    max_idle_s: float = 300.0
    max_anomaly: float = 1.0   # hard gate on the behavioural anomaly signal
    strict: bool = False       # safety-critical: borderline scores are denied, not stepped up
    margin: float = 0.15


class ZeroTrustAccessContract:
    """Equivalent of ZeroTrustAccess.sol: continuous, attribute+trust based
    authorization evaluated on every request (never implicitly trusted)."""

    def __init__(self, registry: IdentityRegistryContract):
        self.registry = registry
        self.policies: Dict[str, Policy] = {}
        self.seen_nonces: set = set()
        self.access_log: List[dict] = []

    def define_policy(self, resource: str, min_trust: float,
                       allowed_classes: List[str], max_idle_s: float = 300.0,
                       max_anomaly: float = 1.0, strict: bool = False, margin: float = 0.15):
        self.policies[resource] = Policy(resource, min_trust, allowed_classes, max_idle_s,
                                         max_anomaly, strict, margin)

    def evaluate_access(self, did: str, resource: str, trust_score: float,
                         nonce: str, signature: bytes, message: bytes,
                         anomaly: float = 0.0) -> Effect:
        """Zero Trust rule: verify -> identify -> contextualize -> authorize,
        on every single request; no standing/implicit trust is granted."""
        record = self.registry.devices.get(did)
        if record is None:
            self._log(did, resource, Effect.DENY, "unknown_device")
            return Effect.DENY

        if record.status != DeviceStatus.ACTIVE:
            self._log(did, resource, Effect.DENY, "device_not_active")
            return Effect.DENY

        if not verify(record.pub_hex, message, signature):
            self._log(did, resource, Effect.DENY, "bad_signature")
            return Effect.DENY

        replay_key = f"{did}:{nonce}"
        if replay_key in self.seen_nonces:
            self._log(did, resource, Effect.DENY, "replay_detected")
            return Effect.DENY
        self.seen_nonces.add(replay_key)

        policy = self.policies.get(resource)
        if policy is None:
            self._log(did, resource, Effect.DENY, "no_policy")
            return Effect.DENY

        if record.device_class not in policy.allowed_classes:
            self._log(did, resource, Effect.DENY, "class_not_allowed")
            return Effect.DENY

        idle = time.time() - record.last_seen
        if anomaly > policy.max_anomaly:
            self._log(did, resource, Effect.DENY, "anomaly_gate")
            return Effect.DENY
        if trust_score < policy.min_trust:
            self._log(did, resource, Effect.DENY, "trust_below_threshold")
            return Effect.DENY
        elif trust_score < policy.min_trust + policy.margin or idle > policy.max_idle_s:
            if policy.strict:
                self._log(did, resource, Effect.DENY, "strict_borderline")
                return Effect.DENY
            self.registry.touch(did)
            self._log(did, resource, Effect.STEP_UP, "borderline_trust_or_idle")
            return Effect.STEP_UP

        self.registry.touch(did)
        self._log(did, resource, Effect.ALLOW, "ok")
        return Effect.ALLOW

    def _log(self, did, resource, effect, reason):
        self.access_log.append({
            "did": did, "resource": resource, "effect": effect.value,
            "reason": reason, "ts": time.time(),
        })
