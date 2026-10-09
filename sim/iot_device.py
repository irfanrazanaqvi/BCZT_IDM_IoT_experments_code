"""
iot_device.py
-------------
Simulates constrained IoT devices that (a) provision a DID identity,
(b) sign registration/access-request messages with Ed25519, and
(c) can behave adversarially (replay, forged signature, revoked-device
reuse, credential stuffing) for the security evaluation in Section 5.5.
"""

import json
import os
import random
import uuid

from .crypto_utils import generate_keypair, derive_did


DEVICE_CLASSES = ["sensor", "actuator", "gateway", "camera", "controller"]


class IoTDevice:
    def __init__(self, owner: str = "org:factory-01", device_class: str = None):
        self.keypair = generate_keypair()
        self.pub_hex = self.keypair.pub_hex()
        self.did = derive_did(self.pub_hex)
        self.owner = owner
        self.device_class = device_class or random.choice(DEVICE_CLASSES)
        self.attributes = {
            "fw_version": f"{random.randint(1,4)}.{random.randint(0,9)}",
            "vendor": random.choice(["Acme", "Nimbus", "Vertex", "Halo"]),
            "location": random.choice(["floor-1", "floor-2", "yard", "cold-storage"]),
        }
        self.nonce_counter = 0

    def registration_message(self) -> bytes:
        payload = {"pub": self.pub_hex, "owner": self.owner,
                   "class": self.device_class, "attrs": self.attributes}
        return json.dumps(payload, sort_keys=True).encode()

    def sign(self, message: bytes) -> bytes:
        return self.keypair.sign(message)

    def next_nonce(self) -> str:
        self.nonce_counter += 1
        return f"{self.did[:16]}-{self.nonce_counter}"

    def access_message(self, resource: str, nonce: str) -> bytes:
        payload = {"did": self.did, "resource": resource, "nonce": nonce}
        return json.dumps(payload, sort_keys=True).encode()

    # ---- context signal generators (legitimate device) ----
    def posture_signal(self) -> float:
        return random.uniform(0.75, 1.0)

    def anomaly_signal(self) -> float:
        return random.uniform(0.0, 0.15)

    def network_signal(self) -> float:
        return random.uniform(0.7, 1.0)


class AdversarialDevice(IoTDevice):
    """Wraps attack behaviors used by the security-evaluation harness."""

    def forged_signature(self, resource: str, nonce: str):
        """Sign with an unrelated key to simulate a forged/impersonation attempt."""
        rogue = generate_keypair()
        message = self.access_message(resource, nonce)
        return message, rogue.sign(message)

    def replay_previous(self, message: bytes, signature: bytes):
        return message, signature  # simply resubmit an old valid (message, sig) pair

    def posture_signal(self) -> float:
        return random.uniform(0.2, 0.5)

    def anomaly_signal(self) -> float:
        return random.uniform(0.5, 0.9)

    def network_signal(self) -> float:
        return random.uniform(0.1, 0.4)
