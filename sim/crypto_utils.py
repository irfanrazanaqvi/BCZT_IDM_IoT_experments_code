"""
crypto_utils.py
----------------
Real cryptographic primitives used by the simulator (not mocked):
- Ed25519 keypair generation, signing and verification (via `cryptography`)
- SHA-256 hashing and a simple Merkle root helper
- DID-style identifier derivation (did:iot:<sha256(pubkey)[:32]>)

These primitives back every "on-chain" identity and access-control
operation performed by contracts.py, so all latency numbers produced by
benchmark.py reflect genuine cryptographic work, not sleep() placeholders.
"""

import hashlib
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaves):
    """Compute a simple binary Merkle root over a list of hex-string leaves."""
    if not leaves:
        return sha256(b"")
    level = [bytes.fromhex(h) if len(h) == 64 else hashlib.sha256(h.encode()).digest() for h in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


@dataclass
class KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def pub_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def pub_hex(self) -> str:
        return self.pub_bytes().hex()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


def generate_keypair() -> KeyPair:
    sk = Ed25519PrivateKey.generate()
    return KeyPair(private_key=sk, public_key=sk.public_key())


def verify(pub_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pk.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def derive_did(pub_hex: str) -> str:
    """did:iot:<first 32 hex chars of sha256(pubkey)>"""
    return f"did:iot:{sha256(bytes.fromhex(pub_hex))[:32]}"


def now_ms() -> float:
    return time.perf_counter() * 1000.0
