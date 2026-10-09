"""
blockchain.py
-------------
Minimal Proof-of-Authority (PoA) blockchain used as the execution and
storage substrate for the identity-registry and zero-trust access-control
"contracts" (see contracts.py). It mirrors, in Python, the semantics of
the Solidity contracts shipped in /contracts (block-ordered, append-only,
hash-chained transaction log with deterministic state transitions) so
that the prototype can be benchmarked without requiring outbound network
access to a public testnet or an npm registry.

This is NOT a claim that Python re-implements the EVM; it is a
discrete-event research prototype used to obtain reproducible latency /
throughput / security numbers for Sections 4-5 of the paper. The actual
production contracts (Solidity, deployable on any EVM chain or
Hyperledger Besu PoA network) are provided in /contracts and /hardhat.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Callable, List

from .crypto_utils import sha256, merkle_root


@dataclass
class Transaction:
    tx_type: str          # "REGISTER" | "REVOKE" | "POLICY" | "ACCESS"
    payload: dict
    sender_pub: str
    signature: str
    timestamp: float = field(default_factory=time.time)

    def digest(self) -> str:
        body = json.dumps(
            {"t": self.tx_type, "p": self.payload, "s": self.sender_pub},
            sort_keys=True,
        ).encode()
        return sha256(body)


@dataclass
class Block:
    index: int
    prev_hash: str
    transactions: List[Transaction]
    validator: str
    timestamp: float = field(default_factory=time.time)

    def merkle(self) -> str:
        return merkle_root([tx.digest() for tx in self.transactions]) if self.transactions else sha256(b"")

    def header(self) -> dict:
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle(),
            "validator": self.validator,
            "timestamp": self.timestamp,
        }

    def hash(self) -> str:
        return sha256(json.dumps(self.header(), sort_keys=True).encode())


class PoAChain:
    """A tiny N-validator round-robin Proof-of-Authority chain."""

    def __init__(self, validators: List[str], block_interval_s: float = 0.0,
                 on_commit: Callable[[Block], None] = None):
        self.validators = validators
        self.block_interval_s = block_interval_s  # simulated block time (0 = immediate/test mode)
        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []
        self.on_commit = on_commit
        genesis = Block(index=0, prev_hash="0" * 64, transactions=[], validator="genesis")
        self.chain.append(genesis)

    def submit(self, tx: Transaction):
        self.mempool.append(tx)

    def seal_block(self) -> Block:
        validator = self.validators[len(self.chain) % len(self.validators)]
        prev_hash = self.chain[-1].hash()
        block = Block(index=len(self.chain), prev_hash=prev_hash,
                      transactions=self.mempool, validator=validator)
        self.chain.append(block)
        self.mempool = []
        if self.on_commit:
            for tx in block.transactions:
                self.on_commit(tx)
        if self.block_interval_s:
            time.sleep(self.block_interval_s)
        return block

    def verify_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            if self.chain[i].prev_hash != self.chain[i - 1].hash():
                return False
        return True

    def height(self) -> int:
        return len(self.chain) - 1
