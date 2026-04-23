"""
blockchain.py
-------------
Core blockchain data structures for the EHR Audit System.

Design
------
  Block
    index         : position in the chain
    timestamp     : Unix timestamp at mining time
    records       : list of encrypted audit record dicts
    previous_hash : SHA-256 of the previous block (chains blocks together)
    nonce         : PoW counter
    hash          : SHA-256 of all the above fields

  Blockchain
    chain           : ordered list of Block objects
    pending_records : buffer of records waiting to be mined into a block
    difficulty      : number of leading '0' chars required in a valid hash (PoW)

Security properties
-------------------
  Immutability  – changing any field in any block invalidates its hash, which
                  cascades to invalidate every subsequent block's previous_hash.
                  is_chain_valid() detects this in O(n).

  Decentralization – each audit node maintains its own full copy of this chain.
                  Longest-chain consensus (in node_sync) means no single node
                  controls the ledger.
"""

import json
import time
from typing import List, Optional, Tuple

from crypto_utils import sha256_hex
from config import BLOCKCHAIN_DIFFICULTY, RECORDS_PER_BLOCK


# ── Block ────────────────────────────────────────────────────────────────────

class Block:
    """A single block in the blockchain."""

    def __init__(
        self,
        index: int,
        records: List[dict],
        previous_hash: str,
        nonce: int = 0,
        timestamp: Optional[float] = None,
    ):
        self.index         = index
        self.timestamp     = timestamp if timestamp is not None else time.time()
        self.records       = records          # list of {'encrypted': ..., 'metadata': ...}
        self.previous_hash = previous_hash
        self.nonce         = nonce
        self.hash          = self.compute_hash()

    # ── Hashing ──────────────────────────────────────────────────────────────

    def compute_hash(self) -> str:
        """
        Deterministic SHA-256 over all block fields.

        'records' contains only encrypted blobs, so the hash commits to
        ciphertext — the plaintext audit data is never exposed at this layer.
        """
        block_data = {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "records":       self.records,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
        }
        return sha256_hex(json.dumps(block_data, sort_keys=True))

    # ── Serialization ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "records":       self.records,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "hash":          self.hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        block = cls(
            index         = d["index"],
            records       = d["records"],
            previous_hash = d["previous_hash"],
            nonce         = d["nonce"],
            timestamp     = d["timestamp"],
        )
        block.hash = d["hash"]   # restore persisted hash without re-mining
        return block

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, "
            f"records={len(self.records)}, "
            f"hash={self.hash[:12]}...)"
        )


# ── Blockchain ────────────────────────────────────────────────────────────────

class Blockchain:
    """
    An append-only, hash-linked blockchain with proof-of-work.

    Each audit node maintains one instance of this class in memory.
    State is serialised to / from JSON for peer synchronisation.
    """

    def __init__(self, difficulty: int = BLOCKCHAIN_DIFFICULTY):
        self.difficulty       = difficulty
        self.chain: List[Block] = []
        self.pending_records: List[dict] = []
        self._create_genesis_block()

    # ── Genesis ──────────────────────────────────────────────────────────────

    def _create_genesis_block(self):
        """
        The genesis block has no previous hash (all zeros).
        It contains no records and is mined at initialisation.
        """
        genesis = Block(index=0, records=[], previous_hash="0" * 64)
        genesis = self._proof_of_work(genesis)
        self.chain.append(genesis)

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    @property
    def length(self) -> int:
        return len(self.chain)

    # ── Record Management ────────────────────────────────────────────────────

    def add_record(self, record_entry: dict) -> Block:
        """
        Append *record_entry* to the pending buffer and mine if threshold reached.

        *record_entry* format::

            {
              "encrypted_record": "<base64 AES-256-CBC ciphertext>",
              "patient_id":       "patient_3",          # unencrypted, for indexing
              "event_id":         "<uuid>",              # for deduplication
              "submitter":        "audit_node_1",
              "signature":        "<base64 RSA sig>",
            }

        Only the 'encrypted_record' blob is ever stored on-chain;
        'patient_id' is kept in plaintext metadata for query routing but
        the actual record contents remain ciphertext.
        """
        self.pending_records.append(record_entry)
        if len(self.pending_records) >= RECORDS_PER_BLOCK:
            return self.mine_pending_records()
        return None

    def mine_pending_records(self) -> Block:
        """
        Bundle all pending records into a new block and mine it.

        Proof-of-work: increment nonce until hash starts with
        `self.difficulty` leading zeros.
        """
        if not self.pending_records:
            raise ValueError("No pending records to mine.")

        new_block = Block(
            index         = self.length,
            records       = list(self.pending_records),
            previous_hash = self.last_block.hash,
        )
        new_block = self._proof_of_work(new_block)
        self.chain.append(new_block)
        self.pending_records.clear()
        return new_block

    # ── Proof of Work ────────────────────────────────────────────────────────

    def _proof_of_work(self, block: Block) -> Block:
        """
        Increment block.nonce until block.compute_hash() has the required
        number of leading zeros.  Sets block.hash on success.
        """
        target = "0" * self.difficulty
        block.nonce = 0
        computed = block.compute_hash()
        while not computed.startswith(target):
            block.nonce += 1
            computed = block.compute_hash()
        block.hash = computed
        return block

    # ── Validation ───────────────────────────────────────────────────────────

    def is_chain_valid(self) -> Tuple[bool, Optional[int]]:
        """
        Walk the entire chain and verify:
          1. Each block's stored hash matches its recomputed hash.
          2. Each block's previous_hash matches the actual hash of the block before it.

        Returns (True, None) if valid.
        Returns (False, tampered_block_index) on the first violation found.

        This is the core immutability-detection mechanism — any post-hoc
        modification of a block will be caught here.
        """
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            # Check 1: block's own hash is still valid
            recomputed = current.compute_hash()
            if current.hash != recomputed:
                return False, i

            # Check 2: chain linkage is intact
            if current.previous_hash != previous.hash:
                return False, i

        return True, None

    # ── Query Helpers ─────────────────────────────────────────────────────────

    def get_all_entries(self) -> List[dict]:
        """Return every record entry from every non-genesis block."""
        entries = []
        for block in self.chain[1:]:   # skip genesis
            for rec in block.records:
                entries.append({**rec, "_block_index": block.index, "_block_hash": block.hash})
        return entries

    def get_entries_for_patient(self, patient_id: str) -> List[dict]:
        """Return all entries whose plaintext 'patient_id' metadata matches."""
        return [e for e in self.get_all_entries() if e.get("patient_id") == patient_id]

    # ── Serialization / Consensus ─────────────────────────────────────────────

    def to_dict(self) -> List[dict]:
        """Serialise the entire chain to a JSON-safe list of block dicts."""
        return [block.to_dict() for block in self.chain]

    @classmethod
    def from_dict(cls, chain_data: List[dict], difficulty: int = BLOCKCHAIN_DIFFICULTY) -> "Blockchain":
        """
        Reconstruct a Blockchain from a serialised chain list.
        Used when a peer receives a new chain during consensus.
        """
        bc = cls.__new__(cls)
        bc.difficulty       = difficulty
        bc.pending_records  = []
        bc.chain            = [Block.from_dict(d) for d in chain_data]
        return bc

    # ── Longest-chain Consensus ───────────────────────────────────────────────

    def replace_chain(self, new_chain_data: List[dict]) -> bool:
        """
        Replace this node's chain with *new_chain_data* if it is:
          a) Longer than the current chain, AND
          b) Cryptographically valid.

        Returns True if the chain was replaced, False otherwise.
        This implements Nakamoto's longest-chain consensus rule.
        """
        candidate = Blockchain.from_dict(new_chain_data, self.difficulty)
        valid, _ = candidate.is_chain_valid()
        if valid and candidate.length > self.length:
            self.chain = candidate.chain
            return True
        return False

    def __repr__(self) -> str:
        return f"Blockchain(blocks={self.length}, difficulty={self.difficulty})"
