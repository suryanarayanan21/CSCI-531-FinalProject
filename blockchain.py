import json
import time
from typing import List, Optional, Tuple

from crypto_utils import sha256_hex
from config import BLOCKCHAIN_DIFFICULTY, RECORDS_PER_BLOCK


class Block:

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

   
    def compute_hash(self) -> str:
   
        block_data = {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "records":       self.records,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
        }
        return sha256_hex(json.dumps(block_data, sort_keys=True))

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
        block.hash = d["hash"]   
        return block

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, "
            f"records={len(self.records)}, "
            f"hash={self.hash[:12]}...)"
        )


class Blockchain:

    def __init__(self, difficulty: int = BLOCKCHAIN_DIFFICULTY):
        self.difficulty       = difficulty
        self.chain: List[Block] = []
        self.pending_records: List[dict] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
       
        genesis = Block(index=0, records=[], previous_hash="0" * 64)
        genesis = self._proof_of_work(genesis)
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    @property
    def length(self) -> int:
        return len(self.chain)


    def add_record(self, record_entry: dict) -> Block:
 
        self.pending_records.append(record_entry)
        if len(self.pending_records) >= RECORDS_PER_BLOCK:
            return self.mine_pending_records()
        return None

    def mine_pending_records(self) -> Block:
   
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

    def _proof_of_work(self, block: Block) -> Block:
        
        target = "0" * self.difficulty
        block.nonce = 0
        computed = block.compute_hash()
        while not computed.startswith(target):
            block.nonce += 1
            computed = block.compute_hash()
        block.hash = computed
        return block

    
    def is_chain_valid(self) -> Tuple[bool, Optional[int]]:
  
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

        
            recomputed = current.compute_hash()
            if current.hash != recomputed:
                return False, i

            if current.previous_hash != previous.hash:
                return False, i

        return True, None

    
    def get_all_entries(self) -> List[dict]:
        entries = []
        for block in self.chain[1:]:   # skip genesis
            for rec in block.records:
                entries.append({**rec, "_block_index": block.index, "_block_hash": block.hash})
        return entries

    def get_entries_for_patient(self, patient_id: str) -> List[dict]:
        return [e for e in self.get_all_entries() if e.get("patient_id") == patient_id]

    
    def to_dict(self) -> List[dict]:
        return [block.to_dict() for block in self.chain]

    @classmethod
    def from_dict(cls, chain_data: List[dict], difficulty: int = BLOCKCHAIN_DIFFICULTY) -> "Blockchain":
    
        bc = cls.__new__(cls)
        bc.difficulty       = difficulty
        bc.pending_records  = []
        bc.chain            = [Block.from_dict(d) for d in chain_data]
        return bc

    
    def replace_chain(self, new_chain_data: List[dict]) -> bool:

        candidate = Blockchain.from_dict(new_chain_data, self.difficulty)
        valid, _ = candidate.is_chain_valid()
        if valid and candidate.length > self.length:
            self.chain = candidate.chain
            return True
        return False

    def __repr__(self) -> str:
        return f"Blockchain(blocks={self.length}, difficulty={self.difficulty})"
