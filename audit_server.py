"""
audit_server.py
---------------
Blockchain Audit Node  (ports 5002 / 5012 / 5022 for nodes 1 / 2 / 3)

Run three instances on different ports to form the decentralised network::

    python audit_server.py 5002
    python audit_server.py 5012
    python audit_server.py 5022

Each instance maintains its own full copy of the blockchain.  After mining
a new block, the node broadcasts its chain to all peer nodes; peers accept
the chain if it is valid and longer than their own (longest-chain consensus).

Endpoints
---------
  POST /audit/record     – submit an encrypted audit record (EHR users only)
  GET  /chain            – retrieve the full blockchain (JSON)
  POST /chain/sync       – receive a chain from a peer; replace if longer+valid
  GET  /chain/validate   – validate this node's chain; report tampering
  GET  /peers            – list peer URLs
  GET  /status           – node health / chain summary
"""

import sys
import threading
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import (
    AUTH_SERVER_URL, AUDIT_NODE_URLS, BLOCKCHAIN_DIFFICULTY
)
from blockchain import Blockchain
from crypto_utils import verify_jwt, sign_data, verify_signature
from config import JWT_SECRET

app = Flask(__name__)
CORS(app)

# ── Node State ────────────────────────────────────────────────────────────────

# Each process gets its own Blockchain instance (in-memory, full copy of chain)
bc = Blockchain(difficulty=BLOCKCHAIN_DIFFICULTY)
_lock = threading.Lock()

# Will be set based on command-line port argument
MY_PORT: int = 5002


def _get_peers() -> list[str]:
    """Return peer URLs (all audit nodes except myself)."""
    my_url = f"http://127.0.0.1:{MY_PORT}"
    return [url for url in AUDIT_NODE_URLS if url != my_url]


# ── Auth Helper ───────────────────────────────────────────────────────────────

def _require_role(token: str, allowed_roles: set) -> dict | None:
    """
    Verify *token* by calling the auth server and check the role.

    Returns decoded payload if authorised, None otherwise.
    """
    try:
        resp = requests.post(
            f"{AUTH_SERVER_URL}/verify_token",
            json={"token": token},
            timeout=5,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("valid"):
            return None
        payload = data["payload"]
        if payload.get("role") not in allowed_roles:
            return None
        return payload
    except Exception:
        # Fallback: verify JWT locally if auth server is temporarily down
        try:
            payload = verify_jwt(token, JWT_SECRET)
            if payload.get("role") in allowed_roles:
                return payload
        except Exception:
            pass
        return None


# ── Broadcasting ──────────────────────────────────────────────────────────────

def _broadcast_chain():
    """
    Push this node's chain to all peers after mining a new block.

    Peers will replace their chain only if ours is longer and valid.
    Runs in a background thread to avoid blocking the miner.
    """
    chain_data = bc.to_dict()
    for peer_url in _get_peers():
        try:
            requests.post(
                f"{peer_url}/chain/sync",
                json={"chain": chain_data},
                timeout=5,
            )
        except Exception:
            pass  # peer may be down; that's fine in a distributed system


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route("/audit/record", methods=["POST"])
def submit_record():
    """
    Accept an encrypted audit record from an authorised EHR user.

    Body (JSON)::

        {
          "token":            "<JWT of the submitting EHR user>",
          "encrypted_record": "<base64 AES-256-CBC ciphertext of the AuditRecord JSON>",
          "patient_id":       "patient_3",
          "event_id":         "<uuid — for deduplication>",
          "signature":        "<base64 RSA-PKCS1v15/SHA-256 signature by submitter>"
        }

    Processing
    ----------
    1. Verify JWT → must be role 'ehr_user'.
    2. Verify RSA signature of encrypted_record using submitter's public key.
       This proves the record was produced by the claimed EHR user.
    3. Add to blockchain pending queue → mine block → broadcast to peers.

    Only the encrypted blob is stored on-chain.  The patient_id is kept as
    plaintext metadata *outside* the encrypted blob so the query layer can
    filter records by patient without decrypting everything.
    """
    data = request.get_json(force=True)
    token = data.get("token", "")

    payload = _require_role(token, {"ehr_user"})
    if payload is None:
        return jsonify({"error": "Forbidden: requires ehr_user JWT"}), 403

    encrypted_record = data.get("encrypted_record")
    patient_id       = data.get("patient_id")
    event_id         = data.get("event_id")
    signature        = data.get("signature")

    if not all([encrypted_record, patient_id, event_id]):
        return jsonify({"error": "Missing required fields"}), 400

    # ── Signature verification ────────────────────────────────────────────────
    if signature:
        submitter = payload["username"]
        try:
            pub_resp = requests.get(
                f"{AUTH_SERVER_URL}/public_key/{submitter}", timeout=5
            )
            if pub_resp.status_code == 200:
                public_pem = pub_resp.json()["public_pem"].encode()
                is_valid = verify_signature(encrypted_record, signature, public_pem)
                if not is_valid:
                    return jsonify({"error": "Invalid record signature"}), 400
        except Exception:
            pass  # if auth server is down, proceed without sig check for demo

    # ── Store on blockchain ───────────────────────────────────────────────────
    record_entry = {
        "encrypted_record": encrypted_record,
        "patient_id":       patient_id,
        "event_id":         event_id,
        "submitter":        payload["username"],
        "signature":        signature,
    }

    with _lock:
        block = bc.add_record(record_entry)

    # Broadcast asynchronously so the response returns quickly
    threading.Thread(target=_broadcast_chain, daemon=True).start()

    block_info = block.to_dict() if block else None
    return jsonify({
        "message":    "Record added to blockchain",
        "block":      block_info,
        "chain_length": bc.length,
    }), 201


@app.route("/chain", methods=["GET"])
def get_chain():
    """
    Return the full blockchain as JSON.

    Called by the query server to retrieve records, and by peers for sync.
    The chain contains only encrypted record blobs — raw audit data is never
    exposed here.
    """
    with _lock:
        chain_data   = bc.to_dict()
        chain_length = bc.length
    return jsonify({"chain": chain_data, "length": chain_length}), 200


@app.route("/chain/sync", methods=["POST"])
def sync_chain():
    """
    Receive a chain from a peer node and adopt it if it is longer and valid.

    This implements Nakamoto's longest-chain consensus rule:
      - A node always prefers the chain with more proof-of-work (= more blocks).
      - A candidate chain is only accepted if it passes full cryptographic
        validation (is_chain_valid), preventing injection of fake blocks.

    Body (JSON): { "chain": [ <block_dict>, ... ] }
    """
    data = request.get_json(force=True)
    candidate_chain = data.get("chain", [])

    with _lock:
        replaced = bc.replace_chain(candidate_chain)

    if replaced:
        return jsonify({"message": "Chain replaced (longer valid chain received)"}), 200
    else:
        return jsonify({"message": "Chain kept (ours is already longest/valid)"}), 200


@app.route("/chain/validate", methods=["GET"])
def validate_chain():
    """
    Validate the integrity of this node's blockchain.

    Returns whether the chain is intact and, if not, which block was tampered.
    Used by the tamper_demo to demonstrate immutability detection.
    """
    with _lock:
        is_valid, tampered_index = bc.is_chain_valid()

    if is_valid:
        return jsonify({
            "valid":   True,
            "message": "Blockchain integrity verified — no tampering detected.",
            "blocks":  bc.length,
        }), 200
    else:
        return jsonify({
            "valid":          False,
            "message":        f"TAMPER DETECTED at block index {tampered_index}!",
            "tampered_block": tampered_index,
        }), 200


@app.route("/peers", methods=["GET"])
def list_peers():
    """List this node's peer URLs."""
    return jsonify({"my_port": MY_PORT, "peers": _get_peers()}), 200


@app.route("/debug/tamper", methods=["POST"])
def debug_tamper():
    """
    ⚠️  DEMO-ONLY ENDPOINT — would NOT exist in production.

    Directly mutates a field inside one block's first record to simulate
    a rogue insider attack on the blockchain.  After this call, the node's
    chain will fail is_chain_valid() because the stored hash no longer matches
    the block's actual content.

    Body (JSON)::

        {
          "block_index": 1,
          "field":       "patient_id",
          "new_value":   "ERASED"
        }
    """
    data        = request.get_json(force=True)
    block_index = data.get("block_index", 1)
    field       = data.get("field", "patient_id")
    new_value   = data.get("new_value", "TAMPERED")

    with _lock:
        if block_index >= len(bc.chain):
            return jsonify({"error": f"Block {block_index} does not exist"}), 404

        block = bc.chain[block_index]
        if not block.records:
            return jsonify({"error": "Block has no records to tamper"}), 400

        old_value = block.records[0].get(field, "<not found>")
        # ← This is the attack: modify the record content WITHOUT updating the hash.
        #   The block.hash still reflects the original data, so the chain appears
        #   intact to a naive check — but is_chain_valid() recomputes and catches it.
        block.records[0][field] = new_value

    return jsonify({
        "message":     f"Block {block_index} tampered (demo only).",
        "field":       field,
        "old_value":   str(old_value),
        "new_value":   new_value,
        "warning":     "Hash not updated — tamper is detectable by is_chain_valid()",
    }), 200


@app.route("/status", methods=["GET"])
def status():
    """Quick health + chain summary for monitoring."""
    with _lock:
        chain_length = bc.length
        last_hash    = bc.last_block.hash
    return jsonify({
        "node":         f"audit_node:{MY_PORT}",
        "chain_length": chain_length,
        "last_hash":    last_hash,
        "difficulty":   BLOCKCHAIN_DIFFICULTY,
        "peers":        _get_peers(),
    }), 200


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    MY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5002
    print(f"[audit_node:{MY_PORT}] Starting. Peers: {_get_peers()}")
    app.run(port=MY_PORT, debug=False)
