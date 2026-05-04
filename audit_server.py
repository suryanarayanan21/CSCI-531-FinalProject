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

bc = Blockchain(difficulty=BLOCKCHAIN_DIFFICULTY)
_lock = threading.Lock()

MY_PORT: int = 5002


def _get_peers() -> list[str]:
    my_url = f"http://127.0.0.1:{MY_PORT}"
    return [url for url in AUDIT_NODE_URLS if url != my_url]


def _require_role(token: str, allowed_roles: set) -> dict | None:

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
        try:
            payload = verify_jwt(token, JWT_SECRET)
            if payload.get("role") in allowed_roles:
                return payload
        except Exception:
            pass
        return None

def _broadcast_chain():
    chain_data = bc.to_dict()
    for peer_url in _get_peers():
        try:
            requests.post(
                f"{peer_url}/chain/sync",
                json={"chain": chain_data},
                timeout=5,
            )
        except Exception:
            pass 

@app.route("/audit/record", methods=["POST"])
def submit_record():
    
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
            pass 

    record_entry = {
        "encrypted_record": encrypted_record,
        "patient_id":       patient_id,
        "event_id":         event_id,
        "submitter":        payload["username"],
        "signature":        signature,
    }

    with _lock:
        block = bc.add_record(record_entry)

    threading.Thread(target=_broadcast_chain, daemon=True).start()

    block_info = block.to_dict() if block else None
    return jsonify({
        "message":    "Record added to blockchain",
        "block":      block_info,
        "chain_length": bc.length,
    }), 201


@app.route("/chain", methods=["GET"])
def get_chain():
    with _lock:
        chain_data   = bc.to_dict()
        chain_length = bc.length
    return jsonify({"chain": chain_data, "length": chain_length}), 200


@app.route("/chain/sync", methods=["POST"])
def sync_chain():
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

    return jsonify({"my_port": MY_PORT, "peers": _get_peers()}), 200


@app.route("/debug/tamper", methods=["POST"])
def debug_tamper():
    
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


if __name__ == "__main__":
    MY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5002
    print(f"[audit_node:{MY_PORT}] Starting. Peers: {_get_peers()}")
    app.run(port=MY_PORT, debug=False)
