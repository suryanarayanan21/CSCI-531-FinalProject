
import sys
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import AUTH_SERVER_URL, AUDIT_NODE_URLS, QUERY_SERVER_PORT
from crypto_utils import aes_decrypt, decode_key, verify_jwt
from config import JWT_SECRET

app = Flask(__name__)
CORS(app)


def _verify_token(token: str) -> dict | None:
    """Call auth server to validate *token*; return payload or None."""
    try:
        resp = requests.post(
            f"{AUTH_SERVER_URL}/verify_token",
            json={"token": token},
            timeout=5,
        )
        if resp.status_code == 200 and resp.json().get("valid"):
            return resp.json()["payload"]
    except Exception:
        # Fallback: verify locally
        try:
            return verify_jwt(token, JWT_SECRET)
        except Exception:
            pass
    return None


def _get_aes_key(patient_id: str, token: str) -> bytes | None:
    try:
        resp = requests.post(
            f"{AUTH_SERVER_URL}/patient_key/{patient_id}",
            json={"token": token},
            timeout=5,
        )
        if resp.status_code == 200:
            return decode_key(resp.json()["key_b64"])
    except Exception:
        pass
    return None


def _fetch_chain_from_any_node() -> list:
    
    for node_url in AUDIT_NODE_URLS:
        try:
            resp = requests.get(f"{node_url}/chain", timeout=5)
            if resp.status_code == 200:
                return resp.json()["chain"]
        except Exception:
            continue
    raise RuntimeError("No audit node is reachable.")


def _decrypt_entry(entry: dict, aes_key: bytes) -> dict | None:
    
    try:
        plaintext = aes_decrypt(entry["encrypted_record"], aes_key)
        record    = json.loads(plaintext)
        return {
            **record,
            "_block_index": entry.get("_block_index"),
            "_block_hash":  entry.get("_block_hash"),
            "_submitter":   entry.get("submitter"),
        }
    except Exception:
        return None


def _entries_from_chain(chain: list) -> list[dict]:
    entries = []
    for block in chain[1:]:   # block 0 is genesis
        for rec in block.get("records", []):
            entries.append({
                **rec,
                "_block_index": block["index"],
                "_block_hash":  block["hash"],
            })
    return entries


@app.route("/query/my_records", methods=["POST"])
def query_my_records():
   
    data  = request.get_json(force=True)
    token = data.get("token", "")

    payload = _verify_token(token)
    if payload is None:
        return jsonify({"error": "Invalid token"}), 401
    if payload["role"] != "patient":
        return jsonify({"error": "Only patients may use this endpoint"}), 403

    patient_id = payload["username"]

    try:
        chain = _fetch_chain_from_any_node()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    entries = [e for e in _entries_from_chain(chain) if e.get("patient_id") == patient_id]

    aes_key = _get_aes_key(patient_id, token)
    if aes_key is None:
        return jsonify({"error": "Could not retrieve decryption key"}), 500

    decrypted = [r for e in entries if (r := _decrypt_entry(e, aes_key)) is not None]

    return jsonify({
        "patient_id":    patient_id,
        "record_count":  len(decrypted),
        "records":       decrypted,
    }), 200


@app.route("/query/patient/<patient_id>", methods=["POST"])
def query_patient(patient_id: str):
    
    data  = request.get_json(force=True)
    token = data.get("token", "")

    payload = _verify_token(token)
    if payload is None:
        return jsonify({"error": "Invalid token"}), 401
    if payload["role"] != "audit_company":
        return jsonify({"error": "Only audit companies may use this endpoint"}), 403

    try:
        chain = _fetch_chain_from_any_node()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    entries = [e for e in _entries_from_chain(chain) if e.get("patient_id") == patient_id]

    aes_key = _get_aes_key(patient_id, token)
    if aes_key is None:
        return jsonify({"error": "Could not retrieve decryption key"}), 500

    decrypted = [r for e in entries if (r := _decrypt_entry(e, aes_key)) is not None]

    return jsonify({
        "patient_id":   patient_id,
        "queried_by":   payload["username"],
        "record_count": len(decrypted),
        "records":      decrypted,
    }), 200


@app.route("/query/all", methods=["POST"])
def query_all():
    
    data  = request.get_json(force=True)
    token = data.get("token", "")

    payload = _verify_token(token)
    if payload is None:
        return jsonify({"error": "Invalid token"}), 401
    if payload["role"] != "audit_company":
        return jsonify({"error": "Only audit companies may use this endpoint"}), 403

    try:
        chain = _fetch_chain_from_any_node()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    all_entries = _entries_from_chain(chain)

    # Group by patient_id so we fetch each AES key only once
    by_patient: dict[str, list] = {}
    for e in all_entries:
        pid = e.get("patient_id", "unknown")
        by_patient.setdefault(pid, []).append(e)

    all_decrypted = []
    for pid, entries in by_patient.items():
        aes_key = _get_aes_key(pid, token)
        if aes_key is None:
            continue
        for e in entries:
            dec = _decrypt_entry(e, aes_key)
            if dec:
                all_decrypted.append(dec)

    # Sort chronologically
    all_decrypted.sort(key=lambda r: r.get("timestamp", ""))

    return jsonify({
        "queried_by":   payload["username"],
        "record_count": len(all_decrypted),
        "records":      all_decrypted,
    }), 200


@app.route("/query/by_user/<user_id>", methods=["POST"])
def query_by_user(user_id: str):
   
    data  = request.get_json(force=True)
    token = data.get("token", "")

    payload = _verify_token(token)
    if payload is None:
        return jsonify({"error": "Invalid token"}), 401
    if payload["role"] != "audit_company":
        return jsonify({"error": "Only audit companies may use this endpoint"}), 403

    try:
        chain = _fetch_chain_from_any_node()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    all_entries = _entries_from_chain(chain)

    results = []
    seen_patients: dict[str, bytes] = {}

    for e in all_entries:
        pid = e.get("patient_id", "")
        if pid not in seen_patients:
            key = _get_aes_key(pid, token)
            seen_patients[pid] = key
        aes_key = seen_patients.get(pid)
        if aes_key is None:
            continue
        dec = _decrypt_entry(e, aes_key)
        if dec and dec.get("user_id") == user_id:
            results.append(dec)

    results.sort(key=lambda r: r.get("timestamp", ""))

    return jsonify({
        "user_id":      user_id,
        "queried_by":   payload["username"],
        "record_count": len(results),
        "records":      results,
    }), 200


@app.route("/status", methods=["GET"])
def status():
   
    try:
        chain = _fetch_chain_from_any_node()
        node_status = "reachable"
        chain_len   = len(chain)
    except RuntimeError:
        node_status = "no audit nodes reachable"
        chain_len   = 0
    return jsonify({
        "service":      "query_server",
        "node_status":  node_status,
        "chain_length": chain_len,
    }), 200

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else QUERY_SERVER_PORT
    print(f"[query_server] Listening on port {port}")
    app.run(port=port, debug=False)
