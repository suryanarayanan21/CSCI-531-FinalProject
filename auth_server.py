"""
auth_server.py
--------------
Authentication & Authorization Server  (port 5001)

Responsibilities
----------------
  POST /register          – register a new user; generates RSA key pair
  POST /login             – authenticate with username/password; returns JWT
  GET  /public_key/<usr>  – fetch a user's RSA public key (public info)
  POST /verify_token      – validate a JWT and return its claims
  GET  /users             – list all registered users (for admin / demo)

Key management
--------------
  Each user gets an RSA-2048 key pair at registration time.
  The public key is stored in USER_DB and served on request.
  The private key is stored in PRIVATE_KEY_STORE (in production this would
  be an HSM or a secure vault; here it lives in memory for the demo).

  Per-patient AES keys (for encrypting audit records) are also managed here:
    - generated once per patient at registration
    - the raw AES key is stored in PATIENT_AES_KEYS (in production: KMS)
    - for audit companies, a copy of each patient AES key is available
      via /patient_key/<patient_id> (access is role-gated)
"""

import sys
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import AUTH_SERVER_PORT, JWT_SECRET, INITIAL_USERS
from crypto_utils import (
    generate_rsa_keypair,
    generate_aes_key,
    generate_jwt,
    verify_jwt,
    hash_password,
    encode_key,
)
from models import User

app = Flask(__name__)
CORS(app)

# ── In-memory stores (swap for a database in production) ─────────────────────

# username → User
USER_DB: dict[str, User] = {}

# username → private PEM (bytes) — NEVER exposed via API
PRIVATE_KEY_STORE: dict[str, bytes] = {}

# patient_id → raw AES key (bytes) — used to encrypt that patient's audit records
PATIENT_AES_KEYS: dict[str, bytes] = {}

_lock = threading.Lock()


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def _register_user(username: str, password: str, role: str):
    """Internal helper — called at startup and from the /register endpoint."""
    private_pem, public_pem = generate_rsa_keypair()
    user = User(
        username      = username,
        password_hash = hash_password(password),
        role          = role,
        public_pem    = public_pem.decode(),
    )
    USER_DB[username]           = user
    PRIVATE_KEY_STORE[username] = private_pem

    # Every patient gets a dedicated AES key for encrypting their audit records
    if role == "patient":
        PATIENT_AES_KEYS[username] = generate_aes_key()


def _seed_users():
    for u in INITIAL_USERS:
        _register_user(u["username"], u["password"], u["role"])
    print(f"[auth_server] Seeded {len(USER_DB)} users.")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    Body (JSON): { username, password, role }
    Returns: 201 with user info, or 409 if username taken.
    """
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in User.VALID_ROLES:
        return jsonify({"error": f"Invalid role. Choose from {User.VALID_ROLES}"}), 400

    with _lock:
        if username in USER_DB:
            return jsonify({"error": "Username already taken"}), 409
        _register_user(username, password, role)

    return jsonify({"message": f"User '{username}' registered.", "role": role}), 201


@app.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and issue a JWT.

    Body (JSON): { username, password }
    Returns: { token } on success, 401 on bad credentials.

    The JWT payload carries { username, role } and is signed with JWT_SECRET.
    Downstream servers call /verify_token to authenticate requests.
    """
    data     = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    user = USER_DB.get(username)
    if not user or user.password_hash != hash_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_jwt({"username": username, "role": user.role}, JWT_SECRET)
    return jsonify({"token": token, "role": user.role}), 200


@app.route("/verify_token", methods=["POST"])
def verify_token():
    """
    Verify a JWT token sent by another server component.

    Body (JSON): { token }
    Returns: decoded payload, or 401 on invalid/expired token.

    Called by audit_server and query_server to authenticate incoming requests
    without maintaining their own session state.
    """
    data  = request.get_json(force=True)
    token = data.get("token", "")
    try:
        payload = verify_jwt(token, JWT_SECRET)
        return jsonify({"valid": True, "payload": payload}), 200
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401


@app.route("/public_key/<username>", methods=["GET"])
def get_public_key(username: str):
    """
    Return the RSA public key (PEM) for *username*.

    Public keys are not secret — any component may fetch them to verify
    record signatures or to encrypt data for a specific user.
    """
    user = USER_DB.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": username, "public_pem": user.public_pem}), 200


@app.route("/private_key/<username>", methods=["POST"])
def get_private_key(username: str):
    """
    Return the private key for *username* — gated by valid JWT of that user.

    In a real deployment this endpoint would not exist; the private key would
    never leave the client device.  It is included here only so the demo
    query_server can decrypt records on behalf of authenticated patients without
    requiring client-side key management.

    Body (JSON): { token }
    """
    data  = request.get_json(force=True)
    token = data.get("token", "")
    try:
        payload = verify_jwt(token, JWT_SECRET)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    # Only the user themselves (or an audit company) may retrieve this
    if payload["username"] != username and payload["role"] != "audit_company":
        return jsonify({"error": "Forbidden"}), 403

    pem = PRIVATE_KEY_STORE.get(username)
    if not pem:
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"private_pem": pem.decode()}), 200


@app.route("/patient_key/<patient_id>", methods=["POST"])
def get_patient_aes_key(patient_id: str):
    """
    Return the AES key for *patient_id*, gated by role.

    - Patients may only retrieve their own key.
    - Audit companies may retrieve any patient's key (they have legal authority
      to audit all records).
    - EHR users submitting records retrieve keys to encrypt before submission.

    Body (JSON): { token }
    Returns: { key_b64 } — base64-encoded 256-bit AES key.
    """
    data  = request.get_json(force=True)
    token = data.get("token", "")
    try:
        payload = verify_jwt(token, JWT_SECRET)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    role     = payload["role"]
    username = payload["username"]

    # Access control
    if role == "patient" and username != patient_id:
        return jsonify({"error": "Patients may only retrieve their own AES key"}), 403
    if role not in {"patient", "audit_company", "ehr_user"}:
        return jsonify({"error": "Forbidden"}), 403

    aes_key = PATIENT_AES_KEYS.get(patient_id)
    if aes_key is None:
        return jsonify({"error": f"No AES key for patient '{patient_id}'"}), 404

    return jsonify({"patient_id": patient_id, "key_b64": encode_key(aes_key)}), 200


@app.route("/users", methods=["GET"])
def list_users():
    """List all registered users (public info only — no keys, no hashes)."""
    return jsonify([u.to_dict() for u in USER_DB.values()]), 200


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _seed_users()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else AUTH_SERVER_PORT
    print(f"[auth_server] Listening on port {port}")
    app.run(port=port, debug=False)
