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

USER_DB: dict[str, User] = {}

PRIVATE_KEY_STORE: dict[str, bytes] = {}

PATIENT_AES_KEYS: dict[str, bytes] = {}

_lock = threading.Lock()


def _register_user(username: str, password: str, role: str):

    private_pem, public_pem = generate_rsa_keypair()
    user = User(
        username      = username,
        password_hash = hash_password(password),
        role          = role,
        public_pem    = public_pem.decode(),
    )
    USER_DB[username]           = user
    PRIVATE_KEY_STORE[username] = private_pem

    if role == "patient":
        PATIENT_AES_KEYS[username] = generate_aes_key()


def _seed_users():
    for u in INITIAL_USERS:
        _register_user(u["username"], u["password"], u["role"])
    print(f"[auth_server] Seeded {len(USER_DB)} users.")



@app.route("/register", methods=["POST"])
def register():
  
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

    data  = request.get_json(force=True)
    token = data.get("token", "")
    try:
        payload = verify_jwt(token, JWT_SECRET)
        return jsonify({"valid": True, "payload": payload}), 200
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401


@app.route("/public_key/<username>", methods=["GET"])
def get_public_key(username: str):

    user = USER_DB.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": username, "public_pem": user.public_pem}), 200


@app.route("/private_key/<username>", methods=["POST"])
def get_private_key(username: str):

    data  = request.get_json(force=True)
    token = data.get("token", "")
    try:
        payload = verify_jwt(token, JWT_SECRET)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if payload["username"] != username and payload["role"] != "audit_company":
        return jsonify({"error": "Forbidden"}), 403

    pem = PRIVATE_KEY_STORE.get(username)
    if not pem:
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"private_pem": pem.decode()}), 200


@app.route("/patient_key/<patient_id>", methods=["POST"])
def get_patient_aes_key(patient_id: str):
  
    data  = request.get_json(force=True)
    token = data.get("token", "")
    try:
        payload = verify_jwt(token, JWT_SECRET)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    role     = payload["role"]
    username = payload["username"]

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
    return jsonify([u.to_dict() for u in USER_DB.values()]), 200


if __name__ == "__main__":
    _seed_users()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else AUTH_SERVER_PORT
    print(f"[auth_server] Listening on port {port}")
    app.run(port=port, debug=False)
