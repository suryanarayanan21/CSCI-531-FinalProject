"""
config.py
---------
System-wide configuration for the EHR Blockchain Audit System.

Architecture overview (Option 2 – Decentralization + Auth):
  - Auth Server     : port 5001  — registration, login, JWT issuance
  - Audit Node 1    : port 5002  ─┐
  - Audit Node 2    : port 5012  ─┤  3-node blockchain network
  - Audit Node 3    : port 5022  ─┘
  - Query Server    : port 5003  — authorised queries over audit data
"""

# ── Server Ports ────────────────────────────────────────────────────────────
AUTH_SERVER_PORT  = 5001
QUERY_SERVER_PORT = 5003

# Three independent blockchain nodes (run on the same machine for the demo)
AUDIT_NODE_PORTS = [5002, 5012, 5022]
AUDIT_NODE_URLS  = [f"http://127.0.0.1:{p}" for p in AUDIT_NODE_PORTS]

AUTH_SERVER_URL  = f"http://127.0.0.1:{AUTH_SERVER_PORT}"
QUERY_SERVER_URL = f"http://127.0.0.1:{QUERY_SERVER_PORT}"

# ── Blockchain Parameters ────────────────────────────────────────────────────
# Proof-of-work difficulty: hash must start with this many leading zeros.
# 3 is fast enough for a demo while still demonstrating real PoW.
BLOCKCHAIN_DIFFICULTY = 3

# Records to accumulate before mining a new block (set to 1 for demo clarity)
RECORDS_PER_BLOCK = 1

# ── Cryptographic Parameters ─────────────────────────────────────────────────
RSA_KEY_BITS       = 2048      # RSA key size for user key pairs
AES_KEY_BYTES      = 32        # 256-bit AES keys for record encryption
JWT_ALGORITHM      = "HS256"   # JWT signing algorithm
JWT_SECRET         = "csci531-ehr-audit-secret-2026"   # In prod: env variable
JWT_EXPIRY_SECONDS = 3600      # 1-hour token lifetime

# ── Pre-defined Users ────────────────────────────────────────────────────────
# The system is seeded with 10 patients, 3 audit companies, and EHR staff.
# Passwords would be hashed in a production system; kept plaintext for demo.
INITIAL_USERS = [
    # --- Patients ---
    {"username": "patient_1",  "password": "pass_p1",  "role": "patient"},
    {"username": "patient_2",  "password": "pass_p2",  "role": "patient"},
    {"username": "patient_3",  "password": "pass_p3",  "role": "patient"},
    {"username": "patient_4",  "password": "pass_p4",  "role": "patient"},
    {"username": "patient_5",  "password": "pass_p5",  "role": "patient"},
    {"username": "patient_6",  "password": "pass_p6",  "role": "patient"},
    {"username": "patient_7",  "password": "pass_p7",  "role": "patient"},
    {"username": "patient_8",  "password": "pass_p8",  "role": "patient"},
    {"username": "patient_9",  "password": "pass_p9",  "role": "patient"},
    {"username": "patient_10", "password": "pass_p10", "role": "patient"},
    # --- Audit Companies ---
    {"username": "audit_co_1", "password": "pass_ac1", "role": "audit_company"},
    {"username": "audit_co_2", "password": "pass_ac2", "role": "audit_company"},
    {"username": "audit_co_3", "password": "pass_ac3", "role": "audit_company"},
    # --- EHR Staff (generate audit events when they access patient records) ---
    {"username": "doctor_1",   "password": "pass_d1",  "role": "ehr_user"},
    {"username": "doctor_2",   "password": "pass_d2",  "role": "ehr_user"},
    {"username": "nurse_1",    "password": "pass_n1",  "role": "ehr_user"},
    {"username": "admin_1",    "password": "pass_a1",  "role": "ehr_user"},
]

# Valid EHR action types (per project specification)
VALID_ACTIONS = {"create", "delete", "change", "query", "print", "copy"}
