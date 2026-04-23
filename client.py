"""
client.py
---------
Client-side library for the EHR Blockchain Audit System.

Provides three client classes:

  AuthClient   – register, login, fetch public keys
  AuditClient  – submit encrypted audit records to a blockchain node
  QueryClient  – issue authorised queries to the query server

These classes are used by ehr_simulator.py, tamper_demo.py, and run_demo.py.
"""

import json
import requests
from typing import Optional

from config import AUTH_SERVER_URL, AUDIT_NODE_URLS, QUERY_SERVER_URL
from crypto_utils import (
    aes_encrypt,
    decode_key,
    sign_data,
)
from models import AuditRecord


# ── AuthClient ────────────────────────────────────────────────────────────────

class AuthClient:
    """Interacts with the authentication server."""

    def __init__(self, auth_url: str = AUTH_SERVER_URL):
        self.auth_url = auth_url
        self.token: Optional[str] = None
        self.role:  Optional[str] = None
        self.username: Optional[str] = None

    def register(self, username: str, password: str, role: str) -> dict:
        resp = requests.post(
            f"{self.auth_url}/register",
            json={"username": username, "password": password, "role": role},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def login(self, username: str, password: str) -> str:
        """Login and store the JWT token. Returns the token."""
        resp = requests.post(
            f"{self.auth_url}/login",
            json={"username": username, "password": password},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        self.token    = data["token"]
        self.role     = data["role"]
        self.username = username
        return self.token

    def get_patient_aes_key(self, patient_id: str) -> bytes:
        """Fetch the AES key for *patient_id* (caller must be authorised)."""
        resp = requests.post(
            f"{self.auth_url}/patient_key/{patient_id}",
            json={"token": self.token},
            timeout=10,
        )
        resp.raise_for_status()
        return decode_key(resp.json()["key_b64"])

    def get_private_key(self, username: str) -> bytes:
        """Fetch the RSA private key PEM for *username* (for signing)."""
        resp = requests.post(
            f"{self.auth_url}/private_key/{username}",
            json={"token": self.token},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["private_pem"].encode()

    def list_users(self) -> list:
        resp = requests.get(f"{self.auth_url}/users", timeout=10)
        resp.raise_for_status()
        return resp.json()


# ── AuditClient ───────────────────────────────────────────────────────────────

class AuditClient:
    """
    Submits audit records to blockchain nodes as an authorised EHR user.

    Workflow
    --------
    1. Login to auth server → get JWT.
    2. Fetch patient's AES key from auth server.
    3. Encrypt the AuditRecord JSON with AES-256-CBC.
    4. Sign the ciphertext with the submitter's RSA private key.
    5. POST the encrypted blob to an audit node.
    """

    def __init__(self, auth_client: AuthClient, node_url: str = AUDIT_NODE_URLS[0]):
        self.auth  = auth_client
        self.node  = node_url
        # Cache private key after first fetch to avoid repeated round-trips
        self._private_pem: Optional[bytes] = None

    def _get_private_pem(self) -> bytes:
        if self._private_pem is None:
            self._private_pem = self.auth.get_private_key(self.auth.username)
        return self._private_pem

    def submit_record(self, record: AuditRecord) -> dict:
        """
        Encrypt, sign, and submit *record* to the blockchain node.

        Returns the server's response dict (includes block info).
        """
        # 1. Fetch patient's AES key
        aes_key = self.auth.get_patient_aes_key(record.patient_id)

        # 2. Encrypt the canonical record JSON (no signature field)
        plaintext_json    = record.to_json()
        encrypted_record  = aes_encrypt(plaintext_json, aes_key)

        # 3. Sign the ciphertext (proves this EHR user produced the record)
        private_pem = self._get_private_pem()
        signature   = sign_data(encrypted_record, private_pem)

        # 4. Attach signature to record object (for completeness in the model)
        record.signature = signature

        # 5. POST to audit node
        resp = requests.post(
            f"{self.node}/audit/record",
            json={
                "token":            self.auth.token,
                "encrypted_record": encrypted_record,
                "patient_id":       record.patient_id,
                "event_id":         record.event_id,
                "signature":        signature,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def get_chain(self) -> list:
        """Retrieve the full blockchain from this node."""
        resp = requests.get(f"{self.node}/chain", timeout=10)
        resp.raise_for_status()
        return resp.json()["chain"]

    def validate_chain(self) -> dict:
        """Ask the node to validate its own chain and return the result."""
        resp = requests.get(f"{self.node}/chain/validate", timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_status(self) -> dict:
        resp = requests.get(f"{self.node}/status", timeout=10)
        resp.raise_for_status()
        return resp.json()


# ── QueryClient ───────────────────────────────────────────────────────────────

class QueryClient:
    """Issues authorised read queries to the query server."""

    def __init__(self, auth_client: AuthClient, query_url: str = QUERY_SERVER_URL):
        self.auth      = auth_client
        self.query_url = query_url

    def my_records(self) -> dict:
        """Patient: fetch my own audit records."""
        resp = requests.post(
            f"{self.query_url}/query/my_records",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def patient_records(self, patient_id: str) -> dict:
        """Audit company: fetch records for one patient."""
        resp = requests.post(
            f"{self.query_url}/query/patient/{patient_id}",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def all_records(self) -> dict:
        """Audit company: fetch ALL records across all patients."""
        resp = requests.post(
            f"{self.query_url}/query/all",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def records_by_user(self, user_id: str) -> dict:
        """Audit company: all access events by a specific EHR user."""
        resp = requests.post(
            f"{self.query_url}/query/by_user/{user_id}",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
