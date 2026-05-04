"""
For Testing purposes on terminal
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

class AuthClient:
   
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
       
        resp = requests.post(
            f"{self.auth_url}/patient_key/{patient_id}",
            json={"token": self.token},
            timeout=10,
        )
        resp.raise_for_status()
        return decode_key(resp.json()["key_b64"])

    def get_private_key(self, username: str) -> bytes:
    
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

class AuditClient:

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
      
        aes_key = self.auth.get_patient_aes_key(record.patient_id)

        plaintext_json    = record.to_json()
        encrypted_record  = aes_encrypt(plaintext_json, aes_key)

        private_pem = self._get_private_pem()
        signature   = sign_data(encrypted_record, private_pem)

        record.signature = signature

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
        resp = requests.get(f"{self.node}/chain", timeout=10)
        resp.raise_for_status()
        return resp.json()["chain"]

    def validate_chain(self) -> dict:
        resp = requests.get(f"{self.node}/chain/validate", timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_status(self) -> dict:
        resp = requests.get(f"{self.node}/status", timeout=10)
        resp.raise_for_status()
        return resp.json()


class QueryClient:
    
    def __init__(self, auth_client: AuthClient, query_url: str = QUERY_SERVER_URL):
        self.auth      = auth_client
        self.query_url = query_url

    def my_records(self) -> dict:
        resp = requests.post(
            f"{self.query_url}/query/my_records",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def patient_records(self, patient_id: str) -> dict:
        resp = requests.post(
            f"{self.query_url}/query/patient/{patient_id}",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def all_records(self) -> dict:
        resp = requests.post(
            f"{self.query_url}/query/all",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def records_by_user(self, user_id: str) -> dict:
        resp = requests.post(
            f"{self.query_url}/query/by_user/{user_id}",
            json={"token": self.auth.token},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
