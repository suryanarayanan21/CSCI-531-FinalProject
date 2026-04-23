"""
models.py
---------
Data models for the EHR Blockchain Audit System.

AuditRecord  – one logged EHR access event.
User         – a registered system principal (patient, audit company, EHR staff).
"""

import uuid
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ── AuditRecord ──────────────────────────────────────────────────────────────

@dataclass
class AuditRecord:
    """
    One audit event generated when EHR data is accessed.

    Fields required by the project specification:
      - timestamp   : ISO-8601 UTC time of the access event
      - patient_id  : which patient's record was accessed
      - user_id     : who performed the access (doctor, nurse, admin …)
      - action_type : create | delete | change | query | print | copy

    Additional fields added for security:
      - event_id    : unique UUID to prevent replay / duplicate insertion
      - details     : free-form notes (e.g. "accessed medication list")
      - signature   : RSA signature over the record by the submitting EHR system
    """
    patient_id:  str
    user_id:     str
    action_type: str
    details:     str                    = ""
    timestamp:   str                    = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    event_id:    str                    = field(default_factory=lambda: str(uuid.uuid4()))
    signature:   Optional[str]          = None   # set after signing

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        """Canonical JSON representation used for signing / hashing."""
        d = self.to_dict()
        d.pop("signature", None)   # signature is NOT included in signed payload
        return json.dumps(d, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict) -> "AuditRecord":
        return cls(
            patient_id  = d["patient_id"],
            user_id     = d["user_id"],
            action_type = d["action_type"],
            details     = d.get("details", ""),
            timestamp   = d.get("timestamp", datetime.now(tz=timezone.utc).isoformat()),
            event_id    = d.get("event_id", str(uuid.uuid4())),
            signature   = d.get("signature"),
        )


# ── User ─────────────────────────────────────────────────────────────────────

@dataclass
class User:
    """
    A registered principal in the system.

    Roles:
      patient       – may query only their own audit records
      audit_company – may query all audit records for any patient
      ehr_user      – EHR staff who generate audit events; cannot query blockchain
    """
    username:     str
    password_hash: str
    role:          str          # patient | audit_company | ehr_user
    public_pem:    str          = ""   # RSA-2048 public key (PEM, str)
    # private_pem is stored separately and NEVER sent over the network

    VALID_ROLES = {"patient", "audit_company", "ehr_user"}

    def to_dict(self) -> dict:
        """Return a safe dict (no private key, no password hash)."""
        return {
            "username":   self.username,
            "role":       self.role,
            "public_pem": self.public_pem,
        }
