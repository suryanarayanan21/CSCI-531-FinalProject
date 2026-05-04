
import uuid
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ── AuditRecord ──────────────────────────────────────────────────────────────

@dataclass
class AuditRecord:
    
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


@dataclass
class User:
   
    username: str
    password_hash: str
    role: str          
    public_pem: str = ""   
    
    VALID_ROLES = {"patient", "audit_company", "ehr_user"}

    def to_dict(self) -> dict:
        return {
            "username":   self.username,
            "role":       self.role,
            "public_pem": self.public_pem,
        }
