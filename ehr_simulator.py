"""
Prefills sample data"""
import time
from typing import List

from client import AuthClient, AuditClient
from models import AuditRecord
from config import AUDIT_NODE_URLS


EHR_SCENARIOS: List[dict] = [
    # ── Doctor 1 morning rounds
    {"user_id": "doctor_1",  "patient_id": "patient_1",  "action_type": "query",  "details": "Reviewed lab results"},
    {"user_id": "doctor_1",  "patient_id": "patient_2",  "action_type": "query",  "details": "Pre-op assessment"},
    {"user_id": "doctor_1",  "patient_id": "patient_3",  "action_type": "change", "details": "Updated medication dosage"},
    {"user_id": "doctor_1",  "patient_id": "patient_1",  "action_type": "change", "details": "Updated diagnosis notes"},
    # ── Doctor 2 consultations
    {"user_id": "doctor_2",  "patient_id": "patient_4",  "action_type": "query",  "details": "Consultation review"},
    {"user_id": "doctor_2",  "patient_id": "patient_5",  "action_type": "print",  "details": "Printed discharge summary"},
    {"user_id": "doctor_2",  "patient_id": "patient_6",  "action_type": "query",  "details": "Reviewed imaging results"},
    {"user_id": "doctor_2",  "patient_id": "patient_7",  "action_type": "change", "details": "Added allergy note"},
    # ── Nurse 1 care tasks
    {"user_id": "nurse_1",   "patient_id": "patient_8",  "action_type": "create", "details": "Nursing observation entry"},
    {"user_id": "nurse_1",   "patient_id": "patient_9",  "action_type": "query",  "details": "Checked medication schedule"},
    {"user_id": "nurse_1",   "patient_id": "patient_10", "action_type": "create", "details": "Vital signs recorded"},
    {"user_id": "nurse_1",   "patient_id": "patient_1",  "action_type": "query",  "details": "Wound care check"},
    # ── Admin 1 administrative tasks
    {"user_id": "admin_1",   "patient_id": "patient_2",  "action_type": "copy",   "details": "Records transfer to specialist"},
    {"user_id": "admin_1",   "patient_id": "patient_5",  "action_type": "copy",   "details": "Insurance claim processing"},
    {"user_id": "admin_1",   "patient_id": "patient_8",  "action_type": "query",  "details": "Billing verification"},
]

# Passwords from config.py (matching INITIAL_USERS)
EHR_USER_PASSWORDS = {
    "doctor_1": "pass_d1",
    "doctor_2": "pass_d2",
    "nurse_1":  "pass_n1",
    "admin_1":  "pass_a1",
}


def simulate_ehr_accesses(node_index: int = 0, verbose: bool = True) -> List[dict]:

    node_url = AUDIT_NODE_URLS[node_index]
    results  = []

    sessions: dict[str, tuple[AuthClient, AuditClient]] = {}

    def _get_session(user_id: str):
        if user_id not in sessions:
            auth = AuthClient()
            auth.login(user_id, EHR_USER_PASSWORDS[user_id])
            audit = AuditClient(auth, node_url)
            sessions[user_id] = (auth, audit)
        return sessions[user_id]

    for i, scenario in enumerate(EHR_SCENARIOS, 1):
        user_id    = scenario["user_id"]
        patient_id = scenario["patient_id"]
        action     = scenario["action_type"]
        details    = scenario["details"]

        auth_client, audit_client = _get_session(user_id)

        record = AuditRecord(
            patient_id  = patient_id,
            user_id     = user_id,
            action_type = action,
            details     = details,
        )

        try:
            result = audit_client.submit_record(record)
            results.append({"status": "ok", "event_id": record.event_id, **result})
            if verbose:
                block_idx = result.get("block", {}).get("index", "?") if result.get("block") else "pending"
                print(
                    f"  [{i:02d}/{len(EHR_SCENARIOS)}] ✓  {user_id:12s} → {patient_id:12s} "
                    f"| {action:8s} | block {block_idx}"
                )
        except Exception as e:
            results.append({"status": "error", "event_id": record.event_id, "error": str(e)})
            if verbose:
                print(f"  [{i:02d}/{len(EHR_SCENARIOS)}] ✗  {user_id} → {patient_id}: {e}")

        # Small delay so timestamps differ for demo clarity
        time.sleep(0.05)

    return results

if __name__ == "__main__":
    print("=" * 60)
    print("EHR Access Simulator")
    print("=" * 60)
    print(f"Submitting {len(EHR_SCENARIOS)} audit events to the blockchain...\n")
    results = simulate_ehr_accesses(verbose=True)
    ok    = sum(1 for r in results if r["status"] == "ok")
    error = sum(1 for r in results if r["status"] == "error")
    print(f"\nDone. {ok} succeeded, {error} failed.")
