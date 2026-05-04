"""
run_demo.py
-----------
End-to-end demonstration of the EHR Blockchain Audit System (Option 2).

What this script does
---------------------
  1.  Start Auth Server (port 5001)
  2.  Start three Audit Nodes (ports 5002, 5012, 5022) → decentralised network
  3.  Start Query Server (port 5003)
  4.  Wait for all servers to come online
  5.  Simulate 15 EHR access events → encrypted audit records on the blockchain
  6.  Demo: Patient queries their own records
  7.  Demo: Audit company queries all records
  8.  Demo: Audit company investigates a specific EHR user
  9.  Demo: Tamper detection & recovery
  10. Print final chain summary from all three nodes

Usage
-----
    python run_demo.py

All servers are spawned as subprocesses and killed on exit.
"""

import sys
import time
import json
import signal
import subprocess
import requests

from config import (
    AUTH_SERVER_PORT, AUDIT_NODE_PORTS, QUERY_SERVER_PORT,
    AUTH_SERVER_URL, AUDIT_NODE_URLS, QUERY_SERVER_URL,
)
from client import AuthClient, AuditClient, QueryClient
from ehr_simulator import simulate_ehr_accesses
from tamper_demo import run_tamper_demo

PYTHON = sys.executable   # use the same Python interpreter that runs this script

_procs = []   # keep track of subprocesses so we can kill them at exit


# ── Process Management ────────────────────────────────────────────────────────

def _start_server(script: str, port: int) -> subprocess.Popen:
    """Spawn *script* on *port* as a background subprocess."""
    proc = subprocess.Popen(
        [PYTHON, script, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _procs.append(proc)
    return proc


def _kill_all():
    for p in _procs:
        try:
            p.terminate()
        except Exception:
            pass


def _wait_for(url: str, retries: int = 30, delay: float = 0.5) -> bool:
    """Poll *url* until it returns HTTP 200 or retries are exhausted."""
    for _ in range(retries):
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


# ── Pretty Print Helpers ──────────────────────────────────────────────────────

def _sep(title: str = ""):
    w = 60
    if title:
        pad = (w - len(title) - 2) // 2
        print("\n" + "─" * pad + f" {title} " + "─" * pad)
    else:
        print("\n" + "─" * w)


def _print_records(records: list, max_rows: int = 8):
    """Print audit records in a readable table."""
    if not records:
        print("  (no records)")
        return
    shown = records[:max_rows]
    for r in shown:
        ts  = r.get("timestamp", "")[:19].replace("T", " ")
        uid = r.get("user_id", "?")
        pid = r.get("patient_id", "?")
        act = r.get("action_type", "?")
        det = r.get("details", "")
        blk = r.get("_block_index", "?")
        print(f"  [{ts}] {uid:12s} → {pid:12s} | {act:8s} | {det[:35]} | blk#{blk}")
    if len(records) > max_rows:
        print(f"  ... and {len(records) - max_rows} more records.")


# ── Main Demo ─────────────────────────────────────────────────────────────────

def main():
    signal.signal(signal.SIGINT,  lambda *_: (_kill_all(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *_: (_kill_all(), sys.exit(0)))

    print("╔══════════════════════════════════════════════════════╗")
    print("║  EHR Blockchain Audit System – Full Demo (Option 2) ║")
    print("╚══════════════════════════════════════════════════════╝")

    # ── Step 1: Start servers ─────────────────────────────────────────────────
    _sep("Starting Servers")

    print(f"  ▸ Auth Server     → port {AUTH_SERVER_PORT}")
    _start_server("auth_server.py", AUTH_SERVER_PORT)

    for port in AUDIT_NODE_PORTS:
        print(f"  ▸ Audit Node      → port {port}")
        _start_server("audit_server.py", port)
        time.sleep(0.2)   # stagger starts

    print(f"  ▸ Query Server    → port {QUERY_SERVER_PORT}")
    _start_server("query_server.py", QUERY_SERVER_PORT)

    # ── Step 2: Wait for all servers ──────────────────────────────────────────
    _sep("Waiting for Services")
    all_urls = (
        [f"{AUTH_SERVER_URL}/users"]
        + [f"{u}/status" for u in AUDIT_NODE_URLS]
        + [f"{QUERY_SERVER_URL}/status"]
    )
    for url in all_urls:
        ok = _wait_for(url)
        tag = url.split("/")[2]   # host:port
        print(f"  {'✓' if ok else '✗'} {tag} {'ready' if ok else 'TIMED OUT'}")

    # ── Step 3: Simulate EHR accesses ─────────────────────────────────────────
    _sep("Simulating EHR Access Events")
    print("  Submitting 15 audit events (encrypted, signed) to Node 1 (port 5002)...\n")
    simulate_ehr_accesses(node_index=0, verbose=True)

    # Give nodes a moment to sync
    time.sleep(1)

    # ── Step 4: Show chain status across all nodes ────────────────────────────
    _sep("Blockchain Node Status")
    for url in AUDIT_NODE_URLS:
        try:
            s = requests.get(f"{url}/status", timeout=5).json()
            print(
                f"  {s.get('node'):25s}  "
                f"blocks={s.get('chain_length')}  "
                f"last={s.get('last_hash','')[:16]}..."
            )
        except Exception:
            print(f"  {url}  — unreachable")

    # ── Step 5: Patient query ─────────────────────────────────────────────────
    _sep("Patient Transparency Query")
    print("  patient_1 logs in and queries their own audit records...\n")
    p1_auth = AuthClient()
    p1_auth.login("patient_1", "pass_p1")
    p1_query = QueryClient(p1_auth)
    try:
        result = p1_query.my_records()
        print(f"  patient_1 has {result['record_count']} audit record(s):\n")
        _print_records(result["records"])
    except Exception as e:
        print(f"  Error: {e}")

    # ── Step 6: Audit company – query one patient ─────────────────────────────
    _sep("Audit Company: Query patient_2 Records")
    ac1_auth = AuthClient()
    ac1_auth.login("audit_co_1", "pass_ac1")
    ac1_query = QueryClient(ac1_auth)
    try:
        result = ac1_query.patient_records("patient_2")
        print(f"  audit_co_1 sees {result['record_count']} record(s) for patient_2:\n")
        _print_records(result["records"])
    except Exception as e:
        print(f"  Error: {e}")

    # ── Step 7: Audit company – query all records ─────────────────────────────
    _sep("Audit Company: Query ALL Records")
    try:
        result = ac1_query.all_records()
        print(f"  Total records across all patients: {result['record_count']}\n")
        _print_records(result["records"])
    except Exception as e:
        print(f"  Error: {e}")

    # ── Step 8: Investigate a specific user ───────────────────────────────────
    _sep("Audit Company: Investigate doctor_1")
    try:
        result = ac1_query.records_by_user("doctor_1")
        print(f"  doctor_1 accessed {result['record_count']} record(s):\n")
        _print_records(result["records"])
    except Exception as e:
        print(f"  Error: {e}")

    # ── Step 9: Tamper detection ──────────────────────────────────────────────
    # run_tamper_demo(verbose=True)

    # ── Step 10: Chain consistency check across all nodes ─────────────────────
    _sep("Post-Demo Chain Validation (All Nodes)")
    for url in AUDIT_NODE_URLS:
        try:
            v = requests.get(f"{url}/chain/validate", timeout=5).json()
            status = "✓ VALID" if v.get("valid") else f"✗ TAMPERED (block {v.get('tampered_block')})"
            print(f"  {url}  →  {status}")
        except Exception:
            print(f"  {url}  →  unreachable")

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║  Demo complete. Press Ctrl-C to stop all servers.  ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        _kill_all()
        print("\nAll servers stopped.")


if __name__ == "__main__":
    main()
