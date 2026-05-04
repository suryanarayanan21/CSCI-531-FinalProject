
import json
import requests

from config import AUDIT_NODE_URLS


def tamper_block(node_url: str, block_index: int, field: str, new_value: str) -> dict:
    
    resp = requests.post(
        f"{node_url}/debug/tamper",
        json={"block_index": block_index, "field": field, "new_value": new_value},
        timeout=10,
    )
    return resp.json()


def validate_node(node_url: str) -> dict:
    resp = requests.get(f"{node_url}/chain/validate", timeout=10)
    return resp.json()


def sync_node_with_peer(tampered_node_url: str, healthy_peer_url: str) -> dict:
    
    # 1. Get honest chain from peer
    chain_resp = requests.get(f"{healthy_peer_url}/chain", timeout=10)
    honest_chain = chain_resp.json()["chain"]

    # 2. Push it to the tampered node
    sync_resp = requests.post(
        f"{tampered_node_url}/chain/sync",
        json={"chain": honest_chain},
        timeout=10,
    )
    return sync_resp.json()


def run_tamper_demo(verbose: bool = True) -> dict:
    
    node_1 = AUDIT_NODE_URLS[0]   # target: attacker modifies this node
    node_2 = AUDIT_NODE_URLS[1]   # healthy peer used for recovery

    summary = {}

    if verbose:
        print("\n" + "=" * 60)
        print("TAMPER DETECTION DEMO")
        print("=" * 60)

    if verbose:
        print("\n[Step 0] Baseline chain validation (should be VALID)...")
    result_before = validate_node(node_1)
    summary["before_tamper"] = result_before
    if verbose:
        if result_before.get("valid"):
            print(f"  ✓ Chain is VALID ({result_before.get('blocks')} blocks)")
        else:
            print(f"  ✗ Already invalid? {result_before}")

    if verbose:
        print("\n[Step 1] Attacker modifies block 1, record field 'patient_id'...")
    tamper_result = tamper_block(node_1, block_index=1, field="patient_id", new_value="ERASED")
    summary["tamper_result"] = tamper_result
    if verbose:
        print(f"  Tamper response: {json.dumps(tamper_result, indent=2)}")

    if verbose:
        print("\n[Step 2] Validating chain after tampering...")
    result_after = validate_node(node_1)
    summary["after_tamper"] = result_after
    if verbose:
        if not result_after.get("valid"):
            print(f"  ✓ TAMPER DETECTED! {result_after.get('message')}")
            print(f"    Compromised block: {result_after.get('tampered_block')}")
        else:
            print("  Chain appears valid — tamper may have failed.")

    if verbose:
        print(f"\n[Step 3] Restoring node_1 by syncing with healthy node_2 ({node_2})...")
    try:
        restore_result = sync_node_with_peer(node_1, node_2)
        summary["restore_result"] = restore_result
        if verbose:
            print(f"  Sync response: {restore_result.get('message')}")
    except Exception as e:
        summary["restore_result"] = {"error": str(e)}
        if verbose:
            print(f"  Warning: sync failed ({e}) — node_2 may not be running.")

    if verbose:
        print("\n[Step 4] Validating chain after recovery...")
    result_recovered = validate_node(node_1)
    summary["after_recovery"] = result_recovered
    if verbose:
        if result_recovered.get("valid"):
            print(f"  ✓ Chain RESTORED and VALID ({result_recovered.get('blocks')} blocks)")
        else:
            print(f"  Chain still invalid: {result_recovered}")

    if verbose:
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"  Before tamper  : {'VALID' if summary['before_tamper'].get('valid') else 'INVALID'}")
        print(f"  After tamper   : {'VALID' if summary['after_tamper'].get('valid') else 'INVALID — ATTACK DETECTED'}")
        after_rec = summary.get("after_recovery", {})
        print(f"  After recovery : {'VALID' if after_rec.get('valid') else 'STILL INVALID'}")

    return summary

if __name__ == "__main__":
    run_tamper_demo(verbose=True)
