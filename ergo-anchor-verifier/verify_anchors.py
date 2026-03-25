#!/usr/bin/env python3
"""
RustChain Ergo Anchor Verifier
==============================
Independent verification tool for RustChain-to-Ergo cross-chain anchors.

Verifies that:
1. The stored commitment hash matches the on-chain Ergo TX R4 register
2. The on-chain commitment matches the locally recomputed commitment
3. Reports any discrepancies with detailed evidence

Usage:
    python verify_anchors.py [--db PATH] [--node URL] [--ergo-key KEY] [--output FORMAT]

Database schema (ergo_anchors):
    id, tx_id, commitment, miner_count, rc_slot, created_at

Author: kuanglaodi2-sudo (RustChain Bounty #2278)
Wallet: C4c7r9WPsnEe6CUfegMU9M7ReHD1pWg8qeSfTBoRcLbg
"""

import os
import sys
import json
import hashlib
import argparse
import sqlite3
import logging
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [VERIFY] %(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Blake2b-256 ──────────────────────────────────────────────────────────────

def blake2b_256(data: bytes) -> str:
    """Compute Blake2b-256 hash (64 hex chars)."""
    return hashlib.blake2b(data, digest_size=32).hexdigest()

def canonical_json(obj: Any) -> bytes:
    """Canonical JSON serialization (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def blake2b256_hex(obj: Any) -> str:
    """Blake2b-256 of canonical JSON serialization."""
    return blake2b_256(canonical_json(obj))

# ─── Merkle Tree ───────────────────────────────────────────────────────────────

class MerkleTree:
    """Simple Merkle tree for computing root hashes."""

    @staticmethod
    def _hash_pair(a: str, b: str) -> str:
        """Hash two values in sorted order."""
        if a < b:
            return blake2b_256((a + b).encode())
        return blake2b_256((b + a).encode())

    @classmethod
    def root(cls, items: List[str]) -> str:
        """Compute Merkle root of a list of hex strings."""
        if not items:
            return blake2b_256(b"")
        layer = list(items)
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            new_layer = []
            for i in range(0, len(layer), 2):
                new_layer.append(cls._hash_pair(layer[i], layer[i + 1]))
            layer = new_layer
        return layer[0]

    @classmethod
    def commit_items(cls, items: List[str]) -> str:
        """Alias for root — compute commitment from items."""
        return cls.root(items)

# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class AnchorRecord:
    """A single anchor record from the ergo_anchors table."""
    id: int
    tx_id: str
    commitment: str
    miner_count: int
    rc_slot: int
    created_at: int

    @classmethod
    def from_row(cls, row: Tuple) -> "AnchorRecord":
        return cls(id=row[0], tx_id=row[1], commitment=row[2],
                    miner_count=row[3], rc_slot=row[4], created_at=row[5])


@dataclass
class VerificationResult:
    """Result of verifying a single anchor."""
    anchor_id: int
    tx_id: str
    rc_slot: int
    stored_commitment: str
    onchain_commitment: Optional[str]
    recomputed_commitment: Optional[str]
    miner_count: int
    status: str  # MATCH | MISMATCH | ERROR
    error: Optional[str] = None
    details: Optional[Dict] = None

    def __str__(self) -> str:
        tx_short = self.tx_id[:10] + "..." if self.tx_id else "N/A"
        if self.status == "MATCH":
            return (f"Anchor #{self.anchor_id}: TX {tx_short} | "
                    f"Commitment MATCH | {self.miner_count} miners | "
                    f"Epoch {self.rc_slot}")
        elif self.status == "MISMATCH":
            return (f"Anchor #{self.anchor_id}: TX {tx_short} | "
                    f"Commitment MISMATCH | Expected: {self.recomputed_commitment or '?'} | "
                    f"Got: {self.onchain_commitment or '?'} | {self.error or ''}")
        else:
            return (f"Anchor #{self.anchor_id}: TX {tx_short} | "
                    f"ERROR: {self.error}")


# ─── Ergo Node Client ──────────────────────────────────────────────────────────

class ErgoNodeClient:
    """Lightweight Ergo node API client (no external deps)."""

    def __init__(self, node_url: str, api_key: str = ""):
        self.node_url = node_url.rstrip("/")
        self.api_key = api_key
        self.session_header = "api_key"

    def _request(self, endpoint: str, method: str = "GET",
                 data: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request to Ergo node API."""
        url = f"{self.node_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.session_header] = self.api_key

        try:
            if method == "GET":
                req = Request(url, headers=headers)
            else:
                req = Request(url, data=json.dumps(data).encode(),
                              headers=headers, method=method)

            with urlopen(req, timeout=30) as resp:
                if resp.status == 200 or resp.status == 201:
                    return json.loads(resp.read().decode())
                logger.error(f"Ergo API {endpoint} returned {resp.status}")
                return None
        except HTTPError as e:
            logger.error(f"HTTP {e.code} for {endpoint}: {e.reason}")
            return None
        except URLError as e:
            logger.error(f"URL error for {endpoint}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"Request error for {endpoint}: {e}")
            return None

    def get_transaction(self, tx_id: str) -> Optional[Dict]:
        """Fetch a transaction by ID."""
        return self._request(f"/transactions/{tx_id}")

    def get_box(self, box_id: str) -> Optional[Dict]:
        """Fetch a box (UTXO) by ID."""
        return self._request(f"/boxes/{box_id}")

    def get_epoch_height(self) -> Optional[int]:
        """Get current Ergo blockchain height."""
        info = self._request("/info")
        if info:
            return info.get("fullHeight")
        return None


# ─── Anchor Verification ───────────────────────────────────────────────────────

class AnchorVerifier:
    """
    Verifies RustChain Ergo anchors by:
    1. Reading anchor records from local DB
    2. Fetching commitment from Ergo TX on-chain
    3. Recomputing commitment from miner_attest_recent
    4. Comparing all three
    """

    def __init__(self, db_path: str, ergo_client: ErgoNodeClient):
        self.db_path = db_path
        self.ergo = ergo_client
        self._conn: Optional[sqlite3.Connection] = None

    # ── Database access ───────────────────────────────────────────────────────

    def _connect(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def read_anchors(self, limit: Optional[int] = None,
                     start_slot: Optional[int] = None) -> List[AnchorRecord]:
        """Read anchor records from ergo_anchors table."""
        conn = self._connect()
        cur = conn.cursor()
        query = "SELECT id, tx_id, commitment, miner_count, rc_slot, created_at FROM ergo_anchors"
        params: List[Any] = []
        if start_slot is not None:
            query += " WHERE rc_slot >= ?"
            params.append(start_slot)
        query += " ORDER BY rc_slot ASC"
        if limit is not None:
            query += f" LIMIT {limit}"  # safe: limit is int
        cur.execute(query, params)
        return [AnchorRecord.from_row(row) for row in cur.fetchall()]

    def read_epoch_attestations(self, rc_slot: int) -> List[Dict]:
        """
        Read attestations from miner_attest_recent for a given epoch/slot.
        Returns list of attestation dicts with 'miner' and other fields.
        """
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT miner, device_arch, rtc_earned, attested_at FROM miner_attest_recent "
            "WHERE rc_slot = ? ORDER BY miner",
            (rc_slot,)
        )
        rows = cur.fetchall()
        return [
            {"miner": r[0], "device_arch": r[1], "rtc_earned": r[2], "attested_at": r[3]}
            for r in rows
        ]

    def get_state_root(self, rc_slot: int) -> Optional[str]:
        """Get state root for an epoch from local DB (if available)."""
        conn = self._connect()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT state_root FROM epoch_state WHERE rc_slot = ?",
                (rc_slot,)
            )
            row = cur.fetchone()
            if row:
                return row[0]
        except sqlite3.OperationalError:
            pass  # table may not exist
        return None

    # ── Commitment recomputation ───────────────────────────────────────────────

    def recompute_commitment(self, anchor: AnchorRecord,
                              attestations: List[Dict]) -> str:
        """
        Recompute the Blake2b-256 commitment for an anchor.

        Commitment fields:
        - rc_height: RustChain block height (from rc_slot * blocks_per_epoch)
        - rc_hash: hash of block at that height
        - state_root: Merkle root of state (from epoch_state or derived)
        - attestations_root: Merkle root of miner attestations
        - timestamp: Unix timestamp ms from anchor record
        """
        # rc_height: approximate as rc_slot * 600 (600 blocks per epoch)
        rc_height = anchor.rc_slot * 600

        # rc_hash: derive from attestations root + slot (deterministic)
        # We use a standard derivation: blake2b(slot || attestations_root)
        att_hashes = [blake2b_256(a["miner"].encode()) for a in attestations]
        attestations_root = MerkleTree.commit_items(att_hashes) if att_hashes else blake2b_256(b"empty")

        # state_root: try from DB, else derive from attestations
        state_root = self.get_state_root(anchor.rc_slot)
        if not state_root:
            # Fallback: hash attestations_root with slot for deterministic derivation
            state_root = blake2b_256(f"{anchor.rc_slot}:{attestations_root}".encode())

        # timestamp: convert created_at (seconds) to ms
        timestamp_ms = anchor.created_at * 1000

        # Build commitment data
        data = {
            "rc_height": rc_height,
            "rc_hash": blake2b_256(f"{rc_height}:{attestations_root}".encode())[:16],
            "state_root": state_root,
            "attestations_root": attestations_root,
            "timestamp": timestamp_ms
        }
        return blake2b256_hex(data)

    # ── On-chain R4 extraction ────────────────────────────────────────────────

    def fetch_onchain_commitment(self, tx_id: str) -> Optional[str]:
        """
        Fetch the commitment hash stored in R4 register of the Ergo TX output.

        The commitment is stored as R4 register in the first output box.
        R4 contains: Coll[Byte] serialised as base16.
        """
        tx = self.ergo.get_transaction(tx_id)
        if not tx:
            return None

        # Get outputs (boxes)
        outputs = tx.get("outputs", [])
        if not outputs:
            logger.warning(f"TX {tx_id[:10]}... has no outputs")
            return None

        # First output typically holds the commitment
        box = outputs[0]
        registers = box.get("additionalRegisters", {})
        r4 = registers.get("R4")

        if not r4:
            logger.warning(f"TX {tx_id[:10]}... has no R4 register")
            return None

        # R4 is stored as Coll[Byte] = base16 encoded bytes
        # Format: 0e20<64 hex chars> for a 32-byte Coll[Byte]
        r4_val = r4.get("serializedValue", "")
        if r4_val.startswith("0e20"):
            # 0e = Coll type, 20 = 32 bytes, followed by 64 hex chars
            return r4_val[4:]
        elif len(r4_val) == 64:
            # Direct hex
            return r4_val
        else:
            # Try to decode as-is
            return r4_val

    # ── Core verification ─────────────────────────────────────────────────────

    def verify_anchor(self, anchor: AnchorRecord) -> VerificationResult:
        """Verify a single anchor record."""
        # Fetch on-chain commitment
        onchain = self.fetch_onchain_commitment(anchor.tx_id)

        # Read attestations from local DB
        attestations = self.read_epoch_attestations(anchor.rc_slot)

        # Recompute
        recomputed = None
        if attestations:
            recomputed = self.recompute_commitment(anchor, attestations)
        else:
            logger.warning(f"No attestations found for slot {anchor.rc_slot}")

        # Compare
        stored = anchor.commitment

        if onchain is None:
            return VerificationResult(
                anchor_id=anchor.id, tx_id=anchor.tx_id, rc_slot=anchor.rc_slot,
                stored_commitment=stored, onchain_commitment=None,
                recomputed_commitment=recomputed,
                miner_count=anchor.miner_count,
                status="ERROR",
                error="Could not fetch on-chain commitment"
            )

        # 3-way comparison
        match_stored_onchain = (stored == onchain)
        match_onchain_recomputed = (onchain == recomputed)

        if match_stored_onchain and match_onchain_recomputed:
            status = "MATCH"
            error = None
        else:
            status = "MISMATCH"
            reasons = []
            if not match_stored_onchain:
                reasons.append(f"stored != on-chain (stored={stored[:16]}..., on-chain={onchain[:16]}...)")
            if not match_onchain_recomputed:
                reasons.append(f"on-chain != recomputed (on-chain={onchain[:16] if onchain else '?'}..., recomputed={recomputed[:16] if recomputed else '?'}...)")
            error = "; ".join(reasons)

        return VerificationResult(
            anchor_id=anchor.id, tx_id=anchor.tx_id, rc_slot=anchor.rc_slot,
            stored_commitment=stored, onchain_commitment=onchain,
            recomputed_commitment=recomputed,
            miner_count=anchor.miner_count,
            status=status,
            error=error,
            details={
                "stored": stored,
                "onchain": onchain,
                "recomputed": recomputed,
                "match_stored_onchain": match_stored_onchain,
                "match_onchain_recomputed": match_onchain_recomputed,
                "attestation_count": len(attestations),
            }
        )

    def verify_all(self, limit: Optional[int] = None,
                   start_slot: Optional[int] = None) -> List[VerificationResult]:
        """Verify all anchors."""
        anchors = self.read_anchors(limit=limit, start_slot=start_slot)
        logger.info(f"Verifying {len(anchors)} anchors from DB: {self.db_path}")
        results: List[VerificationResult] = []
        for anchor in anchors:
            result = self.verify_anchor(anchor)
            results.append(result)
            print(result)
        return results


# ─── Summary Report ────────────────────────────────────────────────────────────

def print_summary(results: List[VerificationResult]):
    """Print summary of verification results."""
    total = len(results)
    matches = sum(1 for r in results if r.status == "MATCH")
    mismatches = sum(1 for r in results if r.status == "MISMATCH")
    errors = sum(1 for r in results if r.status == "ERROR")

    print()
    print("=" * 70)
    print("ANCHOR VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total anchors verified: {total}")
    print(f"  Commitment MATCH:    {matches} ({100*matches//total if total else 0}%)")
    print(f"  Commitment MISMATCH: {mismatches} ({100*mismatches//total if total else 0}%)")
    print(f"  Errors:             {errors} ({100*errors//total if total else 0}%)")
    print()

    if mismatches > 0:
        print("MISMATCH DETAILS:")
        for r in results:
            if r.status == "MISMATCH":
                print(f"  #{r.anchor_id} | TX {r.tx_id[:10]}... | Epoch {r.rc_slot}")
                if r.error:
                    print(f"    Reason: {r.error}")

    if errors > 0:
        print("ERROR DETAILS:")
        for r in results:
            if r.status == "ERROR":
                print(f"  #{r.anchor_id} | TX {r.tx_id[:10]}... | {r.error}")


def export_json(results: List[VerificationResult], path: str):
    """Export results as JSON."""
    with open(path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"Results exported to {path}")


# ─── Offline DB Mode ──────────────────────────────────────────────────────────

def offline_mode(db_path: str, ergo_export_dir: str,
                 output: str = "text") -> List[VerificationResult]:
    """
    Offline verification mode: uses a DB dump and pre-fetched Ergo TX data.

    Expects:
        ergo_export_dir/
            <tx_id>.json   # Ergo transaction JSON for each TX
    """
    class OfflineClient:
        def __init__(self, export_dir: str):
            self.export_dir = export_dir

        def get_transaction(self, tx_id: str) -> Optional[Dict]:
            path = os.path.join(self.export_dir, f"{tx_id}.json")
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
            return None

        def get_box(self, box_id: str) -> Optional[Dict]:
            return None  # not needed in offline mode

        def get_epoch_height(self) -> Optional[int]:
            return None

    offline_client = OfflineClient(ergo_export_dir)
    verifier = AnchorVerifier(db_path, offline_client)

    anchors = verifier.read_anchors()
    results = []
    for anchor in anchors:
        result = verifier.verify_anchor(anchor)
        results.append(result)
        print(result)

    verifier.close()
    print_summary(results)

    if output == "json":
        export_json(results, "anchor_verification_results.json")

    return results


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Verify RustChain-to-Ergo anchor commitments"
    )
    parser.add_argument(
        "--db", default=os.environ.get("DB_PATH", "/root/rustchain/rustchain_v2.db"),
        help="Path to rustchain_v2.db (default: /root/rustchain/rustchain_v2.db)"
    )
    parser.add_argument(
        "--node", default=os.environ.get("ERGO_NODE_URL", "http://localhost:9053"),
        help="Ergo node URL (default: http://localhost:9053)"
    )
    parser.add_argument(
        "--ergo-key", default=os.environ.get("ERGO_API_KEY", ""),
        help="Ergo node API key"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Limit number of anchors to verify"
    )
    parser.add_argument(
        "--start-slot", type=int, default=None,
        help="Start from this rc_slot/epoch"
    )
    parser.add_argument(
        "--output", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--offline", metavar="EXPORT_DIR",
        help="Offline mode: path to pre-exported Ergo TX JSON files"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.offline:
        print(f"[OFFLINE MODE] DB: {args.db} | Export dir: {args.offline}")
        results = offline_mode(args.db, args.offline, args.output)
    else:
        client = ErgoNodeClient(args.node, args.ergo_key)
        verifier = AnchorVerifier(args.db, client)

        # Test connection
        height = client.get_epoch_height()
        if height:
            print(f"Connected to Ergo node at {args.node}, height: {height}")
        else:
            logger.warning("Could not connect to Ergo node — will use local DB only")

        results = verifier.verify_all(limit=args.limit, start_slot=args.start_slot)
        verifier.close()

    print_summary(results)

    if args.output == "json":
        export_json(results, "anchor_verification_results.json")

    # Exit code: 0 if all match, 1 if any mismatch or error
    mismatches = sum(1 for r in results if r.status != "MATCH")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
