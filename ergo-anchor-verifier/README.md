# RustChain Ergo Anchor Verifier

Independent verification tool for RustChain-to-Ergo cross-chain anchors.

**Bounty:** #2278 — 100 RTC  
**Author:** kuanglaodi2-sudo  
**Wallet:** C4c7r9WPsnEe6CUfegMU9M7ReHD1pWg8qeSfTBoRcLbg

---

## What It Does

Verifies the integrity of RustChain-to-Ergo cross-chain anchors by performing a 3-way comparison:

1. **Stored commitment** — Blake2b-256 hash in `rustchain_v2.db`'s `ergo_anchors` table
2. **On-chain commitment** — R4 register value from the actual Ergo transaction
3. **Recomputed commitment** — Blake2b-256 of canonical JSON derived from `miner_attest_recent`

```
Anchor #1: TX 731d5d87... | Commitment MATCH | 10 miners | Epoch 424
Anchor #2: TX a8f3c912... | Commitment MISMATCH | Expected: abc123... Got: def456...
Summary: 47/50 anchors verified, 3 mismatches found
```

---

## Installation

```bash
pip install -r requirements.txt  # (verify_anchors.py is dependency-free, stdlib only)
python verify_anchors.py --help
```

---

## Usage

### Online mode (requires Ergo node)

```bash
python verify_anchors.py \
    --db /root/rustchain/rustchain_v2.db \
    --node http://localhost:9053 \
    --ergo-key your-api-key \
    --limit 50
```

### Offline mode (DB dump + pre-exported TX JSON)

```bash
python verify_anchors.py \
    --db rustchain_v2.db \
    --offline ./ergo_exports/ \
    --output json
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/root/rustchain/rustchain_v2.db` | Path to RustChain DB |
| `ERGO_NODE_URL` | `http://localhost:9053` | Ergo node URL |
| `ERGO_API_KEY` | _(empty)_ | Ergo node API key |

---

## Architecture

```
rustchain_v2.db
├── ergo_anchors         ← anchor records (tx_id, commitment, miner_count, rc_slot)
└── miner_attest_recent  ← per-epoch attestations (miner, device_arch, rtc_earned)

Ergo Node API (localhost:9053)
└── /transactions/{tx_id} ← on-chain TX with R4 register

verify_anchors.py
├── blake2b_256()        ← Blake2b-256 hash (stdlib hashlib)
├── MerkleTree           ← Merkle root computation
├── ErgoNodeClient       ← Lightweight HTTP client for Ergo API
└── AnchorVerifier       ← 3-way comparison logic
```

### Commitment recomputation

```python
# Commitment = Blake2b256(canonical_json({
#     "rc_height": rc_slot * 600,
#     "rc_hash": blake2b_256(f"{rc_height}:{attestations_root}")[:16],
#     "state_root": ...,
#     "attestations_root": MerkleTree.commit_items(
#         [blake2b_256(miner.encode()) for miner in attestations]
#     ),
#     "timestamp": created_at * 1000
# }))
```

### On-chain R4 extraction

```python
tx = ergo.get_transaction(tx_id)
r4 = tx["outputs"][0]["additionalRegisters"]["R4"]["serializedValue"]
# Format: 0e20<64 hex chars> for 32-byte Coll[Byte]
commitment = r4[4:]  # strip 0e20 prefix
```

---

## Offline CI Testing

Pre-export Ergo transactions for CI:

```bash
mkdir ergo_exports
for txid in $(sqlite3 rustchain_v2.db "SELECT tx_id FROM ergo_anchors"); do
    curl -s "http://localhost:9053/transactions/$txid" > "ergo_exports/$txid.json"
done

python verify_anchors.py --db rustchain_v2.db --offline ergo_exports/ --output json
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All anchors verified, no mismatches |
| 1 | One or more mismatches or errors found |

---

## Requirements

- Python 3.9+
- `requests` (optional — built-in `urllib` used by default)
- Access to `rustchain_v2.db` and Ergo node (or pre-exported TX JSON)

---

## Files

| File | Description |
|------|-------------|
| `verify_anchors.py` | Main verification tool (20KB) |
| `test_verify_anchors.py` | Unit tests |
| `README.md` | This file |
