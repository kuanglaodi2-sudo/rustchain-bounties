"""
RIP-309 Phase 1 Integration — Epoch Settlement Pass
====================================================
Modifies rustchain_v2_integrated_v2.2.1_rip200.py to pass the previous
block hash (nonce) to the fingerprint measurement system so that
`get_active_fp_checks()` can derive its seed deterministically.

Bounty #3008 — 50 RTC
"""

import hashlib
import logging


def settle_epoch(prev_block_hash: bytes, base_reward: float) -> dict:
    """
    Modified epoch settlement that passes the previous block hash to
    the fingerprint rotation system, enabling nonce-based selection
    of the active 4-of-6 checks.

    Args:
        prev_block_hash: The full block hash of the previous epoch (bytes).
        base_reward: Base reward before fingerprint adjustment.

    Returns:
        dict with epoch settlement result.
    """
    # Derive the measurement nonce from the previous block hash
    # This nonce is the same seed used by get_active_fp_checks()
    nonce = hashlib.sha256(prev_block_hash + b"measurement_nonce").digest()

    logging.info(
        f"[RIP-309] Epoch settlement: nonce={nonce.hex()[:12]}..., "
        f"prev_block_hash={prev_block_hash.hex()[:16]}..."
    )

    # Import the rotation logic from rip_200_round_robin_1cpu1vote
    try:
        from rip_200_round_robin_1cpu1vote import (
            settle_epoch_with_rotation,
            get_active_fp_checks,
        )

        result = settle_epoch_with_rotation(prev_block_hash, base_reward)
        result['nonce'] = nonce.hex()
        return result

    except ImportError:
        # Fallback: if the rotation module isn't available yet,
        # log and return the nonce for later integration
        active_checks = _fallback_get_active_checks(nonce)
        logging.warning(
            f"[RIP-309] Rotation module not found. "
            f"Active checks (fallback): {active_checks}"
        )
        return {
            'nonce': nonce.hex(),
            'active_checks': active_checks,
            'adjusted_reward': base_reward,
            'note': 'RIP-309 rotation pending module integration',
        }


def _fallback_get_active_checks(nonce: bytes) -> list:
    """Fallback check selection if module import fails."""
    import random
    FP_CHECKS = [
        'clock_drift', 'cache_timing', 'simd_bias',
        'thermal_drift', 'instruction_jitter', 'anti_emulation',
    ]
    seed = int.from_bytes(nonce[:4], 'big')
    return random.Random(seed).sample(FP_CHECKS, 4)
