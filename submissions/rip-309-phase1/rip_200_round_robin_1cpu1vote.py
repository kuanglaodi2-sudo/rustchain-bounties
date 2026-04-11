"""
RIP-309 Phase 1: Fingerprint Check Rotation
==========================================
Rotates which 4 of 6 hardware fingerprint checks count toward rewards each epoch,
using a block-hash-derived nonce to prevent Goodhart's Law from hollowing out
trust metrics.

Bounty #3008 — 50 RTC
"""

import hashlib
import random
import logging

# All 6 fingerprint checks
FP_CHECKS = [
    'clock_drift',
    'cache_timing',
    'simd_bias',
    'thermal_drift',
    'instruction_jitter',
    'anti_emulation',
]


def get_active_fp_checks(prev_block_hash: bytes) -> list:
    """
    Select 4 of 6 fingerprint checks using a nonce derived from the previous
    block hash. Selection is fully deterministic: same block hash always
    produces the same active set.

    Args:
        prev_block_hash: The block hash of the previous epoch (bytes).

    Returns:
        List of 4 check names from FP_CHECKS.
    """
    nonce = hashlib.sha256(prev_block_hash + b"measurement_nonce").digest()
    seed = int.from_bytes(nonce[:4], 'big')
    active = random.Random(seed).sample(FP_CHECKS, 4)
    return active


def compute_fp_reward_weight(check_name: str, active_checks: list) -> float:
    """
    Returns the weight for a fingerprint check in reward calculation.
    Active checks get weight 1.0; inactive checks get 0.0 (but still run/log).

    Args:
        check_name: One of the six FP_CHECKS names.
        active_checks: List of currently active check names.

    Returns:
        1.0 if check is active, 0.0 otherwise.
    """
    return 1.0 if check_name in active_checks else 0.0


def run_fp_check_with_rotation(check_name: str, prev_block_hash: bytes,
                               *, active_checks: list = None,
                               log_all: bool = True) -> dict:
    """
    Runs a single fingerprint check, applying epoch rotation.

    All 6 checks still execute and log results. Only the 4 active checks
    contribute to the epoch reward weight.

    Args:
        check_name: The fingerprint check to run.
        prev_block_hash: Block hash used to derive the epoch's active set.
        active_checks: Pre-computed active check list (optional).
        log_all: Whether to log inactive check results.

    Returns:
        dict with keys: check, active, weight, result, passed
    """
    if active_checks is None:
        active_checks = get_active_fp_checks(prev_block_hash)

    is_active = check_name in active_checks
    weight = 1.0 if is_active else 0.0

    # Simulate check execution (replace with actual check logic)
    result = _execute_check(check_name)
    passed = result.get('passed', False)

    entry = {
        'check': check_name,
        'active': is_active,
        'weight': weight,
        'result': result,
        'passed': passed,
    }

    if log_all:
        status = "ACTIVE" if is_active else "INACTIVE"
        logging.info(
            f"[RIP-309] {status} check '{check_name}': "
            f"weight={weight}, passed={passed}"
        )

    return entry


def _execute_check(check_name: str) -> dict:
    """
    Placeholder for actual hardware fingerprint check execution.
    Replace with real check implementations.
    """
    # TODO: integrate real hardware fingerprint check functions here.
    # Each check should return {'passed': bool, 'value': float, ...}
    return {'passed': True, 'value': 1.0}


def compute_epoch_reward(entries: list, base_reward: float) -> float:
    """
    Compute the epoch reward using only the 4 active (weighted=1) checks.

    Args:
        entries: List of dicts from run_fp_check_with_rotation().
        base_reward: Base reward amount before FP weighting.

    Returns:
        Adjusted reward for the epoch.
    """
    active_count = sum(1 for e in entries if e['weight'] == 1.0 and e['passed'])
    inactive_count = sum(1 for e in entries if e['weight'] == 0.0)

    logging.info(
        f"[RIP-309] Epoch reward: {active_count}/4 active checks passed, "
        f"{inactive_count} inactive checks logged but not weighted. "
        f"Base reward: {base_reward}"
    )

    if active_count == 0:
        return 0.0

    return base_reward


# ─── Epoch Integration ───────────────────────────────────────────────────────

def settle_epoch_with_rotation(prev_block_hash: bytes, base_reward: float) -> dict:
    """
    Full epoch settlement with RIP-309 fingerprint rotation.

    Args:
        prev_block_hash: Hash of the previous block (used as nonce seed).
        base_reward: Base reward before FP adjustment.

    Returns:
        dict with active_checks, entries, adjusted_reward, and nonce_hex.
    """
    active_checks = get_active_fp_checks(prev_block_hash)
    nonce = hashlib.sha256(prev_block_hash + b"measurement_nonce").digest()

    logging.info(f"[RIP-309] Active FP checks for epoch (nonce={nonce.hex()[:8]}...): {active_checks}")

    entries = [
        run_fp_check_with_rotation(name, prev_block_hash, active_checks=active_checks)
        for name in FP_CHECKS
    ]

    adjusted_reward = compute_epoch_reward(entries, base_reward)

    return {
        'nonce_hex': nonce.hex(),
        'active_checks': active_checks,
        'entries': entries,
        'adjusted_reward': adjusted_reward,
    }
