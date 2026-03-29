# SPDX-License-Identifier: Apache-2.0
"""
generate_data.py — Generate realistic mock attestation data for RustChain Fossil Record.
Spans epochs 1–1000 with ~500 records, mixed architectures.
"""

import random
import json
from datetime import datetime, timedelta

# Architecture definitions: (name, first_epoch, color, base_rtc, miner_count_range)
ARCHITECTURES = [
    {
        "id": "68K",
        "name": "68K",
        "first_epoch": 1,
        "color": "#8B4500",      # dark amber
        "base_rtc": 12.0,
        "miners": ["m68k-α", "m68k-β", "m68k-γ", "m68k-δ", "m68k-ε"],
        "devices": ["Macintosh II", "Amiga 500", "Atari ST", "Sharp X68000", "Apple Lisa"],
    },
    {
        "id": "G3G4",
        "name": "G3/G4",
        "first_epoch": 15,
        "color": "#B87333",      # warm copper
        "base_rtc": 18.5,
        "miners": ["g3-α", "g3-β", "g4-α", "g4-β", "g4-γ", "ppc-α"],
        "devices": ["Power Macintosh G3", "PowerBook G3", "iMac G3", "Power Macintosh G4"],
    },
    {
        "id": "G5",
        "name": "G5",
        "first_epoch": 120,
        "color": "#CD7F32",      # bronze
        "base_rtc": 25.0,
        "miners": ["g5-α", "g5-β", "g5-γ", "g5-δ", "ppc970-α"],
        "devices": ["Power Mac G5", "iMac G5", "Xserve G5"],
    },
    {
        "id": "SPARC",
        "name": "SPARC",
        "first_epoch": 80,
        "color": "#DC143C",      # crimson
        "base_rtc": 22.0,
        "miners": ["sparc-α", "sparc-β", "sparc-ultra", "sparc-iii"],
        "devices": ["Sun Ultra 5", "Sun Blade 100", "SunFire V240", "SPARCstation 20"],
    },
    {
        "id": "MIPS",
        "name": "MIPS",
        "first_epoch": 50,
        "color": "#00A86B",      # jade
        "base_rtc": 16.5,
        "miners": ["mips-α", "mips-β", "mips-r12k", "mips-r10k", "mips-20kc"],
        "devices": ["SGI Indy", "SGI Octane", "DECstation 5000", "PlayStation 2 (Emul)"],
    },
    {
        "id": "POWER8",
        "name": "POWER8",
        "first_epoch": 300,
        "color": "#1E3A5F",      # deep blue
        "base_rtc": 35.0,
        "miners": ["p8-α", "p8-β", "p8-γ", "p8-delta", "ibm-power8-α"],
        "devices": ["IBM Power System S812L", "IBM Power System S822L", "Talos II", "OpenPOWER"],
    },
    {
        "id": "APPLE_SILICON",
        "name": "Apple Silicon",
        "first_epoch": 550,
        "color": "#A8A9AD",      # silver
        "base_rtc": 48.0,
        "miners": ["m1-α", "m1-β", "m1max-α", "m2-α", "m2-β", "m3-α", "apple-silicon-α"],
        "devices": ["MacBook Air M1", "Mac Studio M1 Max", "Mac Mini M2", "MacBook Pro M3"],
    },
    {
        "id": "X86",
        "name": "Modern x86",
        "first_epoch": 200,
        "color": "#C0C0C0",      # pale grey
        "base_rtc": 42.0,
        "miners": ["x86-α", "x86-β", "x86-avx2", "x86-avx512", "x86-zen3-α", "x86-skylake-β", "x86-haswell-γ"],
        "devices": ["AMD Ryzen 9 5950X", "Intel Core i9-13900K", "AMD EPYC 7763", "Intel Xeon Scalable"],
    },
]

# Settlement epochs (every 50 epochs)
SETTLEMENT_EPOCHS = list(range(50, 1001, 50))

# Epoch timestamps (mock): epoch N started at mock_datetime + (N * 4 hours)
MOCK_BASE_TIME = datetime(2024, 1, 1, 0, 0, 0)

def epoch_to_timestamp(epoch):
    return int((MOCK_BASE_TIME + timedelta(hours=epoch * 4)).timestamp())

def generate_attestations():
    attestations = []
    attestation_id = 1

    for epoch in range(1, 1001):
        # Determine which architectures are active at this epoch
        active_archs = [a for a in ARCHITECTURES if epoch >= a["first_epoch"]]

        for arch in active_archs:
            # Each arch has a random subset of miners active per epoch
            num_active = random.randint(1, min(len(arch["miners"]), random.randint(1, 5)))

            for _ in range(num_active):
                miner = random.choice(arch["miners"])
                device = random.choice(arch["devices"])

                # Quality degrades slightly for older archs
                quality_base = 0.85 + random.random() * 0.15
                if arch["id"] in ("68K", "MIPS", "SPARC"):
                    quality_base = 0.65 + random.random() * 0.25

                rtc_earned = round(arch["base_rtc"] * (0.8 + random.random() * 0.4) * quality_base, 4)

                # Fingerprint quality
                fp_quality = round(quality_base + random.uniform(-0.05, 0.05), 3)
                fp_quality = max(0.5, min(1.0, fp_quality))

                attestations.append({
                    "id": f"att-{attestation_id:05d}",
                    "epoch": epoch,
                    "timestamp": epoch_to_timestamp(epoch),
                    "miner_id": miner,
                    "architecture": arch["id"],
                    "architecture_name": arch["name"],
                    "device": device,
                    "rtc_earned": rtc_earned,
                    "fingerprint_quality": fp_quality,
                    "quality_score": round(quality_base, 3),
                    "color": arch["color"],
                })
                attestation_id += 1

    return attestations

def generate_miner_stats(attestations):
    """Aggregate stats per miner across all epochs."""
    miner_map = {}
    for att in attestations:
        mid = att["miner_id"]
        if mid not in miner_map:
            miner_map[mid] = {
                "miner_id": mid,
                "architecture": att["architecture"],
                "architecture_name": att["architecture_name"],
                "device": att["device"],
                "total_rtc": 0.0,
                "total_attestations": 0,
                "avg_quality": [],
                "epochs_active": set(),
                "color": att["color"],
            }
        miner_map[mid]["total_rtc"] += att["rtc_earned"]
        miner_map[mid]["total_attestations"] += 1
        miner_map[mid]["avg_quality"].append(att["quality_score"])
        miner_map[mid]["epochs_active"].add(att["epoch"])

    stats = []
    for m in miner_map.values():
        stats.append({
            "miner_id": m["miner_id"],
            "architecture": m["architecture"],
            "architecture_name": m["architecture_name"],
            "device": m["device"],
            "total_rtc": round(m["total_rtc"], 4),
            "total_attestations": m["total_attestations"],
            "unique_epochs": len(m["epochs_active"]),
            "avg_quality": round(sum(m["avg_quality"]) / len(m["avg_quality"]), 3),
            "first_epoch": min(m["epochs_active"]),
            "last_epoch": max(m["epochs_active"]),
            "color": m["color"],
        })
    return stats

def generate_epoch_aggregates(attestations):
    """Aggregate attestations per epoch per architecture."""
    epoch_arch_map = {}
    for att in attestations:
        key = (att["epoch"], att["architecture"])
        if key not in epoch_arch_map:
            epoch_arch_map[key] = {
                "epoch": att["epoch"],
                "architecture": att["architecture"],
                "architecture_name": att["architecture_name"],
                "active_miners": set(),
                "total_rtc": 0.0,
                "attestation_count": 0,
                "avg_quality": [],
                "color": att["color"],
            }
        epoch_arch_map[key]["active_miners"].add(att["miner_id"])
        epoch_arch_map[key]["total_rtc"] += att["rtc_earned"]
        epoch_arch_map[key]["attestation_count"] += 1
        epoch_arch_map[key]["avg_quality"].append(att["quality_score"])

    aggregates = []
    for v in epoch_arch_map.values():
        aggregates.append({
            "epoch": v["epoch"],
            "architecture": v["architecture"],
            "architecture_name": v["architecture_name"],
            "active_miner_count": len(v["active_miners"]),
            "total_rtc": round(v["total_rtc"], 4),
            "attestation_count": v["attestation_count"],
            "avg_quality": round(sum(v["avg_quality"]) / len(v["avg_quality"]), 3),
            "color": v["color"],
        })
    return aggregates

def main():
    print("Generating attestation data...")
    attestations = generate_attestations()
    print(f"Generated {len(attestations)} attestation records")

    miner_stats = generate_miner_stats(attestations)
    print(f"Generated stats for {len(miner_stats)} unique miners")

    epoch_aggregates = generate_epoch_aggregates(attestations)
    print(f"Generated {len(epoch_aggregates)} epoch-architecture aggregates")

    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_attestations": len(attestations),
        "total_miners": len(miner_stats),
        "epoch_range": {"min": 1, "max": 1000},
        "settlement_epochs": SETTLEMENT_EPOCHS,
        "architectures": [
            {
                "id": a["id"],
                "name": a["name"],
                "first_epoch": a["first_epoch"],
                "color": a["color"],
            }
            for a in ARCHITECTURES
        ],
        "attestations": attestations,
        "miner_stats": miner_stats,
        "epoch_aggregates": epoch_aggregates,
    }

    output_path = "attestation_data.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Data saved to {output_path}")
    return data

if __name__ == "__main__":
    main()
