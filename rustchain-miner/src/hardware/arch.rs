/// Classify CPU brand string into (device_family, device_arch).
///
/// Returns (&str, &str) — the family (e.g. "PowerPC", "x86_64", "RISC-V")
/// and the architecture tier (e.g. "g4", "modern", "sifive_u74").
///
/// # RISC-V Support
///
/// RISC-V is an open ISA (Instruction Set Architecture) that has emerged
/// as a viable vintage computing platform starting ~2010. RISC-V hardware
/// is classified as EXOTIC with a 1.4x antiquity multiplier.
///
/// Supported RISC-V implementations:
/// - SiFive U74 / U54 / E51 (HiFive Unmatched / Freedom U740)
/// - StarFive JH7110 / JH7100 (VisionFive 2 / VisionFive v1)
/// - Allwinner D1 (Nezha board, single-core)
/// - T-Head C910 / C906 (high-performance RISC-V)
/// - Generic RISC-V 64-bit systems
pub fn classify(brand: &str) -> (&'static str, &'static str) {
    let lower = brand.to_lowercase();

    // ─────────────────────────────────────────────────────────────
    // RISC-V Detection (2010+ open ISA vintage hardware)
    // ─────────────────────────────────────────────────────────────
    if lower.contains("riscv")
        || lower.contains("sifive")
        || lower.contains("starfive")
        || lower.contains("visionfive")
        || lower.contains("hifive")
        || lower.contains("allwinner")
        || lower.contains("d1")
        || lower.contains("thead")
        || lower.contains("c910")
        || lower.contains("c906")
        || lower.contains(" kendryte")
    {
        // SiFive detection
        if lower.contains("sifive") {
            if lower.contains("u74") {
                return ("RISC-V", "sifive_u74");
            } else if lower.contains("u54") {
                return ("RISC-V", "sifive_u54");
            } else if lower.contains("e51") {
                return ("RISC-V", "sifive_e51");
            }
            return ("RISC-V", "sifive_generic");
        }

        // StarFive detection (VisionFive boards)
        if lower.contains("starfive") {
            if lower.contains("jh7110") {
                return ("RISC-V", "starfive_jh7110");
            } else if lower.contains("jh7100") {
                return ("RISC-V", "starfive_jh7100");
            }
            return ("RISC-V", "starfive_generic");
        }

        // VisionFive (standalone name)
        if lower.contains("visionfive") {
            return ("RISC-V", "visionfive");
        }

        // HiFive detection
        if lower.contains("hifive") {
            return ("RISC-V", "hifive");
        }

        // Allwinner D1 detection (Nezha SBC)
        if lower.contains("allwinner") || lower.contains("d1") || lower.contains("nezha") {
            return ("RISC-V", "allwinner_d1");
        }

        // T-Head C910 / C906 detection (high-performance)
        if lower.contains("thead") || lower.contains("c910") || lower.contains("c906") {
            return ("RISC-V", "thead_c910");
        }

        // Generic RISC-V fallback
        if lower.contains("64") || lower.contains("rv64") {
            return ("RISC-V", "riscv64_generic");
        }
        if lower.contains("32") || lower.contains("rv32") {
            return ("RISC-V", "riscv32_generic");
        }
        return ("RISC-V", "riscv_generic");
    }

    // ─────────────────────────────────────────────────────────────
    // PowerPC detection
    // ─────────────────────────────────────────────────────────────
    if lower.contains("7450") || lower.contains("7447") || lower.contains("7455") {
        return ("PowerPC", "g4");
    }
    if lower.contains("970") && (lower.contains("power") || lower.contains("apple")) {
        return ("PowerPC", "g5");
    }
    if lower.contains("750") && lower.contains("power") {
        return ("PowerPC", "g3");
    }
    if lower.contains("powerpc") || (lower.contains("power") && lower.contains("pc")) {
        if lower.contains("g4") {
            return ("PowerPC", "g4");
        }
        if lower.contains("g5") {
            return ("PowerPC", "g5");
        }
        if lower.contains("g3") {
            return ("PowerPC", "g3");
        }
        return ("PowerPC", "modern");
    }

    // ─────────────────────────────────────────────────────────────
    // Apple Silicon
    // ─────────────────────────────────────────────────────────────
    if lower.contains("apple m4") {
        return ("ARM", "apple_m4");
    }
    if lower.contains("apple m3") {
        return ("ARM", "apple_m3");
    }
    if lower.contains("apple m2") {
        return ("ARM", "apple_m2");
    }
    if lower.contains("apple m1") {
        return ("ARM", "apple_m1");
    }
    if lower.contains("apple") && lower.contains("silicon") {
        return ("ARM", "apple_silicon");
    }

    // ─────────────────────────────────────────────────────────────
    // Core 2 Duo (vintage x86_64)
    // ─────────────────────────────────────────────────────────────
    if lower.contains("core 2")
        || lower.contains("core2")
        || lower.contains("core(tm) 2")
        || lower.contains("core(tm)2")
    {
        return ("x86_64", "core2duo");
    }

    // ─────────────────────────────────────────────────────────────
    // ARM detection
    // ─────────────────────────────────────────────────────────────
    if lower.contains("aarch64") || lower.contains("arm") || lower.contains("cortex") {
        return ("ARM", "modern");
    }

    // ─────────────────────────────────────────────────────────────
    // Default: modern x86_64
    // ─────────────────────────────────────────────────────────────
    ("x86_64", "modern")
}

/// Get the antiquity multiplier for a given device_arch.
///
/// RISC-V platforms receive a 1.4x EXOTIC multiplier as they represent
/// open ISA vintage hardware from ~2010 onward with unique attestation
/// value due to their emerging heterogeneous ecosystem.
///
/// | Arch            | Multiplier | Category |
/// |-----------------|------------|----------|
/// | g4              | 2.5        | PowerPC  |
/// | g5              | 2.0        | PowerPC  |
/// | g3              | 1.8        | PowerPC  |
/// | core2duo        | 1.3        | x86_64   |
/// | apple_silicon   | 1.2        | ARM      |
/// | riscv_*         | 1.4        | RISC-V   |
/// | (all others)    | 1.0        | standard |
#[allow(dead_code)]
pub fn get_multiplier(device_arch: &str) -> f64 {
    match device_arch {
        // PowerPC vintage multipliers
        "g4" => 2.5,
        "g5" => 2.0,
        "g3" => 1.8,
        // x86 vintage
        "core2duo" => 1.3,
        // Apple Silicon
        "apple_m1" | "apple_m2" | "apple_m3" | "apple_m4" => 1.2,
        "apple_silicon" => 1.2,
        // RISC-V EXOTIC multiplier
        "sifive_u74" | "sifive_u54" | "sifive_e51" | "sifive_generic" => 1.4,
        "starfive_jh7110" | "starfive_jh7100" | "starfive_generic" => 1.4,
        "visionfive" => 1.4,
        "hifive" => 1.4,
        "allwinner_d1" => 1.4,
        "thead_c910" => 1.4,
        "riscv64_generic" | "riscv32_generic" | "riscv_generic" => 1.4,
        // Default
        _ => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────
    // RISC-V Detection Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_riscv_sifive_u74() {
        let (family, arch) = classify("SiFive U74-MC Processor");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "sifive_u74");
        assert!((get_multiplier(arch) - 1.4).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_riscv_sifive_u54() {
        let (family, arch) = classify("SiFive U54 Processor");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "sifive_u54");
    }

    #[test]
    fn test_classify_riscv_starfive_jh7110() {
        let (family, arch) = classify("StarFive JH7110");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "starfive_jh7110");
        assert!((get_multiplier(arch) - 1.4).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_riscv_starfive_jh7100() {
        let (family, arch) = classify("StarFive JH7100");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "starfive_jh7100");
    }

    #[test]
    fn test_classify_riscv_visionfive() {
        let (family, arch) = classify("VisionFive V2");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "visionfive");
    }

    #[test]
    fn test_classify_riscv_hifive() {
        let (family, arch) = classify("HiFive Unmatched");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "hifive");
    }

    #[test]
    fn test_classify_riscv_allwinner_d1() {
        let (family, arch) = classify("Allwinner D1");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "allwinner_d1");
    }

    #[test]
    fn test_classify_riscv_thead_c910() {
        let (family, arch) = classify("T-Head C910");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "thead_c910");
    }

    #[test]
    fn test_classify_riscv_generic_64() {
        let (family, arch) = classify("RISC-V Processor RVA64");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "riscv64_generic");
        assert!((get_multiplier(arch) - 1.4).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_riscv_generic() {
        let (family, arch) = classify("Generic RISC-V Board");
        assert_eq!(family, "RISC-V");
        assert_eq!(arch, "riscv_generic");
    }

    #[test]
    fn test_riscv_multiplier_consistency() {
        // All RISC-V architectures must receive the 1.4x EXOTIC multiplier
        let riscv_archs = [
            "sifive_u74",
            "sifive_u54",
            "sifive_e51",
            "starfive_jh7110",
            "starfive_jh7100",
            "visionfive",
            "hifive",
            "allwinner_d1",
            "thead_c910",
            "riscv64_generic",
            "riscv_generic",
        ];
        for arch in riscv_archs {
            assert!(
                (get_multiplier(arch) - 1.4).abs() < f64::EPSILON,
                "RISC-V arch '{}' should have 1.4x multiplier, got {}",
                arch,
                get_multiplier(arch)
            );
        }
    }

    // ─────────────────────────────────────────────────────────────
    // PowerPC Detection Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_g4() {
        let (family, arch) = classify("PowerPC G4 (7450)");
        assert_eq!(family, "PowerPC");
        assert_eq!(arch, "g4");
        assert!((get_multiplier(arch) - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_g5() {
        let (family, arch) = classify("PowerPC 970FX");
        assert_eq!(family, "PowerPC");
        assert_eq!(arch, "g5");
    }

    #[test]
    fn test_classify_apple_silicon() {
        let (family, arch) = classify("Apple M2 Pro");
        assert_eq!(family, "ARM");
        assert_eq!(arch, "apple_m2");
    }

    #[test]
    fn test_classify_core2() {
        let (family, arch) = classify("Intel(R) Core(TM) 2 Duo E8400");
        assert_eq!(family, "x86_64");
        assert_eq!(arch, "core2duo");
        assert!((get_multiplier(arch) - 1.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_modern_amd() {
        let (family, arch) = classify("AMD Ryzen 5 8645HS");
        assert_eq!(family, "x86_64");
        assert_eq!(arch, "modern");
        assert!((get_multiplier(arch) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_modern_intel() {
        let (family, arch) = classify("13th Gen Intel(R) Core(TM) i7-13700H");
        assert_eq!(family, "x86_64");
        assert_eq!(arch, "modern");
    }
}
