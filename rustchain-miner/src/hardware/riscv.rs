//! RISC-V specific hardware detection and identification.
//!
//! This module provides RISC-V platform detection for the RustChain miner.
//! RISC-V is an open ISA that has emerged as a vintage computing platform
//! with unique attestation characteristics.
//!
//! # Supported Platforms
//!
//! | Platform          | SoC / CPU          | Cores | Memory  | Notes                    |
//! |-------------------|--------------------|-------|---------|--------------------------|
//! | HiFive Unmatched  | SiFive Freedom U740| 4+1   | 16 GB   | Desktop-class RISC-V     |
//! | VisionFive 2      | StarFive JH7110   | 4     | 2-8 GB  | SBC with GPU             |
//! | VisionFive v1     | StarFive JH7100   | 2     | 2-4 GB  | First RISC-V SBC         |
//! | Nezha (D1)        | Allwinner D1      | 1     | 1 GB    | Single-core SBC          |
//! | Lichee RV         | T-Head C906       | 1     | 256 MB  | Low-cost module          |
//! | Allwinner D1      | T-Head C910       | 1-2   | 1 GB    | Single-core              |
//!
//! # Memory Alignment
//!
//! RISC-V uses the LP64 (Long Pointer 64) memory model on 64-bit systems,
//! which means `long` and pointer types are 64-bit while `int` remains 32-bit.
//! This is consistent with x86_64 but different from arm64 (LP64).
//!
//! # ISA Extensions
//!
//! Common RISC-V ISA extensions relevant to mining:
//! - `M` — Integer Multiply/Divide
//! - `A` — Atomic Operations (required for concurrent mining)
//! - `F` — Single-precision Float
//! - `D` — Double-precision Float
//! - `V` — Vector operations (for future SIMD-like mining optimizations)
//! - `B` — Bit manipulation

use std::fs;
use std::path::Path;

/// Represents a detected RISC-V platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiscVPlatform {
    /// SiFive Freedom U740 (HiFive Unmatched)
    SiFiveU74,
    /// SiFive Freedom U540 (HiFive Unleashed)
    SiFiveU54,
    /// SiFive E51 (embedded core)
    SiFiveE51,
    /// StarFive JH7110 (VisionFive 2)
    StarFiveJH7110,
    /// StarFive JH7100 (VisionFive v1)
    StarFiveJH7100,
    /// Original VisionFive board
    VisionFive,
    /// HiFive Unmatched / Unleashed
    HiFive,
    /// Allwinner D1 (Nezha SBC)
    AllwinnerD1,
    /// T-Head C910 (high-performance)
    THeadC910,
    /// T-Head C906 (embedded)
    THeadC906,
    /// Generic RISC-V system
    Unknown(String),
}

impl RiscVPlatform {
    /// Get the platform name for attestation.
    pub fn name(&self) -> &str {
        match self {
            Self::SiFiveU74 => "SiFive Freedom U740",
            Self::SiFiveU54 => "SiFive Freedom U540",
            Self::SiFiveE51 => "SiFive E51",
            Self::StarFiveJH7110 => "StarFive JH7110",
            Self::StarFiveJH7100 => "StarFive JH7100",
            Self::VisionFive => "VisionFive",
            Self::HiFive => "HiFive",
            Self::AllwinnerD1 => "Allwinner D1",
            Self::THeadC910 => "T-Head C910",
            Self::THeadC906 => "T-Head C906",
            Self::Unknown(s) => s,
        }
    }

    /// Check if this is a high-performance RISC-V core (multi-core).
    pub fn is_high_performance(&self) -> bool {
        matches!(
            self,
            Self::SiFiveU74 | Self::SiFiveU54 | Self::StarFiveJH7110 | Self::THeadC910
        )
    }
}

/// Read /proc/cpuinfo and detect RISC-V platform.
pub fn detect_platform() -> RiscVPlatform {
    // Try reading /proc/cpuinfo first (works on Linux)
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        let lower = contents.to_lowercase();

        // Check for specific ISA strings
        if lower.contains("u74") || lower.contains("u740") {
            return RiscVPlatform::SiFiveU74;
        }
        if lower.contains("u54") || lower.contains("u540") {
            return RiscVPlatform::SiFiveU54;
        }
        if lower.contains("e51") || lower.contains("e510") {
            return RiscVPlatform::SiFiveE51;
        }
        if lower.contains("jh7110") {
            return RiscVPlatform::StarFiveJH7110;
        }
        if lower.contains("jh7100") {
            return RiscVPlatform::StarFiveJH7100;
        }
        if lower.contains("visionfive") {
            // Try to distinguish v1 vs v2 via core count hint
            if lower.contains("4") || lower.contains("quad") {
                return RiscVPlatform::StarFiveJH7110;
            }
            return RiscVPlatform::VisionFive;
        }
        if lower.contains("d1") || lower.contains("nezha") || lower.contains("allwinner") {
            return RiscVPlatform::AllwinnerD1;
        }
        if lower.contains("c910") || lower.contains("thead c910") {
            return RiscVPlatform::THeadC910;
        }
        if lower.contains("c906") || lower.contains("thead c906") || lower.contains("c906") {
            return RiscVPlatform::THeadC906;
        }
        if lower.contains("sifive") {
            return RiscVPlatform::HiFive;
        }
        if lower.contains("riscv") {
            // Check for 64-bit
            if lower.contains("rvc") || lower.contains("rv64") {
                return RiscVPlatform::Unknown("RISC-V 64-bit (generic)".to_string());
            }
            return RiscVPlatform::Unknown("RISC-V (generic)".to_string());
        }
    }

    // Try reading device tree files (common on RISC-V SBCs)
    if Path::new("/sys/firmware/devicetree/base/model").exists() {
        if let Ok(model) = fs::read_to_string("/sys/firmware/devicetree/base/model") {
            let model_lower = model.to_lowercase();
            if model_lower.contains("jf7110") || model_lower.contains("visionfive 2") {
                return RiscVPlatform::StarFiveJH7110;
            }
            if model_lower.contains("jf7100") || model_lower.contains("visionfive") {
                return RiscVPlatform::VisionFive;
            }
            if model_lower.contains("hifive") || model_lower.contains("freedom-u740") {
                return RiscVPlatform::SiFiveU74;
            }
            if model_lower.contains("d1") || model_lower.contains("nezha") {
                return RiscVPlatform::AllwinnerD1;
            }
        }
    }

    RiscVPlatform::Unknown("Unknown RISC-V platform".to_string())
}

/// Check if the system is running on RISC-V architecture.
///
/// Uses `std::env::consts::ARCH` which returns "riscv64" or "riscv32"
/// on RISC-V systems at compile time.
pub fn is_riscv_arch() -> bool {
    std::env::consts::ARCH.contains("riscv")
}

/// Read available RISC-V ISA extensions from /proc/cpuinfo.
///
/// Returns a list of supported extensions (e.g., ["M", "A", "F", "D"]).
pub fn get_isa_extensions() -> Vec<String> {
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        for line in contents.lines() {
            if line.to_lowercase().starts_with("isa") || line.to_lowercase().starts_with("mvendorid") {
                // ISA extension line format: "isa : rv64imafdc"
                if let Some(val) = line.split(':').nth(1) {
                    return val
                        .trim()
                        .trim_start_matches("rv64")
                        .trim_start_matches("rv32")
                        .chars()
                        .map(|c| c.to_string())
                        .collect();
                }
            }
        }
    }
    Vec::new()
}

/// Check if required mining extensions are available.
pub fn has_mining_extensions() -> bool {
    let extensions = get_isa_extensions();
    // M (multiply) and A (atomic) are required for mining operations
    extensions.iter().any(|e| e == "M") && extensions.iter().any(|e| e == "A")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_riscv_platform_detection_sifive() {
        let platform = RiscVPlatform::SiFiveU74;
        assert!(platform.is_high_performance());
        assert_eq!(platform.name(), "SiFive Freedom U740");
    }

    #[test]
    fn test_riscv_platform_detection_starfive() {
        let jh7110 = RiscVPlatform::StarFiveJH7110;
        let jh7100 = RiscVPlatform::StarFiveJH7100;
        assert!(jh7110.is_high_performance());
        assert!(jh7100.is_high_performance());
        assert_eq!(jh7110.name(), "StarFive JH7110");
    }

    #[test]
    fn test_riscv_platform_detection_allwinner() {
        let d1 = RiscVPlatform::AllwinnerD1;
        assert!(!d1.is_high_performance()); // Single-core
        assert_eq!(d1.name(), "Allwinner D1");
    }

    #[test]
    fn test_riscv_platform_detection_thead() {
        let c910 = RiscVPlatform::THeadC910;
        let c906 = RiscVPlatform::THeadC906;
        assert!(c910.is_high_performance());
        assert!(!c906.is_high_performance());
    }

    #[test]
    fn test_platform_name_unknown() {
        let unknown = RiscVPlatform::Unknown("Custom Board".to_string());
        assert_eq!(unknown.name(), "Custom Board");
        assert!(!unknown.is_high_performance());
    }
}
