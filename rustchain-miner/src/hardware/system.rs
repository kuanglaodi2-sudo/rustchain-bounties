use sysinfo::System;

/// Get total RAM in gigabytes.
pub fn get_ram_gb() -> u64 {
    let sys = System::new_all();
    sys.total_memory() / (1024 * 1024 * 1024)
}

/// Get OS name and version string.
pub fn get_os_string() -> String {
    let name = System::name().unwrap_or_else(|| "Unknown".to_string());
    let version = System::os_version().unwrap_or_else(|| "".to_string());
    let kernel = System::kernel_version().unwrap_or_else(|| "".to_string());

    if !kernel.is_empty() {
        format!("{} {}", name, kernel)
    } else if !version.is_empty() {
        format!("{} {}", name, version)
    } else {
        name
    }
}

/// Get system uptime in seconds.
pub fn get_uptime_secs() -> u64 {
    System::uptime()
}

/// Get the hostname of the system.
pub fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Get platform info (OS, architecture, kernel).
///
/// On RISC-V Linux, this returns e.g.:
///   "Linux 6.1.0-riscv64"
pub fn get_platform_info() -> String {
    let os = get_os_string();
    let arch = std::env::consts::OS;
    let machine = std::env::consts::ARCH;
    format!("{} ({})", os, machine)
}

/// Get all available MAC addresses as hex strings.
pub fn get_mac_addresses() -> Vec<String> {
    let mut macs = Vec::new();

    // Try the mac_address crate first
    match mac_address::mac_address_by_name("eth0") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    match mac_address::mac_address_by_name("wlan0") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    match mac_address::mac_address_by_name("en0") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    // macOS interfaces
    match mac_address::mac_address_by_name("en0") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    // Windows interfaces
    match mac_address::mac_address_by_name("Ethernet") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    match mac_address::mac_address_by_name("Wi-Fi") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    // RISC-V SBC specific interfaces
    match mac_address::mac_address_by_name("end0") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }
    match mac_address::mac_address_by_name("wlan") {
        Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
        _ => {}
    }

    // Fallback: get the default/first MAC
    if macs.is_empty() {
        match mac_address::get_mac_address() {
            Ok(Some(addr)) => macs.push(addr.to_string().to_lowercase()),
            _ => macs.push("00:00:00:00:00:00".to_string()),
        }
    }

    // Deduplicate
    macs.sort();
    macs.dedup();
    macs
}

#[cfg(target_os = "linux")]
pub mod riscv_sysfs {
    //! RISC-V specific sysfs readings (Linux only).
    //!
    //! These functions read from the Linux sysfs tree to get
    //! RISC-V specific hardware information that isn't available
    //! through the sysinfo crate.

    use std::fs;

    /// Read the machine type from /proc/device-tree/model.
    /// Common values: "SiFive HiFive Unmatched", "StarFive VisionFive 2", etc.
    pub fn get_device_tree_model() -> Option<String> {
        let dt_model = "/proc/device-tree/model";
        fs::read_to_string(dt_model)
            .ok()
            .map(|s| s.trim_end_matches('\0').to_string())
            .filter(|s| !s.is_empty())
    }

    /// Read the CPU ISA extensions from /proc/cpuinfo.
    /// Returns something like "rv64imafdcv" (base + M, A, F, D, C, V extensions).
    pub fn get_isa_string() -> Option<String> {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
        for line in cpuinfo.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("isa") || lower.starts_with("mvendorid") {
                return line
                    .split(':')
                    .nth(1)
                    .map(|s| s.trim().to_string());
            }
        }
        None
    }

    /// Read the SBI version from /proc/device-tree/chosen.
    /// The SBI (Supervisor Binary Interface) version is important for
    /// RISC-V platform identification.
    pub fn get_sbi_version() -> Option<String> {
        let sbi_path = "/sys/class/processor/processor/sbi_spec_version";
        fs::read_to_string(sbi_path)
            .ok()
            .map(|s| s.trim().to_string())
    }
}
