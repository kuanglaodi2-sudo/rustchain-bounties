pub mod arch;
pub mod cpu;
pub mod riscv; // RISC-V specific hardware detection
pub mod system;

pub use arch::{classify, get_multiplier};
pub use cpu::{get_cpu_model, get_cpu_cores, get_cpu_serial};
pub use riscv::{detect_platform, get_isa_extensions, has_mining_extensions, is_riscv_arch};
pub use system::{get_hostname, get_mac_addresses, get_platform_info};
