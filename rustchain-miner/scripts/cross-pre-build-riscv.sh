#!/usr/bin/env bash
# cross-pre-build-riscv.sh — Pre-build checks and setup for RISC-V cross-compilation
#
# This script should be run BEFORE cross-compiling to ensure all
# dependencies are available. It validates the environment and
# installs any missing toolchain components.
#
# Usage:
#   ./scripts/cross-pre-build-riscv.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Detect host OS
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

log_info "Pre-build check for RISC-V cross-compilation"
log_info "Host: ${HOST_OS} / ${HOST_ARCH}"

# Check Rust installation
if ! command -v rustc &>/dev/null; then
    log_error "Rust not installed. Install from https://rustup.rs"
    exit 1
fi

RUST_VERSION="$(rustc --version)"
log_info "Rust: ${RUST_VERSION}"

# Check if cross is installed
if command -v cross &>/dev/null; then
    log_info "cross: $(cross --version)"
else
    log_warn "cross not found. Installing..."
    cargo install cross
    log_info "cross installed successfully."
fi

# Check for riscv64gc target
if rustup target list --installed 2>/dev/null | grep -q "riscv64gc"; then
    log_info "riscv64gc-unknown-linux-gnu: installed"
else
    log_warn "Adding riscv64gc-unknown-linux-gnu target..."
    rustup target add riscv64gc-unknown-linux-gnu
fi

# Platform-specific toolchain checks
case "${HOST_OS}" in
    Linux)
        log_info "Linux host detected."
        if command -v riscv64-linux-gnu-gcc &>/dev/null; then
            log_info "RISC-V gcc: $(riscv64-linux-gnu-gcc --version | head -1)"
        else
            log_warn "riscv64-linux-gnu-gcc not found. Install with:"
            log_warn "  sudo apt install gcc-riscv64-linux-gnu"
        fi
        ;;
    Darwin)
        log_info "macOS host detected."
        if command -v riscv64-unknown-elf-gcc &>/dev/null; then
            log_info "RISC-V ELF gcc: available"
        else
            log_warn "riscv64-unknown-elf-gcc not found. Install with:"
            log_warn "  brew install riscv-tools"
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        log_info "Windows host detected (Git Bash / MSYS2)."
        if command -v riscv64-unknown-linux-gnu-gcc &>/dev/null; then
            log_info "RISC-V gcc: available"
        else
            log_warn "RISC-V toolchain not found. Consider using WSL2 for Linux cross-compilation."
        fi
        ;;
esac

# Verify the Cargo.toml is valid
log_info "Verifying Cargo.toml..."
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo metadata --format-version=1 --no-deps >/dev/null
log_info "Cargo.toml: valid"

# Build the RISC-V target
log_info "Starting cross-compilation for riscv64gc-unknown-linux-gnu..."
cross build --release --target riscv64gc-unknown-linux-gnu

# Verify the binary was created
BIN_PATH="target/riscv64gc-unknown-linux-gnu/release/rustchain-miner"
if [[ -f "${BIN_PATH}" ]]; then
    log_info "Binary created successfully!"
    log_info "  Size: $(du -h "${BIN_PATH}" | cut -f1)"
    log_info "  Path: ${BIN_PATH}"
    # Try to read the ELF header
    if command -v file &>/dev/null; then
        log_info "  File info: $(file "${BIN_PATH}" | cut -d: -f2)"
    fi
else
    log_error "Build failed — binary not found at ${BIN_PATH}"
    exit 1
fi

log_info "Pre-build check complete. RISC-V binary is ready!"
