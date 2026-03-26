#!/usr/bin/env bash
# build_riscv.sh — Build RustChain miner for RISC-V targets
#
# Supports:
#   - Native RISC-V build (on RISC-V hardware)
#   - Cross-compilation from x86_64 using cross
#   - musl static builds
#
# Usage:
#   ./scripts/build_riscv.sh              # Native build
#   ./scripts/build_riscv.sh --native    # Force native
#   ./scripts/build_riscv.sh --cross     # Cross-compile
#   ./scripts/build_riscv.sh --musl      # Static musl build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET="${TARGET:-}"  # Allow override via env var
MODE="${1:-native}"   # default: native

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if we're already on RISC-V
is_riscv_host() {
    [[ "$(uname -m)" == "riscv64" ]] || [[ "$(uname -m)" == "riscv32" ]]
}

# Add RISC-V target to rustup
install_riscv_target() {
    log_info "Adding RISC-V targets to rustup..."
    rustup target add riscv64gc-unknown-linux-gnu 2>/dev/null || true
    rustup target add riscv64gc-unknown-linux-musl 2>/dev/null || true
    rustup target add riscv32imc-unknown-none-elf 2>/dev/null || true
    log_info "RISC-V targets installed."
}

# Check for cross utility
has_cross() {
    command -v cross &>/dev/null
}

# Native build (on RISC-V hardware)
build_native() {
    log_info "Building RustChain miner natively for RISC-V..."
    cd "${PROJECT_ROOT}"
    cargo build --release
    log_info "Native build complete: target/release/rustchain-miner"
}

# Cross-compilation from x86_64
build_cross() {
    if ! has_cross; then
        log_warn "cross not found. Installing..."
        cargo install cross
    fi
    log_info "Cross-compiling for RISC-V (glibc)..."
    cd "${PROJECT_ROOT}"
    cross build --release --target riscv64gc-unknown-linux-gnu
    log_info "Cross-compile complete: target/riscv64gc-unknown-linux-gnu/release/rustchain-miner"
}

# Static musl build
build_musl() {
    if ! has_cross; then
        cargo install cross
    fi
    log_info "Cross-compiling for RISC-V (musl static)..."
    cd "${PROJECT_ROOT}"
    cross build --release --target riscv64gc-unknown-linux-musl
    log_info "Musl static build complete: target/riscv64gc-unknown-linux-musl/release/rustchain-miner"
}

# Run tests for RISC-V architecture
run_tests() {
    log_info "Running RISC-V specific tests..."
    cd "${PROJECT_ROOT}"
    cargo test --lib hardware::riscv -- --nocapture 2>/dev/null || \
        cargo test hardware::arch -- --nocapture
    log_info "Tests complete."
}

# Main
main() {
    cd "${PROJECT_ROOT}"
    log_info "RustChain Miner — RISC-V Build Script"
    log_info "Mode: ${MODE}"
    log_info "Host architecture: $(uname -m)"

    install_riscv_target

    case "${MODE}" in
        --native|-n)
            build_native
            ;;
        --cross|-c)
            build_cross
            ;;
        --musl|-m)
            build_musl
            ;;
        --test|-t)
            run_tests
            ;;
        *)
            if is_riscv_host; then
                build_native
            else
                log_info "Detected cross-compilation environment."
                if [[ "${TARGET}" == "riscv64gc-unknown-linux-musl" ]]; then
                    build_musl
                else
                    build_cross
                fi
            fi
            ;;
    esac

    log_info "Done!"
}

main "$@"
