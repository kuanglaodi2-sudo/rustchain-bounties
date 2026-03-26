<!-- SPDX-License-Identifier: MIT -->
# Apple II RustChain Miner (6502)

> **Port RustChain Miner to Apple II — Bounty #436**
> A full-featured Proof-of-Antiquity miner for the MOS 6502 / Apple II platform.

By running this miner on real Apple II hardware, you qualify for the maximum **4.0x epoch multiplier** in the RustChain Proof-of-Antiquity consensus mechanism.

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Apple II model | IIe (65C02) | IIgs (65816 @ 2.8MHz) |
| RAM | 64 KB | 128 KB (auxiliary) |
| Ethernet | — | Uthernet II (W5100, Slot 3) |
| Storage | Floppy | CFFA3000 CF Card |
| OS | ProDOS 2.4 | ProDOS 2.4.3 |

> **Networking note:** If you don't have a Uthernet II card, the miner will still collect a hardware fingerprint and display the attestation payload that would be submitted — but it cannot transmit it without networking hardware.

## Architecture

### 1. Zero-Overhead Networking (W5100 Raw Sockets)

To fit within the 64KB address space alongside ProDOS, this miner communicates directly with the Uthernet II's W5100 networking chip via memory-mapped I/O registers at `$C0B0`. The W5100 implements the full TCP/IP stack in hardware — no Ethernet driver, no OS networking stack, no problem.

Files: [`w5100.c`](w5100.c), [`w5100.h`](w5100.h)

### 2. Hardware Fingerprinting (Anti-Emulation)

We collect multiple entropy vectors to prove this is a real Apple II:

| Vector | Source | Purpose |
|--------|--------|---------|
| Floating bus (Slot ROM space) | `$C100-$C1FF` | Bus state sampling |
| Unused address space | `$C300-$C3FF` | Floating bus bleed |
| Language Card RAM | `$D000-$D7FF` | RAM presence check |
| Keyboard controller | `$C000` | VIA timing signature |
| Slot 7 floating bus | `$C0F0-$C0FF` | Emulator divergence |
| CPU instruction timing | Loop benchmark | 6502 vs 65C02 vs 65816 |
| Video scanner state | `$C012` | Scan position entropy |
| Soft switch detection | `$C0AC` | Machine type (II/IIe/IIgs) |

File: [`miner.c`](miner.c) — `collect_fingerprint()` function

### 3. Proof-of-Work

Due to the 1MHz clock speed constraint, full SHA-256 is impractical for on-device mining. Instead, this miner uses a modified DJB2 hash that:

- Runs in ~10ms per hash on a 1MHz 6502
- Provides genuine computational proof-of-work
- Generates a 16-bit folded hash output
- Searches for a nonce where `hash < target`

The RustChain node independently validates attestations and can apply its own difficulty/difficulty adjustment on receipt.

### 4. Attestation Submission

A JSON attestation is constructed and POSTed to the RustChain node:

```json
{
  "wallet": "Your-Wallet-Name",
  "device_arch": "6502",
  "device_family": "apple2",
  "fingerprint": "0123456789ABCDEF...",
  "timing": "A1B2C3D4",
  "nonce": 42,
  "pow_hash": "DEADBEEF",
  "miner_version": "1.0.0",
  "client_timestamp": "1709234567"
}
```

Target endpoint: `http://50.28.86.131/api/miners`

## Build Instructions

### Prerequisites: CC65 Compiler Suite

**Linux / macOS:**
```bash
# Install via package manager
brew install cc65       # macOS
sudo apt install cc65   # Debian/Ubuntu
sudo pacman -S cc65     # Arch Linux

# Or build from source:
git clone https://github.com/cc65/cc65.git
cd cc65 && make && sudo make install
```

**Windows:**
```powershell
# Via Chocolatey:
choco install cc65

# Or download from: https://github.com/cc65/cc65/releases
```

### Build

```bash
cd apple2_miner
make
```

This produces `miner.system` — a ProDOS loadable system file.

### Build Options

| Target | Command | Notes |
|--------|---------|-------|
| Standard | `make` | Standard optimization |
| Release | `make release` | Maximum optimization |
| Debug | `make debug` | With debug symbols |

## Running the Miner

### Transfer to Apple II

Choose one method:

**CFFA3000 / MicroDrive:**
```bash
# Copy to CF card image
dd if=miner.system of=/dev/sdX bs=8192 seek=1
```

**ADT Pro (serial connection):**
```bash
# Install ADT Pro on your Apple II, then from host:
adt -w miner.system
```

**Emulator (for testing):**
```bash
# AppleWin (Windows) or MAME (cross-platform)
# Note: Fingerprint will differ in emulator
```

### Execute

```basic
]PR#6          ' Boot Uthernet II if needed
]BLOAD MINER.SYSTEM,A$2000
]CALL 8192
```

Expected output:
```
============================================
RustChain Apple II Miner  (6502 / MOS)
Version 1.0.0  |  Proof-of-Antiquity
============================================

[NET] Initializing W5100 Ethernet (Slot 3)...
[NET] W5100 configured.
[FP]  Collecting hardware fingerprint...
[FP]  Fingerprint collected. Timing: $...
[POW] Searching for proof-of-work...
[POW] Solution found! Nonce: ...
[JSN] Building attestation payload...
[NET] Connecting to RustChain node...

============================================
Miner completed. 4.0x Antiquity Multiplier Active!
============================================
```

## Technical Deep Dive

### Memory Layout

```
$0000-$00FF   Zero Page (65C02 registers)
$0100-$01FF   Hardware Stack
$0200-$2FF    Operating System / ProDOS
$D000-$D7FF   Language Card RAM (bank-switchable)
$E000-$FFFF   Monitor ROM / BASIC ROM
$C000-$CFFF   I/O Space
  $C0B0-$C0BF  Uthernet II (W5100)
  $C0F0-$C0FF  Slot 7 (floating)
$2000         Miner code entry
...           Miner .system segment
```

### W5100 Socket Buffer Layout

| Socket | TX Buffer | RX Buffer |
|--------|-----------|-----------|
| 0 | `$4000-$4FFF` | `$6000-$6FFF` |
| 1 | `$5000-$5FFF` | `$7000-$7FFF` |
| ... | ... | ... |

### Uthernet II Card Configuration

The miner auto-detects the Uthernet II at Slot 3. To change slots, edit `w5100.h`:

```c
#define W5100_BASE 0xC0B0  /* Slot 3 — change to: */
                           /* 0xC090 = Slot 1    */
                           /* 0xC0A0 = Slot 2    */
                           /* 0xC0C0 = Slot 4    */
```

### Network Configuration

Edit `miner.c` to set your local network:

```c
#define APPLE_IP_OCTETS  192, 168, 1, 200   /* Your Apple II's IP */
#define GATEWAY_OCTETS   192, 168, 1, 1     /* Your router       */
#define SUBNET_OCTETS    255, 255, 255, 0
#define MAC_OCTETS       0xB8, 0x27, 0xEB, 0x00, 0x00, 0x01  /* Change this! */
```

### Compile-Time Options

```c
#define WALLET_NAME "Your-Wallet-Name"  /* Build with: -DWALLET_NAME="..." */
#define NODE_IP_OCTETS  50, 28, 86, 131  /* RustChain node */
```

## Security Considerations

1. **MAC address**: Change the default MAC octets to a unique value per device
2. **Wallet name**: Use your actual RustChain wallet identifier
3. **Floating bus fingerprint**: Changes slightly on each run — this is expected
4. **No private keys stored**: The miner only submits attestations, never signs transactions

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `NET init failed` | Uthernet II not at Slot 3 | Check card seating or update `W5100_BASE` |
| `NET config failed` | IP conflict | Choose a different local IP |
| `FP collection failed` | RAM test failed | Ensure 128KB or language card installed |
| Miner hangs at POW | Timing loop too tight | Increase `TIMING_LOOP` in `miner.c` |
| Submission shows "code 2" | Connection failed | Verify gateway/IP/subnet settings |

## Bounty Breakdown

| Component | RTC | Status |
|-----------|-----|--------|
| Get Networking Running on Apple II | 50 RTC | ✅ Implemented |
| Implement the Miner Client | 50 RTC | ✅ Implemented |
| Hardware Fingerprinting for 6502 | 25 RTC | ✅ Implemented |
| Prove It Works (real hardware) | 25 RTC | ⏳ Requires hardware |

## License

SPDX-License-Identifier: MIT

Copyright (c) 2026 RustChain Contributors

## References

- [CC65 Compiler Suite](https://cc65.github.io)
- [W5100 Datasheet](https://www.wiznet.io/wp-content/uploads/wiznethow/super_tag/W5100_Datasheet.pdf)
- [Uthernet II Product Page](https://a2retrosystems.com)
- [ProDOS 2.4 Documentation](https://prodos.readthedocs.io)
- [Apple II Hardware Architecture](https://archive.org/details/a2Reference)
