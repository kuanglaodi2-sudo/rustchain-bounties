# SPDX-License-Identifier: MIT
# ========================================================================
# Apple II Miner — Build System (CC65)
# ========================================================================
#
# Build Requirements:
#   - CC65 compiler suite: https://cc65.github.io
#     (contains cl65, ca65, ld65)
#
# Linux / macOS / WSL:
#   $ make
#
# Windows (with CC65 installed via chocolatey or manual):
#   $ make
#
# Build targets:
#   miner.system  — ProDOS system file (loadable from BASIC)
#   miner.po      — ProDOS volume image with miner.system
#
# Run instructions:
#   1. Transfer miner.system to your Apple II via:
#        - CFFA3000 CF card
#        - MicroDrive emulator
#        - Floppy disk
#        - ADT Pro (serial)
#   2. Boot ProDOS and run:
#        CALL -151   (or PR#6 for Uthernet II)
#        BLOAD MINER.SYSTEM,A$2000
#        CALL 8192
# ========================================================================

CC = cl65
CFLAGS = -t apple2enh -O -T
LDFLAGS = -t apple2enh -O -T --code-start 0x2000 --code-size 0x8000
CFLAGS += -Wall -Wno-unused-function
LDFLAGS += --zero-start

# Source files (order matters)
SRC = miner.c w5100.c

# Output
TARGET = miner.system
TARGET_PO = miner.po

# CC65 include path
INCDIR = /usr/local/include/cc65
# Override on Windows if needed:
# INCDIR = C:\cc65\include

.PHONY: all clean burn adt

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Build with maximum optimization
release: CFLAGS += -O
release: $(TARGET)

# Build debug version (includes symbols)
debug: CFLAGS += -g -O
debug: $(TARGET:.system=_debug.system)

# Create ProDOS volume image (requires cc65 tools)
$(TARGET_PO): $(TARGET)
	@echo "Creating ProDOS volume image..."
	@mkdir -p img
	cp $(TARGET) img/
	@echo "Note: Use a ProDOS formatter to create img/miner.po"
	@echo "  dd if=/dev/zero of=img/miner.po bs=8192 count=80"
	@echo "  applecommander -p img/miner.po MINER.SYSTEM system 8192 < $(TARGET)"

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TARGET:_system=) *.o img/*

# Burn to floppy disk via ADT Pro (requires ADT Pro installed)
adt:
	@echo "Burning $(TARGET) to floppy via ADT Pro..."
	@echo "Ensure your Apple II is connected via serial cable."
	@echo "Start ADT Pro on your Apple II, then run:"
	@echo "  adt -w $(TARGET)"

# Show help
help:
	@echo "Apple II RustChain Miner Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build miner.system (default)"
	@echo "  release  - Build with maximum optimization"
	@echo "  debug    - Build with debug symbols"
	@echo "  clean    - Remove build artifacts"
	@echo "  adt      - Instructions for burning to floppy"
	@echo ""
	@echo "Requirements: CC65 (https://cc65.github.io)"
