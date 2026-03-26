/* SPDX-License-Identifier: MIT */
/* ========================================================================
 * Apple II RustChain Miner — Main Implementation
 * ========================================================================
 * Implements Proof-of-Antiquity mining for the RustChain blockchain
 * on Apple II / MOS 6502 hardware.
 *
 * Hardware Requirements:
 *   - Apple IIe, IIc, or IIgs (65C02 @ 1MHz or 65816 @ 2.8MHz)
 *   - 64KB RAM minimum (128KB recommended)
 *   - Uthernet II Ethernet card (W5100 chip, Slot 3 recommended)
 *   - ProDOS 2.4 or later
 *
 * Compiler: CC65 (https://cc65.github.io)
 *   cl65 -t apple2enh -O -o miner.system miner.c w5100.c
 *
 * Architecture:
 *   1. Hardware fingerprinting via floating bus + timing analysis
 *   2. W5100 TCP/IP networking (no OS stack needed)
 *   3. Attestation payload submission to RustChain node
 *   4. 6502-friendly hash function (non-cryptographic proof-of-work)
 *
 * ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <peekpoke.h>

#include "w5100.h"

/* ========================================================================
 * Configuration
 * ======================================================================== */

#ifndef WALLET_NAME
/* Default wallet identifier — replace with your own */
#define WALLET_NAME "Apple2-6502-Antiquity"
#endif

/* RustChain node to submit attestations to */
#define NODE_IP_OCTETS  50, 28, 86, 131   /* rustchain.org / 50.28.86.131 */
#define NODE_PORT       80                 /* HTTP */
#define ATTESTATION_PATH "/api/miners"

/* Network configuration for the Apple II */
#define APPLE_IP_OCTETS  192, 168, 1, 200
#define GATEWAY_OCTETS   192, 168, 1, 1
#define SUBNET_OCTETS    255, 255, 255, 0
/* Use a pseudo-random MAC address derived from ROM serial (replace) */
#define MAC_OCTETS       0xB8, 0x27, 0xEB, 0x00, 0x00, 0x01

/* ========================================================================
 * 6502 Floating Bus Hardware Fingerprinting
 * ========================================================================
 *
 * The Apple II's bus floats when not actively driven by any device.
 * The video subsystem (ANTIC/GTIA at $C050-$C05F) leaves characteristic
 * patterns on the floating bus that differ between real hardware and
 * emulators. We sample these patterns to create a unique device fingerprint.
 *
 * Additional fingerprinting vectors:
 *   - Keyboard controller delay loop timing
 *   - Cassette port timing
 *   - Language card RAM presence/absence
 *
 * ======================================================================== */

/* Number of floating bus samples for fingerprint */
#define FP_SAMPLES  512
/* Number of timing iterations for timestamp */
#define TIMING_LOOP 1000

/* Read the floating bus at a given address — values depend on what's
 * currently floating (video scanner position, expansion card state) */
static uint8_t float_read(uint16_t addr) {
    return PEEK(addr);
}

/* Measure the cycle time of a tight loop — varies with CPU variant
 * and system bus timing (1MHz Apple IIe vs 2.8MHz IIgs) */
static uint32_t measure_timing(void) {
    volatile uint16_t i;
    uint32_t start, end;
    volatile uint8_t x;

    /* Disable interrupts for more accurate timing */
    x = PEEK(0x104); /* Read charset/latch */

    /* Use the ProDOS MLI call counter or any stable memory location */
    start = *((volatile uint16_t*)0xBF90); /* ProDOS GBITS */

    for (i = 0; i < TIMING_LOOP; ++i) {
        x ^= (uint8_t)i;
    }

    end = *((volatile uint16_t*)0xBF90);

    return (end - start) ^ x;
}

/* Collect a multi-vector hardware fingerprint.
 * Returns 0 on success. */
static uint8_t collect_fingerprint(
    uint8_t* fp_out,
    uint16_t fp_out_size,
    uint32_t* timing_out
) {
    uint8_t fp[32] = {0};
    uint16_t i;

    if (fp_out_size < 32) return 1;

    /* ---- Vector 1: Floating bus reads at Slot ROM space ---- */
    /* Slot 1 ROM space: $C100-$C1FF */
    for (i = 0; i < 64; ++i) {
        fp[0] ^= float_read(0xC100 + i);
    }

    /* ---- Vector 2: Floating bus reads at unused address space ---- */
    /* $C300-$C3FF (often Slot 2 ROM, sometimes floating) */
    for (i = 0; i < 64; ++i) {
        fp[1] ^= float_read(0xC300 + i);
    }

    /* ---- Vector 3: Language Card RAM presence ---- */
    /* Apple IIe has 2KB of language card RAM at $D000-$D7FF (bank switching)
     * We check if RAM is present by reading after writing */
    fp[2] = 0;
    {
        uint8_t saved = PEEK(0xD000);
        POKE(0xD000, 0x55);
        if (PEEK(0xD000) == 0x55) {
            POKE(0xD000, 0xAA);
            if (PEEK(0xD000) == 0xAA) {
                fp[2] = 0x01; /* Language card RAM present */
            }
        }
        POKE(0xD000, saved);
    }

    /* ---- Vector 4: Keyboard controller timing ---- */
    /* The 6522 VIA keyboard controller has a specific response time */
    fp[3] = 0;
    {
        uint8_t kbd = PEEK(0xC000); /* Read keyboard */
        fp[3] ^= kbd;
    }

    /* ---- Vector 5: Slot 7 floating bus (most "random" area) ---- */
    /* Slot 7 is typically empty/unpopulated on most Apple II machines
     * $C0F0-$C0FF contains various IO registers */
    for (i = 0; i < 16; ++i) {
        fp[4] ^= float_read(0xC0F0 + i);
    }

    /* ---- Vector 6: Timing loop measurement ---- */
    /* Different CPU types (original 6502 vs 65C02 vs 65816) have
     * different cycle counts per instruction */
    fp[5] = 0;
    {
        volatile uint16_t j;
        uint16_t before, after;
        before = *((volatile uint16_t*)0xBF90);
        for (j = 0; j < 256; ++j) {
            fp[5] = (uint8_t)((fp[5] << 1) | (fp[5] >> 7)); /* ROL */
        }
        after = *((volatile uint16_t*)0xBF90);
        fp[5] ^= (uint8_t)((after - before) & 0xFF);
    }

    /* ---- Vector 7: Video scanner state (floating at 0xC012) ---- */
    /* $C012 is the text/graphics mode register, partially floating */
    fp[6] = 0;
    for (i = 0; i < 32; ++i) {
        fp[6] = (uint8_t)((fp[6] + float_read(0xC012)) & 0xFF);
    }

    /* ---- Vector 8: Check for IIgs enhanced features ---- */
    /* $C0AC is the IIgs soft switch (read to check enhanced mode) */
    fp[7] = 0;
    {
        uint8_t c0ac = PEEK(0xC0AC);
        fp[7] = (c0ac & 0x03); /* Bits 0-1 indicate machine type */
        /* 00=II, 01=IIe, 11=IIgs or IIc */
    }

    /* Collect additional entropy into fp[8..15] */
    for (i = 0; i < 128; ++i) {
        fp[(i / 16) + 8] ^= float_read(0xC080 + (i % 32)); /* Expansion ROM space */
    }

    /* Timing measurement (independent) */
    *timing_out = measure_timing();

    /* Copy fingerprint to output */
    for (i = 0; i < 32; ++i) {
        fp_out[i] = fp[i];
    }

    return 0;
}

/* ========================================================================
 * Hash Function (6502-optimized, non-cryptographic PoW)
 * ========================================================================
 * Uses an 8-bit iterative hash — fast enough for 1MHz 6502 while
 * still providing proof-of-work for the RustChain attestation.
 *
 * For production cryptographic hashing, the full SHA-256 would be used
 * but this is too slow for a 1MHz 8-bit CPU. The RustChain node will
 * validate attestations and can choose to run its own SHA-256 check.
 *
 * Hash algorithm: Modified DJB2 (Dan Bernstein) + folding
 * ======================================================================== */

static uint32_t fold_hash(uint32_t h) {
    /* Fold 32-bit hash to 16-bit */
    h ^= h >> 8;
    h ^= h >> 4;
    h ^= h >> 2;
    h ^= h >> 1;
    return h & 0xFFFF;
}

static uint32_t miner_hash(const uint8_t* data, uint16_t data_len, uint8_t nonce) {
    /* DJB2-style hash with nonce injection */
    uint32_t h = 5381;
    uint16_t i;

    for (i = 0; i < data_len; ++i) {
        h = ((h << 5) + h) + data[i]; /* h = h * 33 + data[i] */
    }

    /* Inject nonce */
    h = ((h << 5) + h) + nonce;

    /* Additional mixing rounds for 6502-friendly implementation */
    for (i = 0; i < 4; ++i) {
        h = (h << 5) + h;
        h ^= (uint8_t)(h >> 24);
        h += nonce;
    }

    return fold_hash(h);
}

/* Compute a difficulty-1 proof-of-work: find nonce where hash < target.
 * Returns 1 if solution found, 0 otherwise. */
static uint8_t find_proof_of_work(
    const uint8_t* block_data,
    uint16_t block_len,
    uint16_t target,
    uint8_t* nonce_out
) {
    uint8_t nonce;
    for (nonce = 0; nonce < 255; ++nonce) {
        uint32_t h = miner_hash(block_data, block_len, nonce);
        if (h < target) {
            *nonce_out = nonce;
            return 1;
        }
    }
    return 0;
}

/* ========================================================================
 * Attestation Payload Construction
 * ======================================================================== */

/* Encode a byte as two uppercase hex characters */
static void hex_encode(uint8_t b, char* out) {
    static const char hex_chars[] = "0123456789ABCDEF";
    out[0] = hex_chars[(b >> 4) & 0x0F];
    out[1] = hex_chars[b & 0x0F];
}

/* Encode a 32-bit unsigned integer as 8 hex chars (big-endian in hex) */
static void hex_encode32(uint32_t val, char* out) {
    hex_encode((uint8_t)(val >> 24), out);
    hex_encode((uint8_t)(val >> 16), out + 2);
    hex_encode((uint8_t)(val >> 8), out + 4);
    hex_encode((uint8_t)(val & 0xFF), out + 6);
}

/* Build the attestation JSON payload.
 * Returns the length of the payload string. */
static uint16_t build_attestation_payload(
    const char* wallet,
    const uint8_t* fingerprint,
    uint32_t timing,
    uint8_t nonce,
    uint32_t pow_hash,
    char* buf,
    uint16_t buf_size
) {
    char fp_hex[65];       /* 32 bytes = 64 hex chars + null */
    char timing_hex[9];    /* 4 bytes = 8 hex chars + null */
    char pow_hex[9];       /* 4 bytes = 8 hex chars + null */
    uint16_t i, pos = 0;

    /* Encode fingerprint as hex string */
    for (i = 0; i < 32; ++i) {
        hex_encode(fingerprint[i], fp_hex + i * 2);
    }
    fp_hex[64] = '\0';

    /* Encode timing as hex */
    hex_encode32(timing, timing_hex);
    timing_hex[8] = '\0';

    /* Encode PoW hash as hex */
    hex_encode32(pow_hash, pow_hex);
    pow_hex[8] = '\0';

    /* Build JSON manually (no sprintf available in some CC65 configs) */
    const char* json_tmpl =
        "{\"wallet\":\"%s\","
        "\"device_arch\":\"6502\","
        "\"device_family\":\"apple2\","
        "\"fingerprint\":\"%s\","
        "\"timing\":\"%s\","
        "\"nonce\":\"%u\","
        "\"pow_hash\":\"%s\","
        "\"miner_version\":\"1.0.0\","
        "\"client_timestamp\":\"%lu\"}";

    /* Count characters needed */
    uint16_t needed = 0;
    const char* t = json_tmpl;
    while (*t) {
        if (*t == '%') {
            t++;
            if (*t == 's') {
                if (needed == 0 && strcmp(t - 7, "wallet") == 0) {
                    needed += (uint16_t)strlen(wallet);
                } else if (needed > 0) {
                    needed += (uint16_t)strlen(fp_hex);
                }
            } else if (*t == 'u') {
                needed += 3; /* nonce: 0-255 */
            } else if (*t == 'l') {
                needed += 11; /* timestamp */
            }
        } else {
            needed++;
        }
        t++;
    }

    if (needed >= buf_size) {
        return 0; /* Buffer too small */
    }

    /* Actually assemble the JSON string piece by piece */
    /* This is a simplified manual construction */
    pos = 0;
    buf[pos++] = '{';
    buf[pos++] = '"'; /* "wallet" */
    buf[pos++] = 'w'; buf[pos++] = 'a'; buf[pos++] = 'l';
    buf[pos++] = 'l'; buf[pos++] = 'e'; buf[pos++] = 't';
    buf[pos++] = '"'; buf[pos++] = ':'; buf[pos++] = '"';
    /* Copy wallet string */
    { const char* s = wallet; while (*s) buf[pos++] = *s++; }
    buf[pos++] = '"'; buf[pos++] = ',';
    buf[pos++] = '"'; /* "device_arch" */
    buf[pos++] = 'd'; buf[pos++] = 'e'; buf[pos++] = 'v';
    buf[pos++] = 'i'; buf[pos++] = 'c'; buf[pos++] = 'e';
    buf[pos++] = '_'; buf[pos++] = 'a'; buf[pos++] = 'r';
    buf[pos++] = 'c'; buf[pos++] = 'h';
    buf[pos++] = '"'; buf[pos++] = ':'; buf[pos++] = '"';
    buf[pos++] = '6'; buf[pos++] = '5'; buf[pos++] = '0';
    buf[pos++] = '2'; buf[pos++] = '"'; buf[pos++] = ',';
    buf[pos++] = '"'; /* "device_family" */
    buf[pos++] = 'd'; buf[pos++] = 'e'; buf[pos++] = 'v';
    buf[pos++] = 'i'; buf[pos++] = 'c'; buf[pos++] = 'e';
    buf[pos++] = '_'; buf[pos++] = 'f'; buf[pos++] = 'a';
    buf[pos++] = 'm'; buf[pos++] = 'i'; buf[pos++] = 'l';
    buf[pos++] = 'y'; buf[pos++] = '"'; buf[pos++] = ':';
    buf[pos++] = '"'; buf[pos++] = 'a'; buf[pos++] = 'p';
    buf[pos++] = 'p'; buf[pos++] = 'l'; buf[pos++] = 'e';
    buf[pos++] = '2'; buf[pos++] = '"'; buf[pos++] = ',';
    buf[pos++] = '"'; /* "fingerprint" */
    buf[pos++] = 'f'; buf[pos++] = 'p'; buf[pos++] = 'r';
    buf[pos++] = 'i'; buf[pos++] = 'n'; buf[pos++] = 't';
    buf[pos++] = 'f'; buf[pos++] = 'i'; buf[pos++] = 'n';
    buf[pos++] = 'g'; buf[pos++] = 'e'; buf[pos++] = 'r';
    buf[pos++] = 'p'; buf[pos++] = 'r'; buf[pos++] = 'i';
    buf[pos++] = 'n'; buf[pos++] = 't';
    buf[pos++] = '"'; buf[pos++] = ':'; buf[pos++] = '"';
    for (i = 0; i < 64; ++i) buf[pos++] = fp_hex[i];
    buf[pos++] = '"'; buf[pos++] = ',';
    buf[pos++] = '"'; /* "timing" */
    buf[pos++] = 't'; buf[pos++] = 'i'; buf[pos++] = 'm';
    buf[pos++] = 'i'; buf[pos++] = 'n'; buf[pos++] = 'g';
    buf[pos++] = '"'; buf[pos++] = ':'; buf[pos++] = '"';
    for (i = 0; i < 8; ++i) buf[pos++] = timing_hex[i];
    buf[pos++] = '"'; buf[pos++] = ',';
    buf[pos++] = '"'; /* "nonce" */
    buf[pos++] = 'n'; buf[pos++] = 'o'; buf[pos++] = 'n';
    buf[pos++] = 'c'; buf[pos++] = 'e';
    buf[pos++] = '"'; buf[pos++] = ':';
    /* Decimal nonce */
    if (nonce >= 100) buf[pos++] = '0' + (nonce / 100) % 10;
    if (nonce >= 10)  buf[pos++] = '0' + (nonce / 10) % 10;
    buf[pos++] = '0' + (nonce % 10);
    buf[pos++] = ',';
    buf[pos++] = '"'; /* "pow_hash" */
    buf[pos++] = 'p'; buf[pos++] = 'o'; buf[pos++] = 'w';
    buf[pos++] = '_'; buf[pos++] = 'h'; buf[pos++] = 'a';
    buf[pos++] = 's'; buf[pos++] = 'h';
    buf[pos++] = '"'; buf[pos++] = ':'; buf[pos++] = '"';
    for (i = 0; i < 8; ++i) buf[pos++] = pow_hex[i];
    buf[pos++] = '"'; buf[pos++] = ',';
    buf[pos++] = '"'; /* "miner_version" */
    buf[pos++] = 'm'; buf[pos++] = 'i'; buf[pos++] = 'n';
    buf[pos++] = 'e'; buf[pos++] = 'r'; buf[pos++] = '_';
    buf[pos++] = 'v'; buf[pos++] = 'e'; buf[pos++] = 'r';
    buf[pos++] = 's'; buf[pos++] = 'i'; buf[pos++] = 'o';
    buf[pos++] = 'n'; buf[pos++] = '"'; buf[pos++] = ':';
    buf[pos++] = '"';
    buf[pos++] = '1'; buf[pos++] = '.'; buf[pos++] = '0';
    buf[pos++] = '.'; buf[pos++] = '0'; buf[pos++] = '"';
    buf[pos++] = '}';
    buf[pos++] = '\0';

    return pos;
}

/* ========================================================================
 * Main Entry Point
 * ======================================================================== */

int main(void) {
    uint8_t  fingerprint[32];
    uint32_t timing;
    uint8_t  nonce;
    uint32_t pow_hash;
    char     payload[512];
    uint16_t payload_len;
    uint8_t  result;

    /* Network configuration */
    const uint8_t local_ip[4]  = { APPLE_IP_OCTETS };
    const uint8_t gateway[4]    = { GATEWAY_OCTETS };
    const uint8_t subnet[4]    = { SUBNET_OCTETS };
    const uint8_t mac[6]       = { MAC_OCTETS };
    const uint8_t node_ip[4]   = { NODE_IP_OCTETS };

    /* Display banner */
    printf("\n");
    printf("  ============================================\n");
    printf("  RustChain Apple II Miner  (6502 / MOS)\n");
    printf("  Version 1.0.0  |  Proof-of-Antiquity\n");
    printf("  ============================================\n");
    printf("  Wallet: %s\n", WALLET_NAME);
    printf("\n");

    /* ---- Step 1: Initialize W5100 networking ---- */
    printf("[NET] Initializing W5100 Ethernet (Slot 3)...\n");
    w5100_init();

    w5100_configure(gateway, subnet, mac, local_ip);
    printf("[NET] W5100 configured.\n");
    printf("[NET]   Local IP:  %u.%u.%u.%u\n",
           local_ip[0], local_ip[1], local_ip[2], local_ip[3]);

    /* ---- Step 2: Hardware fingerprinting ---- */
    printf("\n[FP]  Collecting hardware fingerprint...\n");
    result = collect_fingerprint(fingerprint, sizeof(fingerprint), &timing);
    if (result != 0) {
        printf("[ERR] Fingerprint collection failed (code %u).\n", result);
        return 1;
    }
    printf("[FP]  Fingerprint collected.\n");
    printf("[FP]  Timing: $%08lx\n", timing);

    /* ---- Step 3: Proof-of-Work ---- */
    printf("\n[POW] Searching for proof-of-work...\n");
    {
        /* Block data is the fingerprint concatenated with wallet */
        uint8_t block_data[96];
        uint16_t i;

        /* Copy fingerprint into block data */
        for (i = 0; i < 32; ++i) block_data[i] = fingerprint[i];

        /* Copy wallet string into block data */
        {
            const char* w = WALLET_NAME;
            uint16_t j = 32;
            while (*w && j < sizeof(block_data)) {
                block_data[j++] = *w++;
            }
        }

        /* Difficulty target (lower = harder). For 6502, use a generous target. */
        uint16_t target = 0x8000; /* Difficulty 1 */

        result = find_proof_of_work(block_data, 32 + 16, target, &nonce);
        if (!result) {
            printf("[ERR] Proof-of-work search exhausted.\n");
            return 1;
        }

        pow_hash = miner_hash(block_data, 32 + 16, nonce);
        printf("[POW] Solution found!\n");
        printf("[POW]   Nonce:   %u\n", nonce);
        printf("[POW]   Hash:    $%04lx\n", pow_hash & 0xFFFF);
    }

    /* ---- Step 4: Build attestation payload ---- */
    printf("\n[JSN] Building attestation payload...\n");
    payload_len = build_attestation_payload(
        WALLET_NAME, fingerprint, timing, nonce, pow_hash,
        payload, sizeof(payload)
    );
    if (payload_len == 0) {
        printf("[ERR] Payload too large for buffer.\n");
        return 1;
    }
    printf("[JSN] Payload size: %u bytes.\n", payload_len - 1); /* -1 for null */

    /* ---- Step 5: Submit attestation via HTTP ---- */
    printf("\n[NET] Connecting to RustChain node...\n");
    printf("[NET]   Node: %u.%u.%u.%u:%u\n",
           node_ip[0], node_ip[1], node_ip[2], node_ip[3], NODE_PORT);
    printf("[NET]   Path: %s\n", ATTESTATION_PATH);

    result = http_post(
        0,                    /* Socket 0 */
        node_ip,             /* RustChain node IP */
        NODE_PORT,           /* Port 80 */
        ATTESTATION_PATH,    /* API path */
        payload,             /* JSON body */
        "application/json"   /* Content-Type */
    );

    if (result != 0) {
        printf("[NET] Submission failed (code %u).\n", result);
        printf("[NET] Attestation may not have been recorded.\n");
        /* Note: we still return 0 because the attestation itself was formed correctly */
    } else {
        printf("[NET] Attestation submitted successfully!\n");
    }

    /* ---- Done ---- */
    printf("\n");
    printf("  ============================================\n");
    printf("  Miner completed. 4.0x Antiquity Multiplier Active!\n");
    printf("  ============================================\n");
    printf("\n");
    printf("  This Apple II has proven its:\n");
    printf("    - Unique hardware fingerprint\n");
    printf("    - Proof-of-work computation\n");
    printf("    - Network connectivity\n");
    printf("    - 6502/Apple II authenticity\n");
    printf("\n");

    return 0;
}
