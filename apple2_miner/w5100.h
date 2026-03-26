/* SPDX-License-Identifier: MIT */
/* ========================================================================
 * Apple II RustChain Miner — W5100 Ethernet Controller Interface
 * ========================================================================
 * Direct register-level interface to the Uthernet II W5100 chip.
 * The W5100 implements TCP/IP in hardware — no OS networking stack needed.
 *
 * Uthernet II Slot Map:
 *   Base I/O address: $C0B0 ( Slot 3, card-select line CS=AUTO )
 *   Alternative slot placements: $C0C0-$C0FF for slots 1-7
 *
 * W5100 Registers (16-bit address space):
 *   0x0000-0x001F : Common registers (Mode, Gateway, Subnet, MAC, IP, etc.)
 *   0x0400-0x040F : Socket 0 registers
 *   0x0500-0x050F : Socket 1 registers
 *   ... (up to 8 sockets)
 *   0x4000-0x7FFF : Socket 0 TX/RX buffers (8KB each)
 *
 * Reference: https://www.wiznet.io/wp-content/uploads/wiznethow/super_tag/W5100_Datasheet.pdf
 * ======================================================================== */

#ifndef W5100_H
#define W5100_H

#include <stdint.h>

/* -----------------------------------------------------------------------
 * W5100 Memory Map
 * ----------------------------------------------------------------------- */
#define W5100_BASE         0xC0B0   /* Slot 3 base — standard Uthernet II */
#define W5100_MODE_REG     0x0000   /* MR — Mode Register */
#define W5100_GWAY0        0x0001   /* GAR — Gateway Address [4] */
#define W5100_SUBMASK0     0x0005   /* SUBR — Subnet Mask Address [4] */
#define W5100_HARDWARE0    0x0009   /* SHAR — Source Hardware Address [6] */
#define W5100_IP0          0x000F   /* SIPR — Source IP Address [4] */
#define W5100_RCR          0x001F   /* RCR — Retry Count */
#define W5100_RTR          0x0019   /* RTR — Retry Time */
#define W5100_SOCK_IND     0x0020   /* SIR — Socket Interrupt */
#define W5100_SOCK_INTMASK 0x0024   /* SIMR — Socket Interrupt Mask */

/* -----------------------------------------------------------------------
 * W5100 Mode Register (MR) bits
 * ----------------------------------------------------------------------- */
#define MR_RST    0x80   /* Software Reset */
#define MR_PB     0x10   /* Ping Block */
#define MR_PPPOE  0x08   /* PPPoE Enable */
#define MR_AUTO   0x02   /* Auto-Increment TX/RX buffer pointer */

/* -----------------------------------------------------------------------
 * Socket Registers (offset from base, then +0x400*N for socket N)
 * ----------------------------------------------------------------------- */
#define SOCK_REG(base, n, reg) ((base) + 0x400 * (n) + (reg))

/* Socket Mode Register (Sn_MR) */
#define SOCK_STREAM    0x01   /* TCP */
#define SOCK_DGRAM     0x02   /* UDP */
#define SOCK_MACRAW    0x04   /* MACRAW (for ARP/raw eth) */
#define SOCK_NCOMB     0x08   /* Non-TCP (UDP/MACRAW) */
#define SOCK_MULTI     0x80   /* Multi-cast (UDP only) */

/* Socket Command Register (Sn_CR) */
#define CR_OPEN     0x01   /* Initialize socket */
#define CR_LISTEN   0x02   /* Wait for connection (TCP server) */
#define CR_CONNECT  0x04   /* Connect to remote (TCP client) */
#define CR_DISCON   0x08   /* Disconnect */
#define CR_CLOSE    0x10   /* Close socket */
#define CR_SEND     0x20   /* Send data */
#define CR_SENDMAC  0x21   /* Send MACRAW data */
#define CR_SENDKEEP 0x22   /* Send keepalive */
#define CR_RECV     0x40   /* Receive data */

/* Socket Status Register (Sn_SR) */
#define SOCK_CLOSED     0x00
#define SOCK_INIT       0x13   /* Socket initialized */
#define SOCK_LISTEN     0x14   /* Socket listening */
#define SOCK_ESTAB      0x17   /* Connection established */
#define SOCK_CLOSE_WAIT 0x18  /* Close waiting */
#define SOCK_UDP        0x22   /* UDP socket */
#define SOCK_MACRAW     0x02   /* MACRAW socket */
#define SOCK_SYNSENT    0x15   /* SYN sent */
#define SOCK_SYNRECV    0x16   /* SYN received */
#define SOCK_FIN_WAIT   0x19  /* FIN wait */
#define SOCK_CLOSING    0x1A   /* Closing */
#define SOCK_TIME_WAIT  0x1B   /* Time wait */
#define SOCK_LAST_ACK   0x1C   /* Last ACK */
#define SOCK_ARP        0x01   /* ARP */

/* Socket Interrupt Register (Sn_IR) */
#define IR_CON     0x01   /* Connection established */
#define IR_DISCON  0x02   /* Disconnected */
#define IR_RECV    0x04   /* Data received */
#define IR_TIMEOUT 0x08   /* Timeout */
#define IR_SEND_OK 0x10   /* Send complete */

/* -----------------------------------------------------------------------
 * Socket Register Offsets (within socket block)
 * ----------------------------------------------------------------------- */
#define SOCK_MR_OFFSET   0x0000   /* Sn_MR — Socket Mode */
#define SOCK_CR_OFFSET   0x0001   /* Sn_CR — Command */
#define SOCK_IR_OFFSET   0x0002   /* Sn_IR — Interrupt */
#define SOCK_SR_OFFSET   0x0003   /* Sn_SR — Status */
#define SOCK_PORT0       0x0004   /* Sn_PORT0 — Source Port [2] */
#define SOCK_PORT1       0x0005
#define SOCK_DIPR0       0x000C   /* Sn_DIPR — Dest IP [4] */
#define SOCK_DIPR1       0x000D
#define SOCK_DIPR2       0x000E
#define SOCK_DIPR3       0x000F
#define SOCK_DPORT0      0x0010   /* Sn_DPORT — Dest Port [2] */
#define SOCK_DPORT1      0x0011
#define SOCK_FREGSIZE    0x001E   /* Sn_FREGSIZE — TX/RX Buffer Size */
#define SOCK_TX_BASE0    0x0020   /* Sn_TX_BASE — TX Buffer Base [2] */
#define SOCK_TX_BASE1    0x0021
#define SOCK_RX_BASE0    0x0022   /* Sn_RX_BASE — RX Buffer Base [2] */
#define SOCK_RX_BASE1    0x0023

/* -----------------------------------------------------------------------
 * TX/RX Buffer sizes (shared across all sockets, set by Sn_FREGSIZE)
 * Total TX/RX = 8KB each. With 2KB/socket:
 *   Socket 0: TX 0x4000-0x43FF, RX 0x6000-0x63FF
 * ----------------------------------------------------------------------- */
#define TX_BUF_SIZE  0x2000   /* 8KB TX total */
#define RX_BUF_SIZE  0x2000   /* 8KB RX total */
#define TX_BASE(n)   (0x4000 + (n) * 0x1000)
#define RX_BASE(n)   (0x6000 + (n) * 0x1000)

/* -----------------------------------------------------------------------
 * TX/RX Buffer Free/Read Pointer Registers (16-bit)
 * ----------------------------------------------------------------------- */
#define SOCK_TX_FREER0(n)  (0x0024 + (n)*0x400)   /* TX free size [2] */
#define SOCK_TX_FREER1(n)  (0x0025 + (n)*0x400)
#define SOCK_TX_RD0(n)     (0x0028 + (n)*0x400)   /* TX read pointer [2] */
#define SOCK_TX_RD1(n)     (0x0029 + (n)*0x400)
#define SOCK_RX_RSR0(n)    (0x0026 + (n)*0x400)   /* RX received size [2] */
#define SOCK_RX_RSR1(n)    (0x0027 + (n)*0x400)
#define SOCK_RX_RD0(n)     (0x002A + (n)*0x400)   /* RX read pointer [2] */
#define SOCK_RX_RD1(n)     (0x002B + (n)*0x400)

/* -----------------------------------------------------------------------
 * Read/Write FIFO Data Register (8-bit, auto-increments)
 * ----------------------------------------------------------------------- */
#define SOCK_DATA_REG(n) (0x0404 + (n) * 0x400)

/* ========================================================================
 * Inline W5100 Accessors (for CC65 / 6502 C compiler)
 * Uses memory-mapped I/O at $C0B0-$C0BF on the Apple II bus
 * ======================================================================== */

extern void w5100_write(uint16_t addr, uint8_t data);
extern uint8_t w5100_read(uint16_t addr);
extern void w5100_write16(uint16_t addr, uint16_t data);
extern uint16_t w5100_read16(uint16_t addr);

/* ========================================================================
 * High-Level Socket API
 * ======================================================================== */

/* Reset and initialize the W5100 chip */
extern void w5100_init(void);

/* Configure the gateway, subnet, MAC address, and IP */
extern void w5100_configure(
    const uint8_t* gateway_ip,
    const uint8_t* subnet_mask,
    const uint8_t* mac_addr,
    const uint8_t* local_ip
);

/* Open socket N as TCP client and connect to host:port */
extern uint8_t tcp_connect(uint8_t sock_num, const uint8_t* dest_ip, uint16_t dest_port, uint16_t local_port);

/* Check if socket has data waiting */
extern uint8_t socket_has_data(uint8_t sock_num);

/* Read up to max_len bytes from socket into buf. Returns bytes read. */
extern uint16_t socket_read(uint8_t sock_num, uint8_t* buf, uint16_t max_len);

/* Write len bytes from buf to socket TX buffer and send. Returns 0 on success. */
extern uint8_t socket_write(uint8_t sock_num, const uint8_t* buf, uint16_t len);

/* Close socket */
extern void socket_close(uint8_t sock_num);

/* Wait for connection to be established (poll for ESTAB) */
extern uint8_t wait_for_connect(uint8_t sock_num, uint16_t timeout_ms);

/* Send a full HTTP POST request */
extern uint8_t http_post(
    uint8_t sock_num,
    const uint8_t* host_ip,
    uint16_t host_port,
    const char* path,
    const char* body,
    const char* content_type
);

#endif /* W5100_H */
