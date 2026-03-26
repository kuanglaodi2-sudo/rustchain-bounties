/* SPDX-License-Identifier: MIT */
/* ========================================================================
 * Apple II RustChain Miner — W5100 Implementation
 * ========================================================================
 * Implements the W5100 chip interface for the Uthernet II Ethernet card.
 * Designed for CC65 C compiler targeting MOS 6502 / Apple II.
 * ======================================================================== */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <peekpoke.h>
#include "w5100.h"

/* ========================================================================
 * W5100 Register Access
 * ======================================================================== */

void w5100_write(uint16_t addr, uint8_t data) {
    POKE(W5100_BASE + 0, (uint8_t)((addr >> 8) & 0xFF));
    POKE(W5100_BASE + 1, (uint8_t)(addr & 0xFF));
    POKE(W5100_BASE + 3, data);
}

uint8_t w5100_read(uint16_t addr) {
    POKE(W5100_BASE + 0, (uint8_t)((addr >> 8) & 0xFF));
    POKE(W5100_BASE + 1, (uint8_t)(addr & 0xFF));
    return PEEK(W5100_BASE + 3);
}

void w5100_write16(uint16_t addr, uint16_t data) {
    w5100_write(addr, (uint8_t)((data >> 8) & 0xFF));
    w5100_write(addr + 1, (uint8_t)(data & 0xFF));
}

uint16_t w5100_read16(uint16_t addr) {
    uint16_t hi = w5100_read(addr);
    uint16_t lo = w5100_read(addr + 1);
    return (hi << 8) | lo;
}

/* ========================================================================
 * W5100 Initialization
 * ======================================================================== */

void w5100_init(void) {
    /* Trigger software reset */
    w5100_write(W5100_MODE_REG, MR_RST);

    /* Wait for reset to complete (W5100 clears MR_RST after ~10ms) */
    {
        volatile uint16_t i;
        for (i = 0; i < 60000; ++i) {
            if ((w5100_read(W5100_MODE_REG) & MR_RST) == 0) break;
        }
    }

    /* Set auto-increment mode for TX/RX buffer access */
    w5100_write(W5100_MODE_REG, MR_AUTO);
}

void w5100_configure(
    const uint8_t* gateway_ip,
    const uint8_t* subnet_mask,
    const uint8_t* mac_addr,
    const uint8_t* local_ip
) {
    /* Gateway address */
    w5100_write(W5100_GWAY0 + 0, gateway_ip[0]);
    w5100_write(W5100_GWAY0 + 1, gateway_ip[1]);
    w5100_write(W5100_GWAY0 + 2, gateway_ip[2]);
    w5100_write(W5100_GWAY0 + 3, gateway_ip[3]);

    /* Subnet mask */
    w5100_write(W5100_SUBMASK0 + 0, subnet_mask[0]);
    w5100_write(W5100_SUBMASK0 + 1, subnet_mask[1]);
    w5100_write(W5100_SUBMASK0 + 2, subnet_mask[2]);
    w5100_write(W5100_SUBMASK0 + 3, subnet_mask[3]);

    /* Hardware (MAC) address */
    w5100_write(W5100_HARDWARE0 + 0, mac_addr[0]);
    w5100_write(W5100_HARDWARE0 + 1, mac_addr[1]);
    w5100_write(W5100_HARDWARE0 + 2, mac_addr[2]);
    w5100_write(W5100_HARDWARE0 + 3, mac_addr[3]);
    w5100_write(W5100_HARDWARE0 + 4, mac_addr[4]);
    w5100_write(W5100_HARDWARE0 + 5, mac_addr[5]);

    /* Local IP address */
    w5100_write(W5100_IP0 + 0, local_ip[0]);
    w5100_write(W5100_IP0 + 1, local_ip[1]);
    w5100_write(W5100_IP0 + 2, local_ip[2]);
    w5100_write(W5100_IP0 + 3, local_ip[3]);

    /* Set retry count and retry time */
    w5100_write(W5100_RCR, 8);       /* 8 retries */
    w5100_write(W5100_RTR + 0, 0x07); /* 2000ms (0x07D0 = 2000) */
    w5100_write(W5100_RTR + 1, 0xD0);
}

/* ========================================================================
 * Socket Management
 * ======================================================================== */

void socket_close(uint8_t sock_num) {
    uint16_t cr_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_CR_OFFSET);

    /* Send close command */
    w5100_write(cr_reg, CR_CLOSE);

    /* Wait for socket to reach CLOSED state */
    {
        volatile uint16_t i;
        uint16_t sr_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_SR_OFFSET);
        for (i = 0; i < 30000; ++i) {
            if (w5100_read(sr_reg) == SOCK_CLOSED) break;
        }
    }
}

uint8_t tcp_connect(uint8_t sock_num, const uint8_t* dest_ip, uint16_t dest_port, uint16_t local_port) {
    uint16_t mr_reg   = SOCK_REG(W5100_BASE, sock_num, SOCK_MR_OFFSET);
    uint16_t cr_reg   = SOCK_REG(W5100_BASE, sock_num, SOCK_CR_OFFSET);
    uint16_t sr_reg   = SOCK_REG(W5100_BASE, sock_num, SOCK_SR_OFFSET);
    uint16_t port_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_PORT0);
    uint16_t ip_reg   = SOCK_REG(W5100_BASE, sock_num, SOCK_DIPR0);
    uint16_t dport_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_DPORT0);

    /* Close any existing socket */
    socket_close(sock_num);

    /* Set TX/RX buffer sizes for this socket */
    w5100_write(SOCK_REG(W5100_BASE, sock_num, SOCK_FREGSIZE), 0x03); /* 2KB each */

    /* Configure local port */
    w5100_write(port_reg + 0, (uint8_t)((local_port >> 8) & 0xFF));
    w5100_write(port_reg + 1, (uint8_t)(local_port & 0xFF));

    /* Configure destination IP */
    w5100_write(ip_reg + 0, dest_ip[0]);
    w5100_write(ip_reg + 1, dest_ip[1]);
    w5100_write(ip_reg + 2, dest_ip[2]);
    w5100_write(ip_reg + 3, dest_ip[3]);

    /* Configure destination port */
    w5100_write(dport_reg + 0, (uint8_t)((dest_port >> 8) & 0xFF));
    w5100_write(dport_reg + 1, (uint8_t)(dest_port & 0xFF));

    /* Set TCP mode and open socket */
    w5100_write(mr_reg, SOCK_STREAM);
    w5100_write(cr_reg, CR_OPEN);

    /* Wait for INIT state */
    {
        volatile uint16_t i;
        for (i = 0; i < 30000; ++i) {
            if (w5100_read(sr_reg) == SOCK_INIT) break;
        }
    }

    /* Issue CONNECT command */
    w5100_write(cr_reg, CR_CONNECT);

    return 0;
}

uint8_t wait_for_connect(uint8_t sock_num, uint16_t timeout_ms) {
    uint16_t sr_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_SR_OFFSET);
    uint16_t ir_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_IR_OFFSET);

    /* Poll until ESTABLISHED or timeout */
    volatile uint32_t i;
    uint32_t max_iters = (uint32_t)timeout_ms * 100; /* Approximate */

    for (i = 0; i < max_iters; ++i) {
        uint8_t sr = w5100_read(sr_reg);

        if (sr == SOCK_ESTAB) {
            /* Clear connection interrupt */
            w5100_write(ir_reg, IR_CON);
            return 1;
        }

        if (sr == SOCK_CLOSED) {
            return 0; /* Connection failed */
        }
    }

    return 0; /* Timeout */
}

uint8_t socket_has_data(uint8_t sock_num) {
    uint16_t rsr_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_RX_RSR0);
    uint16_t rsr = w5100_read16(rsr_reg);
    return (rsr > 0) ? 1 : 0;
}

uint16_t socket_read(uint8_t sock_num, uint8_t* buf, uint16_t max_len) {
    uint16_t rsr_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_RX_RSR0);
    uint16_t rd_reg  = SOCK_REG(W5100_BASE, sock_num, SOCK_RX_RD0);
    uint16_t cr_reg  = SOCK_REG(W5100_BASE, sock_num, SOCK_CR_OFFSET);
    uint16_t data_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_DATA_REG(0));
    uint16_t rx_base = RX_BASE(sock_num);

    uint16_t rsr = w5100_read16(rsr_reg);
    if (rsr == 0) return 0;

    uint16_t to_read = (rsr < max_len) ? rsr : max_len;
    uint16_t rd_ptr = w5100_read16(rd_reg);

    uint16_t i;
    for (i = 0; i < to_read; ++i) {
        uint16_t offset = (rd_ptr - rx_base + i);
        buf[i] = w5100_read(offset & 0xFFFF);
    }

    /* Advance RX read pointer */
    uint16_t new_rd = (rd_ptr + to_read) & 0xFFFF;
    w5100_write16(rd_reg, new_rd);

    /* Issue RECV command to notify W5100 we've consumed the data */
    w5100_write(cr_reg, CR_RECV);

    return to_read;
}

uint8_t socket_write(uint8_t sock_num, const uint8_t* buf, uint16_t len) {
    uint16_t fs_reg    = SOCK_REG(W5100_BASE, sock_num, SOCK_TX_FREER0);
    uint16_t wr_reg    = SOCK_REG(W5100_BASE, sock_num, SOCK_TX_RD0);
    uint16_t cr_reg    = SOCK_REG(W5100_BASE, sock_num, SOCK_CR_OFFSET);
    uint16_t tx_base   = TX_BASE(sock_num);

    /* Check TX free size */
    uint16_t free_size = w5100_read16(fs_reg);
    if (free_size < len) {
        return 1; /* Not enough TX buffer space */
    }

    uint16_t wr_ptr = w5100_read16(wr_reg);

    /* Copy data to TX buffer */
    uint16_t i;
    for (i = 0; i < len; ++i) {
        uint16_t offset = (wr_ptr - tx_base + i);
        w5100_write(offset & 0xFFFF, buf[i]);
    }

    /* Advance TX write pointer */
    uint16_t new_wr = (wr_ptr + len) & 0xFFFF;
    w5100_write16(wr_reg, new_wr);

    /* Issue SEND command */
    w5100_write(cr_reg, CR_SEND);

    /* Wait for SEND to complete */
    {
        volatile uint16_t i;
        uint16_t ir_reg = SOCK_REG(W5100_BASE, sock_num, SOCK_IR_OFFSET);
        for (i = 0; i < 30000; ++i) {
            uint8_t ir = w5100_read(ir_reg);
            if (ir & IR_SEND_OK) {
                w5100_write(ir_reg, IR_SEND_OK); /* Clear flag */
                break;
            }
            if (ir & IR_TIMEOUT) {
                w5100_write(ir_reg, IR_TIMEOUT);
                return 2; /* Send timeout */
            }
        }
    }

    return 0;
}

/* ========================================================================
 * HTTP POST
 * ======================================================================== */

uint8_t http_post(
    uint8_t sock_num,
    const uint8_t* host_ip,
    uint16_t host_port,
    const char* path,
    const char* body,
    const char* content_type
) {
    static uint8_t request_buf[512];
    static uint8_t response_buf[512];

    uint16_t body_len = 0;
    while (body[body_len]) ++body_len;

    /* Build HTTP/1.1 POST request manually (no sprintf on 6502 easily) */
    uint16_t pos = 0;
    const char* p;
    uint16_t i;

    /* Request line */
    p = "POST "; while (*p) request_buf[pos++] = *p++;
    p = path;    while (*p) request_buf[pos++] = *p++;
    p = " HTTP/1.1\r\nHost: "; while (*p) request_buf[pos++] = *p++;
    p = "rustchain.org"; while (*p) request_buf[pos++] = *p++;
    request_buf[pos++] = '\r'; request_buf[pos++] = '\n';

    /* Content-Type */
    p = "Content-Type: "; while (*p) request_buf[pos++] = *p++;
    p = content_type; while (*p) request_buf[pos++] = *p++;
    request_buf[pos++] = '\r'; request_buf[pos++] = '\n';

    /* Content-Length */
    p = "Content-Length: "; while (*p) request_buf[pos++] = *p++;
    /* Convert body_len to decimal string */
    if (body_len >= 1000) { request_buf[pos++] = '0' + (body_len/1000)%10; }
    if (body_len >= 100)  { request_buf[pos++] = '0' + (body_len/100)%10; }
    if (body_len >= 10)   { request_buf[pos++] = '0' + (body_len/10)%10; }
    request_buf[pos++] = '0' + (body_len%10);
    request_buf[pos++] = '\r'; request_buf[pos++] = '\n';

    /* Connection: close */
    p = "Connection: close\r\n\r\n"; while (*p) request_buf[pos++] = *p++;

    /* Append body */
    for (i = 0; i < body_len; ++i) request_buf[pos++] = body[i];

    /* Connect to host */
    tcp_connect(sock_num, host_ip, host_port, 0x4000 + sock_num);
    if (!wait_for_connect(sock_num, 5000)) {
        socket_close(sock_num);
        return 1;
    }

    /* Send request */
    uint8_t res = socket_write(sock_num, request_buf, pos);
    if (res != 0) {
        socket_close(sock_num);
        return 2;
    }

    /* Read response (briefly, just to confirm receipt) */
    {
        volatile uint16_t delay;
        for (delay = 0; delay < 30000; ++delay) { }
    }

    /* Read whatever response came back */
    uint16_t resp_len = socket_read(sock_num, response_buf, sizeof(response_buf) - 1);
    response_buf[resp_len] = 0; /* Null terminate */

    socket_close(sock_num);

    /* Check for HTTP 200/201/202 in response */
    if (resp_len >= 9) {
        if (response_buf[7] == '2') { /* HTTP 2xx */
            return 0; /* Success */
        }
    }

    return 3; /* Unexpected response */
}
