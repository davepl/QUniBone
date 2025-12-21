/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2025 Plummer's Software LLC
 * Contributed under the GPL2 License
 */
#ifndef _DELQA_REGS_H_
#define _DELQA_REGS_H_

#include <stdint.h>

// DELQA/DEQNA register offsets (word addresses)
#define DELQA_REG_RDP 0
#define DELQA_REG_RAP 2
#define DELQA_REG_RST 4

// CSR0 bits (LANCE-style, minimal subset for qe)
#define DELQA_CSR0_INIT 0x0001
#define DELQA_CSR0_STRT 0x0002
#define DELQA_CSR0_STOP 0x0004
#define DELQA_CSR0_TDMD 0x0008
#define DELQA_CSR0_TXON 0x0010
#define DELQA_CSR0_RXON 0x0020
#define DELQA_CSR0_INEA 0x0040
#define DELQA_CSR0_INTR 0x0080
#define DELQA_CSR0_IDON 0x0100
#define DELQA_CSR0_TINT 0x0200
#define DELQA_CSR0_RINT 0x0400
#define DELQA_CSR0_MERR 0x0800
#define DELQA_CSR0_MISS 0x1000
#define DELQA_CSR0_CERR 0x2000
#define DELQA_CSR0_BABL 0x4000
#define DELQA_CSR0_ERR  0x8000

#define DELQA_CSR0_CLEAR_BITS (DELQA_CSR0_IDON | DELQA_CSR0_TINT | DELQA_CSR0_RINT | DELQA_CSR0_ERR)
#define DELQA_CSR0_CMD_BITS (DELQA_CSR0_INIT | DELQA_CSR0_STRT | DELQA_CSR0_STOP | DELQA_CSR0_TDMD)

// Descriptor word1 flags
#define DELQA_DESC_OWN  0x8000
#define DELQA_DESC_ERR  0x4000
#define DELQA_DESC_FRAM 0x2000
#define DELQA_DESC_OFLO 0x1000
#define DELQA_DESC_CRC  0x0800
#define DELQA_DESC_BUF  0x0400
#define DELQA_DESC_STP  0x0200
#define DELQA_DESC_ENP  0x0100
#define DELQA_DESC_ADDR_HI_MASK 0x00ff

// Descriptor layout
#define DELQA_DESC_WORDS 4
#define DELQA_DESC_BYTES (DELQA_DESC_WORDS * 2)

#endif
