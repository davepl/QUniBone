/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2026 Plummer's Software LLC
 * Contributed under the GPL2 License
 */
#ifndef _DELQA_REGS_H_
#define _DELQA_REGS_H_

#include <stdint.h>

// Register indices (word offsets from CSR base)
#define DELQA_REG_STA0        0
#define DELQA_REG_STA1        1
#define DELQA_REG_RCVLIST_LO  2
#define DELQA_REG_RCVLIST_HI  3
#define DELQA_REG_XMTLIST_LO  4
#define DELQA_REG_XMTLIST_HI  5
#define DELQA_REG_VECTOR      6
#define DELQA_REG_CSR         7

// CSR bits (DEQNA/DELQA)
#define QE_RCV_ENABLE   0x0001
#define QE_RESET        0x0002
#define QE_NEX_MEM_INT  0x0004
#define QE_LOAD_ROM     0x0008
#define QE_XL_INVALID   0x0010
#define QE_RL_INVALID   0x0020
#define QE_INT_ENABLE   0x0040
#define QE_XMIT_INT     0x0080
#define QE_ILOOP        0x0100
#define QE_ELOOP        0x0200
#define QE_STIM_ENABLE  0x0400
#define QE_OK           0x1000
#define QE_CARRIER      0x2000
#define QE_PARITY       0x4000
#define QE_RCV_INT      0x8000

#define QE_CSR_RO       0xF8B4
#define QE_CSR_RW       0x074B
#define QE_CSR_W1       0x8080
#define QE_CSR_BP       0x0208

// Vector register bits
#define QE_VEC_MS       0x8000
#define QE_VEC_OS       0x4000
#define QE_VEC_RS       0x2000
#define QE_VEC_S3       0x1000
#define QE_VEC_S2       0x0800
#define QE_VEC_S1       0x0400
#define QE_VEC_ST       0x1C00
#define QE_VEC_IV       0x03FC
#define QE_VEC_RR       0x0002
#define QE_VEC_ID       0x0001
#define QE_VEC_RO       0x5C02
#define QE_VEC_RW       0xA3FD

// Descriptor format
#define QE_RING_WORDS 6
#define QE_RING_BYTES (QE_RING_WORDS * 2)

#define QE_RING_ADDR_HI_MASK 0x003f
#define QE_RING_ODD_BEGIN    0x0040
#define QE_RING_ODD_END      0x0080
#define QE_RING_SETUP        0x1000
#define QE_RING_EOMSG        0x2000
#define QE_RING_CHAIN        0x4000
#define QE_RING_VALID        0x8000

// Receive status word values
// Bit 15 = "used" (descriptor processed), Bit 14 = "not last" (more segments follow)
#define QE_RST_USED       0x8000  // Descriptor has been processed
#define QE_RST_NOTLAST    0x4000  // Not the last segment (more data follows)
#define QE_RST_LASTNOT    0xC000  // Used + Not last (for compatibility)
#define QE_RST_LASTERR    0x4000  // Error on last segment
#define QE_RST_LASTNOERR  0x8000  // Last segment, no error (USED bit set)
#define QE_RST_RSVD       0x00f8

#define QE_OVF        0x0001
#define QE_CRCERR     0x0002
#define QE_FRAME      0x0004
#define QE_SHORT      0x0008
#define QE_RBL_HI     0x0700
#define QE_RUNT       0x0800
#define QE_DISCARD    0x1000
#define QE_ESETUP     0x2000
#define QE_ERROR      0x4000
#define QE_LASTNOT    QE_RST_LASTNOT

#define QE_RBL_LO     0x00ff

// Transmit status bits
#define QE_CCNT       0x00f0
#define QE_FAIL       0x0100
#define QE_ABORT      0x0200
#define QE_STE16      0x0400
#define QE_NOCAR      0x0800
#define QE_LOSS       0x1000
#define QE_TDR        0x3fff

// Descriptor ownership
#define QE_NOTYET     0x8000
#define QE_INUSE      0x4000
// Maximum number of MAC address filters
#define XQ_FILTER_MAX 14

#endif // _DELQA_REGS_H_
