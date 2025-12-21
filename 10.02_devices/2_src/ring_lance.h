/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2025 Plummer's Software LLC
 * Contributed under the GPL2 License
 */
#ifndef _RING_LANCE_H_
#define _RING_LANCE_H_

#include <stdint.h>

// NOTE: These structs are for documentation only.
// The emulation DMA-reads raw words from PDP memory and decodes fields explicitly.

typedef struct {
    uint16_t rmd0; // buffer address low
    uint16_t rmd1; // buffer address high (low 8 bits) + status/OWN
    uint16_t rmd2; // buffer byte count (two's complement)
    uint16_t rmd3; // message byte count / status
} qe_rx_desc_t;

typedef struct {
    uint16_t tmd0; // buffer address low
    uint16_t tmd1; // buffer address high (low 8 bits) + status/OWN
    uint16_t tmd2; // buffer byte count (two's complement)
    uint16_t tmd3; // status
} qe_tx_desc_t;

typedef struct {
    uint16_t mode;
    uint16_t padr[3];
    uint16_t ladr[4];
    uint16_t rrd_lo;
    uint16_t rrd_hi;
    uint16_t trd_lo;
    uint16_t trd_hi;
} qe_init_block_t;

#endif
