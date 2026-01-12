/*
 * DEQNA Ethernet Controller Emulation for QUniBone
 * (c) Dave Plummer, davepl@davepl.com, Plummer's Software LLC, 2026
 * Contributed under the BSD License
 *
 * This is a scratch implementation based on:
 *   - DEC DEQNA hardware documentation
 *   - DEQNA User's Guide (EK-DEQNA-UG)
 *   - Q-bus specification
 *   - Reading the OpenSIMH code when mine didn't work to see what it did
 *
 * This file is part of the QUniBone project, licensed under the BSD License.
 *
 *   May be based in part on the DEQNA implementation in the OpenSIMH project:
 * 
 *   Copyright (c) 1993-2008, Robert M Supnik
 *   Permission is hereby granted, free of charge, to any person obtaining a
 *   copy of this software and associated documentation files (the "Software"),
 *   to deal in the Software without restriction, including without limitation
 *   the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *   and/or sell copies of the Software, and to permit persons to whom the
 *   Software is furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * 
 * IMPLEMENTATION NOTES:
 * ---------------------
 * This file implements the DEQNA (M7504) Ethernet controller emulation.
 * Key design decisions follow documented behavior where the hardware
 * documentation is ambiguous:
 *
 * 1. LOOPBACK DETECTION: Loopback mode is active when IL=0 (internal) OR EL=1
 *    (external), independent of the RE (receive enable) bit. IL is active LOW.
 *
 * 2. DESCRIPTOR BASE RECALCULATION: When dispatch_rbdl() or dispatch_xbdl()
 *    is called, the descriptor base address is recalculated from the RCLL/RCLH
 *    or XMTL/XMTH registers. This allows the driver to update the ring pointer
 *    by writing the high register again.
 *
 * 3. RX STATUS WORDS: Normal packets use 0x0000 for last segment, 0xC000 for
 *    not-last (multi-buffer packets). Errors add appropriate error bits.
 *
 * 4. DEFERRED REGISTER WRITES: CSR and VAR are processed immediately since
 *    they don't trigger DMA. Other registers (RCLL/H, XMTL/H) are queued and
 *    processed by worker threads to avoid DMA deadlocks where the PRU waits
 *    for bus grant while the CPU polls CSR.
 * 
 *    TRANSMIT:
 * 
 *       Driver                          DEQNA
 *       ──────                          ─────
 *       1. Allocate buffer
 *       2. Copy packet data to buffer
 *       3. Fill descriptor:
 *           - Set buffer address
 *           - Set length  
 *           - Set V=1, E=1
 *       4. Write XMTH register ──────► Triggers TX processing
 *                                      5. Read descriptor via DMA
 *                                      6. Write 0xFFFF to word 0 (claim it)
 *                                      7. DMA packet data from buffer
 *                                      8. Transmit packet
 *                                      9. Write status to words 4-5
 *.                                     10. Set XI (transmit interrupt)
 *                              ◄────── 11. Interrupt
 *       12. Read status, reclaim descriptor
 *
 *    RECEIVE:
 *
 *       Driver                          DEQNA
 *       ──────                          ─────
 *       1. Allocate buffers
 *       2. Fill descriptors:
 *           - Set buffer address
 *           - Set V=1
 *       3. Write RCLH register ──────► Triggers RX list ready
 *                                      [Packet arrives from network]
 *                                      4. Read descriptor via DMA
 *                                      5. Write 0xFFFF to word 0 (claim it)
 *                                      6. DMA packet data TO buffer
 *                                      7. Write status + length to words 4-5
 *                                      8. Set RI (receive interrupt)
 *                              ◄────── 9. Interrupt
 *       10. Read packet, reclaim descriptor
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <climits>
#include <algorithm>
#include <vector>
#include <utility>

#include "logger.hpp"
#include "utils.hpp"
#include "timeout.hpp"
#include "qunibus.h"
#include "qunibusadapter.hpp"
#include "ddrmem.h"
#include "deqna.hpp"

#if !defined(QBUS)
#error "DEQNA is a QBUS-only device"
#endif

/*
 * Ethernet framing constants
 * ---------------------------
 * These define the valid packet size range. Packets smaller than ETH_MIN_PACKET
 * are padded with zeros; packets larger than ETH_MAX_PACKET are truncated.
 * ETH_FRAME_SIZE includes space for CRC (added by hardware, not seen here).
 */
static const size_t ETH_MIN_PACKET = 60;    // Minimum Ethernet frame (no CRC)
static const size_t ETH_MAX_PACKET = 1514;  // Maximum Ethernet frame (no CRC)
static const size_t ETH_FRAME_SIZE = 1518;  // Frame + CRC space
static const size_t QNA_MAX_RCV_PACKET = 1600;  // Buffer size for oversized frames
static const size_t QNA_LONG_PACKET = 0x0600;   // 1536 bytes - jumbo threshold

/*
 * Queue and timer constants
 */
static const unsigned QNA_QUE_MAX = 64;          // Max packets in RX queue (reduced to prevent flood starvation)
static const unsigned QNA_SERVICE_INTERVAL = 100; // Timer service rate (Hz)
static const unsigned QNA_SYSTEM_ID_SECS = 540;   // MOP system ID interval (9 min)
static const unsigned QNA_HW_SANITY_SECS = 240;   // Hardware sanity timeout (4 min)

static thread_local const char *deqna_thread_ctx = "main";

/*
 * Descriptor ring control bits (word 1 of descriptor)
 * These are mapped from deqna_regs.h QE_RING_* constants for clarity.
 */
static const uint16_t QNA_DSC_V = QE_RING_VALID;     // Descriptor is valid
static const uint16_t QNA_DSC_C = QE_RING_CHAIN;     // Chain to address in words 1,2
static const uint16_t QNA_DSC_E = QE_RING_EOMSG;     // End of message (last segment)
static const uint16_t QNA_DSC_S = QE_RING_SETUP;     // Setup packet (TX only)
static const uint16_t QNA_DSC_L = QE_RING_ODD_END;   // Odd byte at end (subtract 1)
static const uint16_t QNA_DSC_H = QE_RING_ODD_BEGIN; // Odd byte at start (subtract 1)

/*
 * CSR (Control/Status Register) bit definitions
 * Mapped from deqna_regs.h QE_* constants for code clarity.
 */
static const uint16_t QNA_CSR_RI = QE_RCV_INT;       // Receive interrupt pending
static const uint16_t QNA_CSR_PE = QE_PARITY;        // Parity error
static const uint16_t QNA_CSR_CA = QE_CARRIER;       // Carrier detect
static const uint16_t QNA_CSR_OK = QE_OK;            // Transceiver OK
static const uint16_t QNA_CSR_SE = QE_STIM_ENABLE;   // Sanity timer enable
static const uint16_t QNA_CSR_EL = QE_ELOOP;         // External loopback
static const uint16_t QNA_CSR_IL = QE_ILOOP;         // Internal loopback
static const uint16_t QNA_CSR_XI = QE_XMIT_INT;      // Transmit interrupt pending
static const uint16_t QNA_CSR_IE = QE_INT_ENABLE;    // Interrupt enable
static const uint16_t QNA_CSR_RL = QE_RL_INVALID;    // Receive list invalid
static const uint16_t QNA_CSR_XL = QE_XL_INVALID;    // Transmit list invalid
static const uint16_t QNA_CSR_NI = QE_NEX_MEM_INT;   // Non-existent memory interrupt
static const uint16_t QNA_CSR_SR = QE_RESET;         // Software reset
static const uint16_t QNA_CSR_RE = QE_RCV_ENABLE;    // Receive enable

static const uint16_t QNA_CSR_RO = QE_CSR_RO;        // Read-only bits mask
static const uint16_t QNA_CSR_RW = QE_CSR_RW;        // Read-write bits mask
static const uint16_t QNA_CSR_W1 = QE_CSR_W1;        // Write-1-to-clear bits mask
static const uint16_t QNA_CSR_BP = QE_CSR_BP;        // Boot/diag ROM request bits
static const uint16_t QNA_CSR_XIRI = (QNA_CSR_XI | QNA_CSR_RI);  // Any interrupt pending

/*
 * VAR (Vector Address Register) bit definitions
 */
static const uint16_t QNA_VEC_MS = QE_VEC_MS;  // Mode select (kept cleared for DEQNA)
static const uint16_t QNA_VEC_OS = QE_VEC_OS;  // Option switch
static const uint16_t QNA_VEC_RS = QE_VEC_RS;  // Request self-test
static const uint16_t QNA_VEC_ST = QE_VEC_ST;  // Self-test status
static const uint16_t QNA_VEC_IV = QE_VEC_IV;  // Interrupt vector mask
static const uint16_t QNA_VEC_ID = QE_VEC_ID;  // Identity test bit
static const uint16_t QNA_VEC_RO = QE_VEC_RO;  // Read-only bits mask
static const uint16_t QNA_VEC_RW = QE_VEC_RW;  // Read-write bits mask

/*
 * Version string - increment on each code change to verify running code freshness
 */
static const char *DEQNA_VERSION = "v048";  // sw_reset preserves vector, quiets interrupts

/*
 * Setup packet bit definitions (length field encodes these)
 */
static const uint16_t QNA_SETUP_MC = 0x0001;  // Accept all multicast
static const uint16_t QNA_SETUP_PM = 0x0002;  // Promiscuous mode
static const uint16_t QNA_SETUP_LD = 0x000C;  // LED control bits
static const uint16_t QNA_SETUP_ST = 0x0070;  // Sanity timer setting

/*
 * Utility functions for byte/word manipulation
 */
static uint8_t word_low(uint16_t w)
{
    return static_cast<uint8_t>(w & 0xff);
}

static uint8_t word_high(uint16_t w)
{
    return static_cast<uint8_t>((w >> 8) & 0xff);
}

/*
 * mac_is_zero
 * Purpose: central helper to validate all-zero MACs.
 * Behavior: checks six bytes for zeros and returns true if all are zero.
 * Notes: used to gate setup and filter logic; expects a 6-byte array.
 */
static bool mac_is_zero(const uint8_t *mac)
{
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

/*
 * mac_is_broadcast
 * Purpose: detect the Ethernet broadcast address.
 * Behavior: returns true when all six bytes are 0xff.
 * Notes: used in receive accept path and filter logic.
 */
static bool mac_is_broadcast(const uint8_t *mac)
{
    return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
           mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff;
}

/*
 * mac_is_multicast
 * Purpose: detect multicast addresses.
 * Behavior: checks the low bit of the first byte.
 * Notes: callers should have validated length; this does not validate OUI.
 */
static bool mac_is_multicast(const uint8_t *mac)
{
    return (mac[0] & 0x01) != 0;
}

/*
 * mac_equal
 * Purpose: byte-wise MAC comparison utility.
 * Behavior: returns true if two 6-byte MACs are identical.
 * Notes: simple memcmp wrapper for clarity in filter code.
 */
static bool mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

/*
 * DEQNA Constructor
 * ------------------
 * Initializes the device with:
 *   - Single deterministic state-machine worker
 *   - Eight device registers (SA0-5, VAR, CSR)
 *   - Default MAC address (DEC OUI with a fixed suffix)
 *   - Packet buffers sized for maximum Ethernet frames
 */
deqna_c::deqna_c() : dec_ether_base_c()
{
    set_workers_count(1);  // Single deterministic state-machine worker

    name.value = "deqna";
    type_name.value = "DEQNA";
    log_label = "deqna";

    set_default_bus_params(DEQNA_DEFAULT_ADDR, DEQNA_DEFAULT_SLOT, DEQNA_DEFAULT_VECTOR, DEQNA_DEFAULT_LEVEL);
    dma_request.set_priority_slot(priority_slot.value);
    dma_desc_request.set_priority_slot(priority_slot.value);
    intr_request.set_priority_slot(priority_slot.value);
    intr_request.set_level(intr_level.value);
    intr_request.set_vector(intr_vector.value);

    /*
     * Register layout (8 registers, 16 bytes total at base address):
     *   +0: SA0 (Station Address byte 0, read-only)
     *   +2: SA1 (Station Address byte 1, read-only)
     *   +4: RCLL (Receive list address low)
     *   +6: RCLH (Receive list address high - triggers RX processing)
     *   +8: XMTL (Transmit list address low)
     *  +10: XMTH (Transmit list address high - triggers TX processing)
     *  +12: VAR  (Vector Address Register)
     *  +14: CSR  (Control/Status Register)
     */
    register_count = 8;

    reg_sta_addr[0] = &(this->registers[0]);
    strcpy(reg_sta_addr[0]->name, "STA0");
    reg_sta_addr[0]->active_on_dati = false;
    reg_sta_addr[0]->active_on_dato = false;
    reg_sta_addr[0]->reset_value = 0;
    reg_sta_addr[0]->writable_bits = 0x0000;  // Read-only

    reg_sta_addr[1] = &(this->registers[1]);
    strcpy(reg_sta_addr[1]->name, "STA1");
    reg_sta_addr[1]->active_on_dati = false;
    reg_sta_addr[1]->active_on_dato = false;
    reg_sta_addr[1]->reset_value = 0;
    reg_sta_addr[1]->writable_bits = 0x0000;

    reg_rcvlist_lo = &(this->registers[2]);
    strcpy(reg_rcvlist_lo->name, "RCLL");
    reg_rcvlist_lo->active_on_dati = false;
    reg_rcvlist_lo->active_on_dato = true;
    reg_rcvlist_lo->reset_value = 0;
    reg_rcvlist_lo->writable_bits = 0xffff;
    reg_sta_addr[2] = reg_rcvlist_lo;

    reg_rcvlist_hi = &(this->registers[3]);
    strcpy(reg_rcvlist_hi->name, "RCLH");
    reg_rcvlist_hi->active_on_dati = false;
    reg_rcvlist_hi->active_on_dato = true;
    reg_rcvlist_hi->reset_value = 0;
    reg_rcvlist_hi->writable_bits = 0xffff;
    reg_sta_addr[3] = reg_rcvlist_hi;

    reg_xmtlist_lo = &(this->registers[4]);
    strcpy(reg_xmtlist_lo->name, "XMTL");
    reg_xmtlist_lo->active_on_dati = false;
    reg_xmtlist_lo->active_on_dato = true;
    reg_xmtlist_lo->reset_value = 0;
    reg_xmtlist_lo->writable_bits = 0xffff;
    reg_sta_addr[4] = reg_xmtlist_lo;

    reg_xmtlist_hi = &(this->registers[5]);
    strcpy(reg_xmtlist_hi->name, "XMTH");
    reg_xmtlist_hi->active_on_dati = false;
    reg_xmtlist_hi->active_on_dato = true;
    reg_xmtlist_hi->reset_value = 0;
    reg_xmtlist_hi->writable_bits = 0xffff;
    reg_sta_addr[5] = reg_xmtlist_hi;

    reg_vector = &(this->registers[6]);
    strcpy(reg_vector->name, "VECTOR");
    reg_vector->active_on_dati = false;
    reg_vector->active_on_dato = true;
    reg_vector->reset_value = 0;
    reg_vector->writable_bits = 0xffff;

    reg_csr = &(this->registers[7]);
    strcpy(reg_csr->name, "CSR");
    reg_csr->active_on_dati = false;
    reg_csr->active_on_dato = true;
    reg_csr->reset_value = 0;
    reg_csr->writable_bits = 0xffff;

    ifname.value = "eth0";
    mac.value = "";
    promisc.value = true;
    rx_slots.value = 0;
    tx_slots.value = 0;
    rx_start_delay_ms.value = 0;
    trace.value = false;
    version.value = DEQNA_VERSION;

    // Default MAC address for the emulated adapter (DEC OUI + fixed suffix)
    mac_addr[0] = 0x08;
    mac_addr[1] = 0x00;
    mac_addr[2] = 0x2B;
    mac_addr[3] = 0xAA;
    mac_addr[4] = 0xBB;
    mac_addr[5] = 0xCC;

    read_buffer.msg.resize(ETH_FRAME_SIZE);
    write_buffer.msg.resize(ETH_FRAME_SIZE);

    reset_controller();
}

deqna_c::~deqna_c()
{
#ifdef HAVE_PCAP
    pcap.close();
#endif
}

bool deqna_c::parse_mac(const std::string &text, uint8_t out[6])
{
    unsigned values[6];
    if (text.empty())
        return false;
    if (sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6)
        return false;

    for (int i = 0; i < 6; ++i) {
        if (values[i] > 0xff)
            return false;
        out[i] = static_cast<uint8_t>(values[i]);
    }
    return true;
}

bool deqna_c::on_param_changed(parameter_c *param)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (param == &priority_slot) {
        dma_request.set_priority_slot(priority_slot.new_value);
        dma_desc_request.set_priority_slot(priority_slot.new_value);
        intr_request.set_priority_slot(priority_slot.new_value);
    } else if (param == &intr_level) {
        intr_request.set_level(intr_level.new_value);
    } else if (param == &intr_vector) {
        intr_request.set_vector(intr_vector.new_value);
    } else if (param == &ifname) {
        if (handle) {
            WARNING("DEQNA: ifname cannot be changed while device is installed");
            return false;
        }
    } else if (param == &promisc) {
        update_pcap_filter();
    } else if (param == &mac) {
        if (mac.new_value.empty()) {
            mac_override = false;
        } else if (!parse_mac(mac.new_value, mac_addr)) {
            ERROR("DEQNA: invalid MAC format '%s'", mac.new_value.c_str());
            return false;
        } else {
            mac_override = true;
        }
        update_mac_checksum();
        if (handle)
            update_station_regs();
        update_pcap_filter();
    }

    return qunibusdevice_c::on_param_changed(param);
}

bool deqna_c::on_before_install(void)
{
#ifndef HAVE_PCAP
    ERROR("DEQNA: libpcap support not compiled in - install libpcap-dev and rebuild with HAVE_PCAP");
    return false;
#else
    INFO("DEQNA: emulation %s", DEQNA_VERSION);

    if (ifname.value.empty()) {
        ERROR("DEQNA: ifname must be set");
        return false;
    }

    if (!pcap.open(ifname.value, promisc.value, 2048, 1)) {
        ERROR("DEQNA: failed to open pcap on %s: %s", ifname.value.c_str(),
              pcap.last_error().c_str());
        return false;
    }

    INFO("DEQNA: PCAP opened successfully on interface %s", ifname.value.c_str());

    ifname.readonly = true;
    mac.readonly = true;
    promisc.readonly = true;
    rx_slots.readonly = true;
    tx_slots.readonly = true;
    rx_start_delay_ms.readonly = true;

    update_transceiver_bits();
    update_csr_reg();
    update_pcap_filter();

    return true;
#endif
}

void deqna_c::on_after_install(void)
{
    reset_controller();
}

void deqna_c::on_after_uninstall(void)
{
#ifdef HAVE_PCAP
    pcap.close();
#endif

    ifname.readonly = false;
    mac.readonly = false;
    promisc.readonly = false;
    rx_slots.readonly = false;
    tx_slots.readonly = false;
    rx_start_delay_ms.readonly = false;

    update_transceiver_bits();
    update_csr_reg();
}

void deqna_c::on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge)
{
    UNUSED(aclo_edge);
    if (dclo_edge == SIGNAL_EDGE_RAISING)
        reset_controller();
}

void deqna_c::on_init_changed(void)
{
    if (init_asserted)
        reset_controller();
}

void deqna_c::update_mac_checksum(void)
{
    uint32_t checksum = 0;
    const uint32_t wmask = 0xffff;

    for (size_t i = 0; i < 6; i += 2) {
        checksum <<= 1;
        if (checksum > wmask)
            checksum -= wmask;
        checksum += (static_cast<uint32_t>(mac_addr[i]) << 8) | mac_addr[i + 1];
        if (checksum > wmask)
            checksum -= wmask;
    }
    if (checksum == wmask)
        checksum = 0;

    mac_checksum[0] = static_cast<uint8_t>(checksum & 0xff);
    mac_checksum[1] = static_cast<uint8_t>(checksum >> 8);
}

void deqna_c::update_station_regs(void)
{
    if (!handle)
        return;

    for (int i = 0; i < 6; ++i) {
        uint8_t value = mac_addr[i];
        if (i < 2 && (csr & QNA_CSR_EL))
            value = mac_checksum[i];
        uint16_t word = static_cast<uint16_t>(0xff00 | value);
        set_register_dati_value(reg_sta_addr[i], word, "update_station_regs");
    }
}

void deqna_c::update_vector_reg(void)
{
    if (!handle)
        return;
    set_register_dati_value(reg_vector, var, "update_vector_reg");
}

void deqna_c::update_csr_reg(void)
{
    if (!handle)
        return;
    set_register_dati_value(reg_csr, csr, "update_csr_reg");
}

/*
 * update_transceiver_bits - Update OK and CA bits based on network state
 *
 * OK (transceiver OK) is set when pcap interface is open and operational.
 * CA (carrier absent) is always cleared - we assume cable is always connected.
 * BUGBUG (Davepl) Can we get physical link state from libpcap?
 */
void deqna_c::update_transceiver_bits(void)
{
    if (pcap.is_open())
        csr |= QNA_CSR_OK;
    else
        csr &= ~QNA_CSR_OK;

    csr &= ~QNA_CSR_CA;  // Always report carrier present
}

/*
 * Interrupt management
 * ---------------------
 * Interrupts are one-shot: when RI/XI becomes set with IE=1, we assert irq
 * and raise an interrupt. When the interrupt vector is fetched (acknowledged),
 * we clear irq so a new interrupt can be raised for subsequent RI/XI events.
 *
 * This matches SIMH behavior where xq_int() auto-clears irq when the vector
 * is fetched. The RI/XI bits in CSR remain set until the driver clears them
 * via W1C - this is separate from the interrupt acknowledgment.
 *
 * Key: intr_request.complete is set by qunibusadapter when the vector is
 * fetched. service_intr_complete() consumes this and clears irq (like SIMH xq_int()).
 */
void deqna_c::set_int(void)
{
    irq = true;
    if (intr_pending_since_ns == 0)
        intr_pending_since_ns = timeout_c::abstime_ns();
    DEBUG("DEQNA: set_int() called, irq=1, csr=%06o ie=%d", csr, (csr & QNA_CSR_IE) ? 1 : 0);
    update_intr();
}

void deqna_c::clr_int(void)
{
    irq = false;
    intr_pending_since_ns = 0;
    note_intr_deasserted();
    DEBUG("DEQNA: clr_int() called, irq=0, csr=%06o ie=%d", csr, (csr & QNA_CSR_IE) ? 1 : 0);
    update_intr();
}

/*
 * csr_set_clr - Atomically set and clear CSR bits with interrupt side effects
 *
 * This function handles the interrupt logic:
 * - If IE transitions high and RI/XI is set, assert interrupt
 * - If RI or XI transitions high while IE=1, assert interrupt
 * - If both RI and XI are cleared, deassert interrupt
 * - If IE transitions low, deassert interrupt
 *
 * SIMPLIFIED: Interrupts are asserted/deasserted immediately.
 * The QBUS can handle concurrent DMA and interrupts.
 */
void deqna_c::csr_set_clr(uint16_t set_bits, uint16_t clear_bits)
{
    uint16_t saved_csr = csr;
    csr = static_cast<uint16_t>((csr | set_bits) & ~clear_bits);

    // Determine if we need to change interrupt state
    bool should_assert = (csr & QNA_CSR_IE) && (csr & QNA_CSR_XIRI) && !irq;
    bool should_deassert = irq && (!(csr & QNA_CSR_IE) || !(csr & QNA_CSR_XIRI));

    // Debug: trace XI/RI interrupt decisions
    if ((set_bits & QNA_CSR_XIRI) && !should_assert) {
        DEBUG("DEQNA: XI/RI set but NOT asserting INTR: csr=%06o IE=%d XI=%d RI=%d irq=%d",
              csr, (csr & QNA_CSR_IE) ? 1 : 0, (csr & QNA_CSR_XI) ? 1 : 0,
              (csr & QNA_CSR_RI) ? 1 : 0, irq ? 1 : 0);
    }

    if (should_deassert)
        clr_int();
    else if (should_assert)
        set_int();

    update_transceiver_bits();
    update_csr_reg();

    if (trace.value && ((saved_csr ^ csr) & (QNA_CSR_RL | QNA_CSR_XL | QNA_CSR_RI | QNA_CSR_XI))) {
        DEBUG("DEQNA: CSR change prev=%06o now=%06o set=%06o clr=%06o",
                saved_csr, csr, set_bits, clear_bits);
    }
}

void deqna_c::note_xl_set(const char *reason, uint32_t desc_ba, const uint16_t *desc_words,
        size_t desc_word_count)
{
    uint16_t csr_snapshot = 0;
    uint16_t xmth = 0;
    uint16_t xmtl = 0;
    uint32_t xbdl_snapshot = 0;
    bool xl_already = false;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        xl_already = (csr & QNA_CSR_XL) != 0;
        csr_snapshot = csr;
        xmth = xbdl[1];
        xmtl = xbdl[0];
        xbdl_snapshot = xbdl_ba;
    }
    if (xl_already)
        return;

    uint16_t words[QE_RING_WORDS] = {0};
    if (desc_words && desc_word_count) {
        const size_t count = std::min(desc_word_count, static_cast<size_t>(QE_RING_WORDS));
        for (size_t i = 0; i < count; ++i)
            words[i] = desc_words[i];
    }

    WARNING("DEQNA: XL set (%s) csr=%06o XMTH=%06o XMTL=%06o XBDL=%06o desc=%06o "
            "w0=%06o w1=%06o w2=%06o w3=%06o w4=%06o w5=%06o",
            reason ? reason : "unknown", csr_snapshot, xmth, xmtl, xbdl_snapshot, desc_ba,
            words[0], words[1], words[2], words[3], words[4], words[5]);
}

void deqna_c::service_intr_complete(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!intr_request.complete)
        return;
    intr_request.complete = false;

    // OpenSIMH-compatible: clear the controller interrupt latch on vector fetch.
    // Note RI/XI bits remain set in CSR until cleared by the guest via W1C.
    clr_int();
}

bool deqna_c::wait_for_interrupt_ack(void)
{
    // SIMPLIFIED: Don't block the worker loop waiting for interrupt acknowledgment.
    // The real QBUS allows concurrent interrupt and DMA operations.
    // The PRU should handle BR/IACK asynchronously from NPR/DMA.
    return false;
}

void deqna_c::nxm_error(void)
{
    WARNING("DEQNA: NXM error triggered!");
    note_xl_set("nxm", 0, nullptr, 0);
    const uint16_t set_bits = QNA_CSR_XI | QNA_CSR_XL | QNA_CSR_RL | QNA_CSR_NI;
    csr_set_clr(set_bits, 0);
    stats.fail++;
    stat_tx_errors.value = stats.fail;
}

bool deqna_c::rx_ready(void)
{
    // Receiver must be enabled (RE=1) AND RX list must be valid (RL=0)
    if (!(csr & QNA_CSR_RE))
        return false;
    if (csr & QNA_CSR_RL)
        return false;  // RX list invalid - descriptors not set up yet
    if (!rx_delay_active)
        return true;
    if (timeout_c::abstime_ns() >= rx_enable_deadline_ns) {
        rx_delay_active = false;
        return true;
    }
    return false;
}

void deqna_c::start_rx_delay(void)
{
    if (rx_start_delay_ms.value == 0) {
        rx_delay_active = false;
        return;
    }
    rx_delay_active = true;
    rx_enable_deadline_ns = timeout_c::abstime_ns() +
            static_cast<uint64_t>(rx_start_delay_ms.value) * 1000000ull;
}

/*
 * update_intr - Signal interrupt state change to bus adapter
 *
 * Uses edge detection to only signal on transitions, avoiding
 * redundant bus operations.
 *
 * The SIMH-compatible interrupt auto-clear happens in service_intr_complete()
 * when we detect that intr_request.complete is true (vector was fetched).
 * This clears irq, allowing new RI/XI events to trigger new interrupts.
 */
void deqna_c::update_intr(void)
{
    if (reset_in_progress.load(std::memory_order_acquire)) {
        if (irq && qunibusadapter)
            qunibusadapter->cancel_INTR(intr_request);
        intr_request.edge_detect_reset();
        irq = false;
        return;
    }

    // Assert interrupt based purely on irq state. Previous versions gated this
    // on dma_in_progress==0 to work around PRU arbitration issues, but that
    // caused TX completion interrupts to be blocked during RX floods, leading
    // to watchdog timeout and qerestart. The PRU should handle concurrent
    // NPR (DMA) and BR (interrupt) requests properly per QBUS spec.
    bool level = irq;

    switch (intr_request.edge_detect(level)) {
    case intr_request_c::INTERRUPT_EDGE_RAISING:
        note_intr_asserted();
        DEBUG("DEQNA: update_intr RAISING edge, calling INTR vec=%03o level=%d csr=%06o",
              intr_request.get_vector(), intr_request.get_level(), csr);
        qunibusadapter->INTR(intr_request, nullptr, 0);
        break;
    case intr_request_c::INTERRUPT_EDGE_FALLING:
        DEBUG("DEQNA: update_intr FALLING edge, cancelling INTR csr=%06o", csr);
        qunibusadapter->cancel_INTR(intr_request);
        break;
    default:
        // No edge - interrupt state unchanged
        break;
    }
}

/*
 * process_deferred_interrupts - Signal any deferred interrupt state changes
 *
 * Must be called AFTER all DMA operations are complete. This prevents
 * deadlock where the interrupt blocks the CPU from responding to DMA.
 * csr_set_clr() sets the deferred flags instead of calling set_int/clr_int
 * directly to ensure interrupts are only raised when it's safe.
 * 
 * Example timing diagram of deferred interrupt processing to avoid DMA deadlock:
 *  
 *      Time    TX Path                RX Path                PRU                  CPU
 *      ────    ─────────              ─────────              ───                  ───
 *      1      DMA read desc                                 [doing TX DMA]        
 *      2      DMA write status                              [doing TX DMA]        
 *      3      csr |= XI                                                          
 *      4      set_int() ─────────────────────────────────►  Assert BR line
 *      5                             DMA read desc ───────► [start RX DMA]       Sees BR, tries IACK
 *      6                                                    Can't respond!       Waiting for vector...
 *      7      Next DMA ──────────────────────────────────►  Blocked (bus busy)   Still waiting...
 *      8                             [waiting for DMA]      STUCK                TIMEOUT!
 *
 *      The deadlock:
 *
 *          When we raise INTR (step 4), the PRU asserts the BR (bus request) line
 *          The PDP-11 CPU sees the interrupt request and tries to acknowledge it (IACK cycle)
 *          But the RX path started a DMA at step 5, so the PRU is busy with that DMA
 *          The PRU can't respond to the IACK because it's mid-DMA
 *          The CPU times out waiting for the interrupt vector
 *          Meanwhile, TX's next DMA is also blocked because the bus is stuck.
 *          This issues doesn't confront SIMH because SIMH's bus model is not cycle-accurate.
 *          The simulated CPU will see this flag on its next instruction and take the interrupt. 
 *          There's no actual hardware signaling, no bus arbitration, no concurrent workers.
 */

void deqna_c::process_deferred_interrupts(void)
{
    // SIMPLIFIED: This function is now a no-op. Interrupts are handled directly
    // in csr_set_clr() when RI/XI bits change. Keeping this function as a stub
    // to avoid modifying all call sites.
}

/*
}

/*
 * reset_sanity_timer - Reset the watchdog timer
 *
 * Called after each successful transmit. If the timer expires before
 * the next TX, the controller is reset (prevents hung driver situations).
 */
void deqna_c::reset_sanity_timer(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!sanity.enabled)
        return;
    sanity.timer = sanity.max;
}

/*
 * service_timers - Periodic timer service (called from state-machine loop)
 *
 * Handles:
 * - Sanity timer: decrements and resets controller on expiry
 * - System ID timer: sends MOP system ID multicast every ~9 minutes
 */
void deqna_c::service_timers(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint64_t now_ns = timeout_c::abstime_ns();
    if (timers_last_service_ns == 0)
        timers_last_service_ns = now_ns;

    const uint64_t tick_ns = 1000000000ull / QNA_SERVICE_INTERVAL; // 10ms @ 100Hz
    uint64_t elapsed_ns = now_ns - timers_last_service_ns;
    uint64_t ticks64 = elapsed_ns / tick_ns;
    if (ticks64 == 0)
        return;
    if (ticks64 > static_cast<uint64_t>(INT_MAX))
        ticks64 = static_cast<uint64_t>(INT_MAX);
    const int ticks = static_cast<int>(ticks64);
    timers_last_service_ns += static_cast<uint64_t>(ticks) * tick_ns;

    if (sanity.enabled) {
        sanity.timer -= ticks;
        if (sanity.timer <= 0) {
            WARNING("DEQNA: sanity timer expired");
            reset_controller();
            return;
        }
    }

    // DEQNA does not autonomously emit MOP system ID responses.
}

/*
 * reset_controller - Full hardware reset
 *
 * Called on:
 * - Power-up (DCLO deassertion)
 * - BINIT signal assertion
 * - Sanity timer expiration
 *
 * Clears all state, sets RL and XL (lists invalid), and updates all registers.
 */
void deqna_c::reset_controller(void)
{
    reset_in_progress.store(true, std::memory_order_release);
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    // Clear descriptor ring pointers
    rbdl[0] = 0;
    rbdl[1] = 0;
    xbdl[0] = 0;
    xbdl[1] = 0;

    // Initialize VAR with DEQNA-compatible vector (MS always cleared)
    var = static_cast<uint16_t>(intr_vector.value & QNA_VEC_IV);
    deqna_lock = true;
    // Initialize CSR with both lists invalid (RL=1, XL=1)
    // Match SIMH: set CSR directly, then clear interrupt unconditionally
    csr = static_cast<uint16_t>(QNA_CSR_RL | QNA_CSR_XL);

    // Clear interrupt state BEFORE updating transceiver bits or registers
    // This matches SIMH's unconditional xq_clrint() after CSR setup
    irq = false;
    intr_pending_since_ns = 0;
    if (qunibusadapter)
        qunibusadapter->cancel_INTR(intr_request);
    intr_request.edge_detect_reset();
    intr_request.set_vector(var & QNA_VEC_IV);

    // Now safe to update MAC checksum and transceiver bits
    // update_transceiver_bits() sets OK directly in csr (no interrupt side effects)
    update_mac_checksum();
    update_transceiver_bits();
    update_station_regs();
    update_vector_reg();
    update_csr_reg();

    rbdl_ba = 0;
    xbdl_ba = 0;
    last_rbdl_start = 0;
    rbdl_wrap_guard = false;

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        if (!read_queue.empty()) {
            WARNING("DEQNA: reset_controller clearing RX queue (size=%zu)", read_queue.size());
        }
        read_queue.clear();
        read_queue_loss = 0;
    }
    write_buffer.len = 0;
    write_buffer.used = 0;

    setup.valid = false;
    setup.promiscuous = false;
    setup.multicast = false;

    rbdl_pending = false;
    rbdl_hi_written = false;
    tx_state = tx_state_enum::idle;
    tx_kick = false;
    xbdl_hi_written = false;
    tx_wait_ba = 0;
    tx_wait_until_ns = 0;
    tx_v0_retries = 0;
    tx_invalid_dumped = false;
    pending_reg_mask.store(0, std::memory_order_release);
    for (int i = 0; i < 8; ++i) {
        pending_reg_byteflags[i].store(0, std::memory_order_relaxed);
        pending_reg_value[i].store(0, std::memory_order_relaxed);
    }

    sanity.enabled = 0;
    sanity.quarter_secs = QNA_HW_SANITY_SECS * 4;
    sanity.max = static_cast<int>(QNA_HW_SANITY_SECS * QNA_SERVICE_INTERVAL);
    sanity.timer = sanity.max;
    timers_last_service_ns = timeout_c::abstime_ns();

    idtmr = 0;

    // Match SIMH: update_transceiver_bits() already set OK in CSR directly.
    // Don't use csr_set_clr() here as it has interrupt side effects.
    // Just update the register value that the PDP-11 sees.
    update_csr_reg();

    update_pcap_filter();
    reset_in_progress.store(false, std::memory_order_release);
}

/*
 * sw_reset - Software reset
 *
 * Clears all state, sets RL and XL (lists invalid), and updates all registers.
 * Called when software writes to the CSR reset bit.
 */

void deqna_c::sw_reset(void)
{
    // Signal reset early so worker loops can abort
    reset_in_progress.store(true, std::memory_order_release);

    // Brief delay to let any in-flight descriptor processing notice reset_in_progress
    // and abort. DMA operations are short (a few microseconds) so 1ms is plenty.
    timeout_c::wait_ms(1);

    std::lock_guard<std::recursive_mutex> state_lock(state_mutex);

    if (trace.value) {
        DEBUG("DEQNA: sw_reset() begin csr=%06o", csr);
    }

    // Clear pending dispatch flags BEFORE modifying CSR
    rbdl_pending = (rbdl[0] || rbdl[1]);
    tx_state = tx_state_enum::idle;
    tx_kick = (xbdl[0] || xbdl[1]);
    tx_wait_ba = 0;
    tx_wait_until_ns = 0;
    tx_v0_retries = 0;
    tx_invalid_dumped = false;
    rbdl_ba = 0;
    xbdl_ba = 0;
    write_buffer.len = 0;
    write_buffer.used = 0;

    // Reset CSR to lists invalid (RL=1, XL=1)
    // Match SIMH: set CSR directly, then clear interrupt unconditionally
    csr = static_cast<uint16_t>(QNA_CSR_XL | QNA_CSR_RL);

    // Clear interrupt state BEFORE updating transceiver bits or registers
    // This matches SIMH's unconditional xq_clrint() after CSR setup
    irq = false;
    intr_pending_since_ns = 0;
    if (qunibusadapter)
        qunibusadapter->cancel_INTR(intr_request);
    intr_request.edge_detect_reset();
    // Preserve the vector programmed in VAR register
    intr_request.set_vector(var & QNA_VEC_IV);

    // Now safe to update MAC checksum and transceiver bits
    // update_transceiver_bits() sets OK directly in csr (no interrupt side effects)
    update_mac_checksum();
    update_transceiver_bits();
    update_station_regs();
    update_vector_reg();
    update_csr_reg();

    // Reset dma_in_progress counter to known state (used by DMA helper functions)
    dma_in_progress.store(0, std::memory_order_release);

    // Clear any pending register writes captured during reset.
    pending_reg_mask.store(0, std::memory_order_release);
    for (int i = 0; i < 8; ++i) {
        pending_reg_byteflags[i].store(0, std::memory_order_relaxed);
        pending_reg_value[i].store(0, std::memory_order_relaxed);
    }

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        if (!read_queue.empty()) {
            DEBUG("DEQNA: sw_reset clearing RX queue (size=%zu loss=%u)",
                    read_queue.size(), read_queue_loss);
        }
        read_queue.clear();
        read_queue_loss = 0;
    }
    last_rbdl_start = 0;
    rbdl_wrap_guard = false;

    setup.valid = false;
    setup.multicast = false;
    setup.promiscuous = false;
    sanity.timer = sanity.max;
    timers_last_service_ns = timeout_c::abstime_ns();

    update_pcap_filter();

    reset_in_progress.store(false, std::memory_order_release);
}

/* update_pcap_filter - Update libpcap filter based on current setup
 *
 * Constructs a pcap filter string based on the current MAC address,
 * promiscuous mode, and multicast settings. Applies the filter to
 * the pcap interface.
 */

void deqna_c::update_pcap_filter(void)
{
#ifdef HAVE_PCAP
    if (!pcap.is_open())
        return;

    // Build a filter to exclude packets from our own source MAC.
    // libpcap can deliver outgoing packets back to us; we want to reject them.
    // Make room for "not (ether src ... or ether src ...)" with two MACs.
    char srcbuf[160] = {0};
    const uint8_t *phys = (setup.valid && !mac_is_zero(setup.macs[0])) ? setup.macs[0] : mac_addr;
    if (setup.valid && !mac_is_zero(setup.macs[0]) && !mac_is_zero(mac_addr) && !mac_equal(setup.macs[0], mac_addr)) {
        snprintf(srcbuf, sizeof(srcbuf),
                 "not (ether src %02x:%02x:%02x:%02x:%02x:%02x or ether src %02x:%02x:%02x:%02x:%02x:%02x)",
                 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
                 setup.macs[0][0], setup.macs[0][1], setup.macs[0][2], setup.macs[0][3], setup.macs[0][4], setup.macs[0][5]);
    } else if (!mac_is_zero(phys)) {
        snprintf(srcbuf, sizeof(srcbuf), "not ether src %02x:%02x:%02x:%02x:%02x:%02x",
                 phys[0], phys[1], phys[2], phys[3], phys[4], phys[5]);
    }
    const bool have_src_excl = srcbuf[0] != '\0';

    // setup.promiscuous is set by the guest OS via setup frame - if set, deliver all packets.
    // promisc.value controls whether the HOST interface is in promiscuous mode (pcap.open),
    // but does NOT bypass emulated MAC filtering - only setup.promiscuous does that.
    if (setup.promiscuous) {
        std::string filter = "ip or not ip";
        if (have_src_excl) {
            filter = std::string(srcbuf) + " and (" + filter + ")";
        }
        if (!pcap.set_filter(filter)) {
            WARNING("DEQNA: pcap filter set failed: %s", pcap.last_error().c_str());
        }
        return;
    }

    std::string filter;
    auto append_term = [&](const std::string &term) {
        if (!filter.empty())
            filter += " or ";
        filter += term;
    };
    auto add_mac = [&](const uint8_t *mac_bytes) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ether dst %02x:%02x:%02x:%02x:%02x:%02x",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        append_term(buf);
    };

    append_term("ether broadcast");
    if (setup.multicast)
        append_term("ether multicast");

    if (!mac_is_zero(phys))
        add_mac(phys);
    if (setup.valid) {
        for (int i = 0; i < QNA_FILTER_MAX; ++i) {
            if (!mac_is_zero(setup.macs[i]) && !mac_equal(setup.macs[i], phys))
                add_mac(setup.macs[i]);
        }
    }

    if (filter.empty())
        filter = "ip or not ip";

    // Exclude packets from our own source MAC
    if (have_src_excl) {
        filter = "(" + filter + ") and " + srcbuf;
    }

    if (!pcap.set_filter(filter)) {
        WARNING("DEQNA: pcap filter set failed: %s", pcap.last_error().c_str());
    }
#endif
}

/*
 * deqna_c::accept_packet
 * Purpose: decide whether a host frame should be delivered to the emulated NIC.
 * Behavior: checks length, broadcast/multicast rules, and filter setup.
 * Notes: assumes data points to a full Ethernet frame.
 */
bool deqna_c::accept_packet(const uint8_t *data, size_t len) const
{
    if (!data || len < 6)
        return false;

    // libpcap can deliver "outgoing" packets for the capture interface. Real DEQNA
    // hardware doesn't receive its own transmitted frames unless loopback is active.
    if (len >= 12) {
        const bool il_clear = (csr & QNA_CSR_IL) == 0;
        const bool el_set = (csr & QNA_CSR_EL) != 0;
        const bool loopback = el_set || il_clear;
        const uint8_t *src = data + 6;
        const uint8_t *phys = (setup.valid && !mac_is_zero(setup.macs[0])) ? setup.macs[0] : mac_addr;
        if (!loopback &&
            ((!mac_is_zero(mac_addr) && mac_equal(src, mac_addr)) ||
             (!mac_is_zero(phys) && mac_equal(src, phys))))
            return false;
    }

    if (setup.promiscuous)
        return true;

    const uint8_t *dst = data;
    const uint8_t *phys = (setup.valid && !mac_is_zero(setup.macs[0])) ? setup.macs[0] : mac_addr;
    if (!mac_is_zero(phys) && mac_equal(dst, phys))
        return true;

    if (mac_is_broadcast(dst))
        return true;

    if (mac_is_multicast(dst) && setup.multicast)
        return true;

    for (int i = 0; i < QNA_FILTER_MAX; ++i) {
        if (!mac_is_zero(setup.macs[i]) && mac_equal(dst, setup.macs[i]))
            return true;
    }

    return false;
}

/* make_addr - Construct a 22-bit address from high and low words   
 *
 * Takes into account the qunibus address width to mask off unused bits in the high word.
 */

uint32_t deqna_c::make_addr(uint16_t hi, uint16_t lo) const
{
    uint16_t mask = QE_RING_ADDR_HI_MASK;
    if (qunibus) {
        if (qunibus->addr_width <= 16)
            mask = 0x0000;
        else if (qunibus->addr_width <= 18)
            mask = 0x0003;
    }
    return (static_cast<uint32_t>(hi & mask) << 16) | lo;
}

/* on_after_register_access - Handle register writes from PDP-11    
 *
 * Processes writes to the DEQNA registers, updating internal state
 * as needed. Writes to RCLH and XMTH trigger processing of the
 * respective descriptor rings.
 */

void deqna_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    uint16_t val = get_register_dato_value(device_reg);
    if (device_reg->index == DEQNA_REG_VECTOR || device_reg->index == DEQNA_REG_CSR) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        handle_register_write(static_cast<uint8_t>(device_reg->index), val, access);
        return;
    }
    if (device_reg->index < 8) {
        const uint16_t byte_mask =
            (access == DATO_WORD) ? 0xffff :
            (access == DATO_BYTEH) ? 0xff00 :
            0x00ff;
        const uint16_t reg_bit = static_cast<uint16_t>(1u << device_reg->index);
        uint16_t merged = val;

        if (pending_reg_mask.load(std::memory_order_acquire) & reg_bit) {
            const uint16_t base = pending_reg_value[device_reg->index].load(std::memory_order_relaxed);
            merged = static_cast<uint16_t>((base & ~byte_mask) | (val & byte_mask));
        } else if (device_reg->index >= DEQNA_REG_RCVLIST_LO &&
                   device_reg->index <= DEQNA_REG_XMTLIST_HI) {
            uint16_t base = 0;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                if (device_reg->index == DEQNA_REG_RCVLIST_LO)
                    base = rbdl[0];
                else if (device_reg->index == DEQNA_REG_RCVLIST_HI)
                    base = rbdl[1];
                else if (device_reg->index == DEQNA_REG_XMTLIST_LO)
                    base = xbdl[0];
                else if (device_reg->index == DEQNA_REG_XMTLIST_HI)
                    base = xbdl[1];
            }
            merged = static_cast<uint16_t>((base & ~byte_mask) | (val & byte_mask));
        }

        pending_reg_value[device_reg->index].store(merged, std::memory_order_relaxed);
        uint8_t flag = 0x01;
        if (access == DATO_WORD)
            flag = 0x03;
        else if (access == DATO_BYTEH)
            flag = 0x02;
        pending_reg_byteflags[device_reg->index].fetch_or(flag, std::memory_order_relaxed);
        pending_reg_mask.fetch_or(reg_bit, std::memory_order_release);
    }
}

/* handle_register_write - Process writes to DEQNA registers    
 *
 * Updates internal state based on register writes. Called from
 * on_after_register_access after acquiring state mutex.
 */

void deqna_c::handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access)
{
    if (trace.value) {
        static const char *reg_names[] = {
            "STA0", "STA1", "RCLL", "RCLH", "XMTL", "XMTH", "VAR", "CSR"
        };
        const char *rname = (reg_index < 8) ? reg_names[reg_index] : "???";
        DEBUG("DEQNA: Write %s (reg %d) = %06o access=%d", rname, reg_index, val, access);
    }

    const uint16_t byte_mask =
        (access == DATO_WORD) ? 0xffff :
        (access == DATO_BYTEH) ? 0xff00 :
        0x00ff;

    switch (reg_index) {
    case DEQNA_REG_RCVLIST_LO:
        rbdl[0] = static_cast<uint16_t>((rbdl[0] & ~byte_mask) | (val & byte_mask));
        break;
    case DEQNA_REG_RCVLIST_HI:
        rbdl[1] = static_cast<uint16_t>((rbdl[1] & ~byte_mask) | (val & byte_mask));
        if (access != DATO_BYTEL)
            rbdl_hi_written = true;
        rbdl_pending = true;
        if (trace.value)
            DEBUG("DEQNA: RX list update pending (RCLH=%06o RCLL=%06o csr=%06o)", rbdl[1], rbdl[0], csr);
        break;
    case DEQNA_REG_XMTLIST_LO:
        xbdl[0] = static_cast<uint16_t>((xbdl[0] & ~byte_mask) | (val & byte_mask));
        break;
    case DEQNA_REG_XMTLIST_HI:
        xbdl[1] = static_cast<uint16_t>((xbdl[1] & ~byte_mask) | (val & byte_mask));
        if (access != DATO_BYTEL)
            xbdl_hi_written = true;
        tx_kick = true;
        tx_v0_retries = 0;
        tx_wait_until_ns = 0;
        tx_invalid_dumped = false;
        if (trace.value)
            DEBUG("DEQNA: TX list update pending (XMTH=%06o XMTL=%06o csr=%06o)", xbdl[1], xbdl[0], csr);
        break;
    case DEQNA_REG_VECTOR: {
        // Byte writes only update the targeted byte.
        uint16_t merged = var;
        if (access == DATO_WORD)
            merged = val;
        else if (access == DATO_BYTEH)
            merged = static_cast<uint16_t>((var & 0x00ff) | (val & 0xff00));
        else
            merged = static_cast<uint16_t>((var & 0xff00) | (val & 0x00ff));

        uint16_t new_var = static_cast<uint16_t>((var & QNA_VEC_RO) | (merged & QNA_VEC_RW));
        // DEQNA: MS is fixed to 0 and ID bit always reads 0.
        new_var &= ~QNA_VEC_MS;
        new_var &= ~(QNA_VEC_OS | QNA_VEC_RS | QNA_VEC_ST | QNA_VEC_ID);
        deqna_lock = true;

        var = new_var;
        update_vector_reg();
        intr_request.set_vector(var & QNA_VEC_IV);
        break;
    }
    case DEQNA_REG_CSR: {
        uint16_t prev = csr;
        const uint16_t data_masked = static_cast<uint16_t>(val & byte_mask);
        const uint16_t rw_in_access = static_cast<uint16_t>(QNA_CSR_RW & byte_mask);

        uint16_t set_bits = static_cast<uint16_t>(data_masked & rw_in_access);
        uint16_t clr_bits = static_cast<uint16_t>(((data_masked ^ rw_in_access) & rw_in_access) |
                                                  (data_masked & QNA_CSR_W1) |
                                                  ((data_masked & QNA_CSR_XI) ? QNA_CSR_NI : 0));

        // OpenSIMH-compatible: reset controller when SR transitions to cleared.
        // Only applies if the SR bit is actually being written (low byte or full word).
        if ((byte_mask & QNA_CSR_SR) && (prev & QNA_CSR_SR) && !(data_masked & QNA_CSR_SR)) {
            WARNING("DEQNA: SW reset by driver (qerestart): prev_csr=%06o RI=%d XI=%d RL=%d XL=%d irq=%d vec=%03o",
                    prev,
                    (prev & QNA_CSR_RI) ? 1 : 0,
                    (prev & QNA_CSR_XI) ? 1 : 0,
                    (prev & QNA_CSR_RL) ? 1 : 0,
                    (prev & QNA_CSR_XL) ? 1 : 0,
                    irq ? 1 : 0,
                    var & QNA_VEC_IV);
            sw_reset();
            return;
        }

        csr_set_clr(set_bits, clr_bits);

        if ((prev ^ csr) & QNA_CSR_RE) {
            if (csr & QNA_CSR_RE)
                start_rx_delay();
            else
                rx_delay_active = false;
        }

        if ((prev ^ csr) & QNA_CSR_EL)
            update_station_regs();

        if ((csr & QNA_CSR_BP) == QNA_CSR_BP) {
            if (trace.value)
                DEBUG("DEQNA: Boot/diagnostic ROM request ignored (ROM disabled)");
            csr_set_clr(0, QNA_CSR_BP);
        }

        // Process deferred interrupts immediately when CPU writes CSR.
        // This is safe because we're not in a DMA context here.
        process_deferred_interrupts();
        break;
    }
    default:
        break;
    }
}

/* apply_pending_reg_writes - Apply pending register writes
 *
 * Processes any pending register writes that were deferred
 * from on_after_register_access. Called from the worker loop
 * to ensure register writes are handled in a thread-safe manner.
 */

void deqna_c::apply_pending_reg_writes(void)
{
    uint16_t mask = pending_reg_mask.exchange(0, std::memory_order_acquire);
    if (!mask)
        return;

    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    for (uint8_t idx = 0; idx < 8; ++idx) {
        if (mask & static_cast<uint16_t>(1u << idx)) {
            uint16_t val = pending_reg_value[idx].load(std::memory_order_relaxed);
            uint8_t flags = pending_reg_byteflags[idx].exchange(0, std::memory_order_relaxed);
            DATO_ACCESS access = DATO_BYTEL;
            if (flags & 0x02) {
                access = (flags & 0x01) ? DATO_WORD : DATO_BYTEH;
            } else if (!(flags & 0x01)) {
                access = DATO_WORD;
            }
            handle_register_write(idx, val, access);
        }
    }
}

/*
 * enqueue_readq - Add a received packet to the RX queue
 *
 * @param type   Packet type: 0=setup echo, 1=loopback, 2=normal
 * @param data   Packet data pointer
 * @param len    Packet length in bytes
 * @param status Status code (unused, for future expansion)
 *
 * If the queue is full (QNA_QUE_MAX), the oldest packet is dropped.
 * This ensures we don't block indefinitely when the driver is slow
 * to provide RX descriptors.
 */
void deqna_c::enqueue_readq(int type, const uint8_t *data, size_t len, int status)
{
    std::lock_guard<std::mutex> lock(queue_mutex);  // Fix: Use queue_mutex for queue access
    if (trace.value) {
        DEBUG("DEQNA: Enqueue RX type=%d len=%zu status=%06o queue=%zu",
                type, len, static_cast<uint16_t>(status), read_queue.size());
    }

    if (read_queue.size() >= QNA_QUE_MAX) {
        read_queue_loss++;
        if (!read_queue.empty())
            read_queue.pop_front();  // Drop oldest
    }

    queue_item item;
    item.type = type;
    item.packet.msg.assign(data, data + len);
    item.packet.len = len;
    item.packet.used = 0;
    item.packet.status = status;
    item.enqueue_time = std::chrono::steady_clock::now();

    /* Debug: For loopback and normal packets, log a short hexdump for correlation */
    if (trace.value && (type == 1 || type == 2) && len > 0) {
        std::string hexdump;
        size_t dump_len = (len > 64) ? 64 : len;
        char tmp[8];
        for (size_t i = 0; i < dump_len; ++i) {
            snprintf(tmp, sizeof(tmp), "%02x", data[i]);
            hexdump += tmp;
            if (((i + 1) % 8) == 0) hexdump += ' ';
        }
        DEBUG("DEQNA: ENQ DBG type=%d len=%zu data=%s", type, len, hexdump.c_str());

        /* If this looks like DECnet (EtherType 0x6003) then snapshot rings */
        if (type == 2 && len >= 14) {
            uint16_t ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);
            if (ethertype == 0x6003) {
                DEBUG("DEQNA: DECnet packet detected (ethertype=0x6003) - snapshotting rings");
                dump_descriptor_rings("DECnet enqueued");
            }
        }
    }

    read_queue.push_back(std::move(item));
}

/*
 * dispatch_rbdl - Start RX descriptor ring processing
 *
 * Called when:
 * - RCLH register is written (driver provides new RX ring)
 * - Packets are waiting in queue and RL is clear
 *
 * Behavior:
 * 1. Clear RL bit (list is now valid)
 * 2. Recalculate rbdl_ba from RCLH:RCLL registers (allows driver to
 *    update ring pointer by writing RCLH again)
 * 3. Read first descriptor (but don't write 0xFFFF flag yet)
 * 4. If packets are queued, call process_rbdl() to deliver them
 *
 * Returns: true on success, false on NXM error
 */
bool deqna_c::dispatch_rbdl(void)
{
    uint32_t cur_ba = 0;
    uint16_t csr_snapshot = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, QNA_CSR_RL);
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
        cur_ba = rbdl_ba;
        csr_snapshot = csr;
    }
    if (cur_ba == 0) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        tx_state = tx_state_enum::idle;
        return false;
    }

    if (trace.value) {
        size_t queue_size = 0;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            queue_size = read_queue.size();
        }
        DEBUG("DEQNA: RX list dispatch at %06o (csr=%06o queue=%zu)",
              cur_ba, csr_snapshot, queue_size);
    }

    // If packets are queued (or setup/loopback is pending), process immediately.
    // Otherwise the RX worker will return quickly on the next iteration.
    bool do_process = false;
    int front_type = 2;
    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        do_process = !read_queue.empty();
        if (do_process)
            front_type = read_queue.front().type;
    }
    if (do_process && (front_type < 2 || rx_ready()))
        return process_rbdl();

    return true;
}

/*
 * process_rbdl - Process RX descriptors and deliver queued packets
 *
 * This is the main RX processing loop. For each queued packet:
 * 1. Write 0xFFFF to word 0 (flag word) to claim the descriptor
 * 2. Read remaining descriptor words
 * 3. Check V (valid) bit - if clear, set RL and stop
 * 4. Handle C (chain) bit - follow chain to next descriptor
 * 5. DMA packet data to buffer address
 * 6. Write status words (word 4 and 5)
 * 7. Advance to next descriptor (cur_ba + 12)
 * 8. Set RI (receive interrupt) when done
 *
 * Descriptor format (12 bytes / 6 words):
 *   Word 0: Flag (0xFFFF = in use by device)
 *   Word 1: Addr high bits + flags (V, C, H, L)
 *   Word 2: Buffer address low
 *   Word 3: Buffer length (one's complement)
 *   Word 4: Status 1 (written by device: segment status + length high)
 *   Word 5: Status 2 (written by device: length low bytes)
 *
 * Status word 1 values:
 *   0x0000 = last segment, no errors
 *   0xC000 = not last segment (QE_RST_LASTNOT)
 *   0x8000 = unused/bootrom special (QE_RST_UNUSED)
 *   + error bits if applicable
 *
 * RE (Receive Enable) handling:
 *   Setup (type 0) and loopback (type 1) packets are delivered regardless
 *   of RE state - they are internal to the controller. Normal network
 *   packets (type 2) require RE=1 to be delivered.
 *
 * Thread safety:
 *   Access to shared state (csr, rbdl_ba, etc.) is protected by state_mutex.
 *   DMA operations are serialized by dma_mutex in the base class.
 */
bool deqna_c::process_rbdl(void)
{
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        if (csr & QNA_CSR_RL)
            return false;
    }

    bool ri_pending = false;
    unsigned processed = 0;
    // Limit RX processing per call to prevent TX starvation during floods.
    // Even if rx_slots.value is 0 (unlimited), impose a reasonable maximum
    // to allow TX to run and prevent watchdog timeout.
    const unsigned limit = rx_slots.value ? static_cast<unsigned>(rx_slots.value) : 8;

    // Track starting address to detect circular chains (OpenSIMH-style)
    uint32_t start_rbdl_ba = 0;
    uint32_t wrap_base = 0;
    bool wrap_guard_enabled = false;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        start_rbdl_ba = rbdl_ba;
        wrap_guard_enabled = rbdl_wrap_guard;
        wrap_base = wrap_guard_enabled ? last_rbdl_start : start_rbdl_ba;
    }
    unsigned desc_count = 0;
    const unsigned max_desc_count = 256;  // Sanity limit to prevent infinite loops
    while (true) {
        // Abort immediately if reset is in progress
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;

        int front_type = 2;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue.empty())
                break;
            front_type = read_queue.front().type;
        }

        uint32_t cur_ba = 0;
        uint16_t csr_snapshot = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = rbdl_ba;
            csr_snapshot = csr;
        }

        // Guard against lapping a circular ring across successive calls when
        // the guest hasn't reclaimed descriptors yet. If we return to the same
        // start address as the previous call while packets remain queued, stop
        // delivering and let packets be dropped at the queue/pcap level.
        if (wrap_guard_enabled && cur_ba == wrap_base) {
            // BUGFIX: Drop queued packets when the ring wraps without reclaim.
            // This prevents a tight loop that never makes forward progress.
            size_t dropped = 0;
            {
                std::lock_guard<std::mutex> queue_lock(queue_mutex);
                if (!read_queue.empty()) {
                    dropped = read_queue.size();
                    read_queue_loss += static_cast<unsigned>(dropped);
                    read_queue.clear();
                }
            }
            if (trace.value) {
                DEBUG("DEQNA: RX wrap guard hit at %06o (wrap_base=%06o drop=%zu)", cur_ba, wrap_base, dropped);
            }
            break;
        }

        // Circular ring overrun avoidance (OpenSIMH-style): if the ring chains
        // back to the start and we've already processed at least one descriptor,
        // stop now to avoid overwriting descriptors the guest may not have
        // reclaimed yet.
        if (desc_count > 0 && cur_ba == start_rbdl_ba) {
            if (trace.value) {
                DEBUG("DEQNA: RX processed %u descriptors; stopping to avoid overrun (ring chained to %06o)",
                      desc_count, start_rbdl_ba);
            }
            break;
        }

        // Sanity limit: prevent infinite loops through garbage memory
        if (++desc_count > max_desc_count) {
            WARNING("DEQNA: RX descriptor limit reached (%u), stopping", max_desc_count);
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(static_cast<uint16_t>(QNA_CSR_RL | QNA_CSR_RI), 0);
            process_deferred_interrupts();
            return false;
        }

        // Normal packets require the receiver to be enabled. Setup and loopback
        // packets are internal and bypass RE.
        if (front_type == 2 && !rx_ready()) {
            if (trace.value)
                DEBUG("DEQNA: RX blocked (RE=0) csr=%06o", csr_snapshot);
            process_deferred_interrupts();
            return true;
        }

        // Real QNA hardware delays setup/loopback delivery by ~400us.
        if (front_type < 2) {
            std::chrono::steady_clock::time_point enqueue_time;
            {
                std::lock_guard<std::mutex> queue_lock(queue_mutex);
                if (!read_queue.empty())
                    enqueue_time = read_queue.front().enqueue_time;
            }
            auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - enqueue_time).count();
            if (elapsed_us < 500)
                return true;
        }

        uint16_t words[QE_RING_WORDS] = {0};
        if (trace.value)
            DEBUG("DEQNA: RX desc_read_words @ %08o words=%u", cur_ba, 4u);
        if (!desc_read_words(cur_ba, words, 4)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            // OpenSIMH-compatible: NXM triggers NI|XI|XL|RL (and interrupts via XI).
            nxm_error();
            process_deferred_interrupts();
            return false;
        }

        // Mark descriptor processed/in-use by writing 0xFFFF to word[0].
        // OpenSIMH does this unconditionally for each descriptor it touches,
        // including explicit chain and list-end (V=0) descriptors.
        const uint16_t flag_word = 0xFFFF;
        if (!desc_write_words(cur_ba, &flag_word, 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            process_deferred_interrupts();
            return false;
        }

        // RX: OpenSIMH checks V (valid) BEFORE C (chain). A chain pointer is only
        // followed when the descriptor is valid.
        if (~words[1] & QNA_DSC_V) {
            if (trace.value) {
                uint32_t address = make_addr(words[1], words[2]) & ~1u;
                DEBUG("DEQNA: RX list end: descriptor not valid @%06o (word1=%06o word2=%06o addr=%06o)",
                      cur_ba, words[1], words[2], address);
            }
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            // RL indicates RX list exhausted/invalid. Avoid raising RI here to
            // prevent early interrupt/DMA contention during ifconfig.
            csr_set_clr(QNA_CSR_RL, 0);
            process_deferred_interrupts();
            return true;
        }

        if (words[1] & QNA_DSC_C) {
            uint32_t next_ba = make_addr(words[1], words[2]) & ~1u;
            // NOTE: Chain descriptors just point to the next descriptor; they do NOT
            // have packets in the queue for them. We follow the chain immediately.
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = next_ba;
            continue;
        }

        queue_item item;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue.empty())
                break;
            item = std::move(read_queue.front());
            read_queue.pop_front();
        }

        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        if (words[1] & QNA_DSC_H) {
            address += 1;
            if (b_length)
                b_length -= 1;
        }
        if (words[1] & QNA_DSC_L) {
            if (b_length)
                b_length -= 1;
        }

        size_t rbl = item.packet.len;
        uint8_t *rbuf = nullptr;
        if (item.packet.used) {
            size_t used = item.packet.used;
            rbl -= used;
            rbuf = &item.packet.msg[used];
        } else {
            if (rbl < ETH_MIN_PACKET) {
                stats.runt++;
                if (item.packet.msg.size() < ETH_MIN_PACKET)
                    item.packet.msg.resize(ETH_MIN_PACKET, 0);
                else
                    memset(&item.packet.msg[rbl], 0, ETH_MIN_PACKET - rbl);
                rbl = ETH_MIN_PACKET;
                item.packet.len = rbl;
            }

            if (rbl > ETH_MAX_PACKET) {
                stats.giant++;
                item.packet.len = ETH_MAX_PACKET;
                rbl = ETH_MAX_PACKET;
            }

            rbuf = item.packet.msg.data();
        }

        size_t used_before = item.packet.used;
        bool overflow = false;
        if (rbl > b_length) {
            rbl = b_length;
            overflow = true;
        }
        item.packet.used = used_before + rbl;
        if (overflow)
            item.packet.used = item.packet.len;

        bool dma_failed = false;
        if (trace.value) {
            DEBUG("DEQNA: RX deliver type=%d rbl=%zu to addr=%08o blen=%u desc=%06o",
                  item.type, rbl, address, static_cast<unsigned>(b_length), cur_ba);
        }
        if (rbl && !dma_write_bytes(address, rbuf, rbl)) {
            dma_failed = true;
            rbl = 0;
            item.packet.used = item.packet.len;
            WARNING("DEQNA: RX DMA write failed at addr=%08o", address);
        }

        uint16_t status1 = 0;
        // OpenSIMH reports RBL based on the full packet length (even when the packet is
        // split across multiple buffers). For normal packets, the reported length is
        // (packet_len - 60) to keep the value within 11 bits.
        uint16_t report_rbl = static_cast<uint16_t>(item.packet.len & 0xFFFF);
        switch (item.type) {
        case 0: {
            stats.setup++;
            // Setup packets report ESETUP and set RBL<10:8> to 7.
            status1 = static_cast<uint16_t>(QE_ESETUP | 0x0700);

            // Some DEQNA hardware writes an extra word after the setup packet
            // when the buffer is tight. This is important for diagnostics.
            if (!dma_failed && b_length <= static_cast<uint16_t>(rbl + 2)) {
                uint8_t extra[2] = {0x00, 0xC0}; // 0xC000 in little-endian byte order
                uint32_t extra_addr = address + static_cast<uint32_t>(rbl);
                (void)dma_write_bytes(extra_addr, extra, sizeof(extra));
                if (trace.value)
                    DEBUG("DEQNA: RX setup wrote extra word at %08o", extra_addr);
            }
            break;
        }
        case 1:
            stats.loop++;
            status1 = QE_RST_LASTNOERR;
            status1 |= static_cast<uint16_t>(report_rbl & 0x0700);
            if (csr_snapshot & QNA_CSR_EL)
                status1 |= QE_ESETUP;
            break;
        case 2:
        default:
            if (report_rbl >= 60)
                report_rbl = static_cast<uint16_t>(report_rbl - 60);
            else
                report_rbl = 0;
            status1 = static_cast<uint16_t>((report_rbl & 0x0700) | QE_RST_RSVD);
            break;
        }

        if (dma_failed) {
            status1 |= QE_RST_LASTERR;
            status1 |= QE_DISCARD;
        } else if (overflow) {
            status1 |= QE_RST_LASTERR;
            status1 |= QE_OVF | QE_DISCARD;
        } else if (item.packet.used < item.packet.len) {
            status1 |= QE_RST_LASTNOT;
        }

        bool loss = false;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue_loss) {
                loss = true;
                read_queue_loss = 0;
            }
        }
        if (loss)
            status1 |= QE_OVF;

        words[4] = status1;
        const uint16_t rbl_low = static_cast<uint16_t>(report_rbl & 0x00FF);
        words[5] = static_cast<uint16_t>((rbl_low << 8) | rbl_low);

        if (trace.value) {
            DEBUG("DEQNA: RX status type=%d st1=%06o st2=%06o desc=%06o",
                  item.type, words[4], words[5], cur_ba + 8);
        }

        if (!desc_write_words(cur_ba + 8, &words[4], 2)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            process_deferred_interrupts();
            return false;
        }

        const bool packet_complete = (item.packet.used >= item.packet.len);
        if (!packet_complete) {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            read_queue.push_front(std::move(item));
        } else {
            ri_pending = true;
        }

        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = cur_ba + QE_RING_BYTES;
        }

        if (limit && (++processed >= limit))
            break;
    }

    // Update wrap guard state based on whether packets remain queued.
    {
        bool queue_empty = false;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            queue_empty = read_queue.empty();
        }
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        if (queue_empty) {
            rbdl_wrap_guard = false;
            // BUGFIX: Clear wrap base when the RX queue drains to avoid stale guard hits.
            last_rbdl_start = 0;
        } else {
            rbdl_wrap_guard = true;
            // BUGFIX: Keep the wrap base stable across backlog processing.
            last_rbdl_start = wrap_base;
        }
    }

    if (ri_pending) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(QNA_CSR_RI, 0);
        update_csr_reg();
    }

    // Process deferred interrupts AFTER all DMA operations complete
    process_deferred_interrupts();

    return true;
}

void deqna_c::touch_rbdl_if_idle(void)
{
    // Descriptors are only touched when processing packets
    // Just log for debugging, no DMA operations
    bool is_empty = false;
    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        is_empty = read_queue.empty();
    }
    if (!is_empty)
        return;
    if (trace.value) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        DEBUG("DEQNA: RX idle at %06o (queue empty)", rbdl_ba);
    }
}

/*
 * dispatch_xbdl - Start TX descriptor ring processing
 *
 * Called when XMTH register is written (driver provides new TX ring).
 *
 * Behavior:
 * 1. Clear XL bit (list is now valid)
 * 2. Recalculate xbdl_ba from XMTH:XMTL registers
 * 3. Reset write_buffer for new packet assembly
 * 4. Call process_xbdl() to transmit queued packets
 *
 * Returns: true on success, false on NXM error
 */
bool deqna_c::dispatch_xbdl(void)
{
    DEBUG("DEQNA: dispatch_xbdl() called");
    uint32_t cur_ba = 0;
    uint16_t csr_snapshot = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, QNA_CSR_XL);

        // Always recalculate xbdl_ba from base registers when dispatching
        xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
        tx_state = tx_state_enum::active;
        tx_wait_ba = 0;
        tx_wait_until_ns = 0;
        cur_ba = xbdl_ba;
        csr_snapshot = csr;

        write_buffer.len = 0;
        write_buffer.used = 0;
    }
    if (cur_ba == 0)
        return false;

    DEBUG("DEQNA: TX list dispatch at %06o (csr=%06o IE=%d)", cur_ba, csr_snapshot,
          (csr_snapshot & QNA_CSR_IE) ? 1 : 0);

    return process_xbdl();
}

/*
 * write_callback - Handle TX completion (success or failure)
 *
 * @param status  0 = success, non-zero = failure
 *
 * Called after pcap.send() completes. Updates descriptor status words,
 * sets XI interrupt,
 * and continues processing any remaining TX descriptors.
 *
 * TDR (Transmit Delay Report) is a rough estimate of transmission time
 * in bit times, used by the driver for collision backoff calculations.
 */
void deqna_c::write_callback(int status)
{
    uint32_t cur_ba = 0;
    size_t len_snapshot = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        cur_ba = xbdl_ba;
        len_snapshot = write_buffer.len;
    }
    const uint16_t TDR = static_cast<uint16_t>(100 + len_snapshot * 8);
    // TX status word 1: 0x0000 = used, last segment, no errors
    // TX status word 2: TDR (Time Domain Reflectometry) value
    uint16_t write_success[2] = {0x0000, static_cast<uint16_t>(TDR & 0x03FF)};
    // OpenSIMH-compatible: on failure, status word 1 is set to QNA_DSC_C.
    uint16_t write_failure[2] = {QNA_DSC_C, static_cast<uint16_t>(TDR & 0x03FF)};

    stats.xmit++;
    stat_tx_frames.value = stats.xmit;

    if (trace.value) {
        DEBUG("DEQNA: TX callback status=%d st1=%06o st2=%06o desc=%06o",
              status,
              (status == 0) ? write_success[0] : write_failure[0],
              (status == 0) ? write_success[1] : write_failure[1],
              cur_ba + 8);
    }

    // Write status words back to descriptor
    if (!desc_write_words(cur_ba + 8, (status == 0) ? write_success : write_failure, 2)) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        nxm_error();
        process_deferred_interrupts();
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        if (status != 0) {
            stats.fail++;
            stat_tx_errors.value = stats.fail;
        }

        DEBUG("DEQNA: write_callback setting XI, csr=%06o IE=%d irq=%d",
              csr, (csr & QNA_CSR_IE) ? 1 : 0, irq ? 1 : 0);
        csr_set_clr(QNA_CSR_XI, 0);  // Set transmit interrupt
        DEBUG("DEQNA: after XI set: csr=%06o irq=%d", csr, irq ? 1 : 0);
        update_csr_reg(); /* Ensure CSR shows XI for diagnostics */

        write_buffer.len = 0;
        write_buffer.used = 0;
        xbdl_ba = cur_ba + QE_RING_BYTES;  // Advance to next descriptor
    }

    reset_sanity_timer();
    // Note: the caller's loop in process_xbdl() will continue processing
    // remaining TX descriptors. We don't call process_xbdl() here recursively.
}

/*
 * process_xbdl - Process TX descriptors and transmit packets
 *
 * This is the main TX processing loop. For each descriptor:
 * 1. Read all descriptor words
 * 2. For valid or chain descriptors, write 0xFFFF flag to claim it
 * 3. Handle C (chain) bit - follow chain to next descriptor
 * 4. Check V (valid) bit - if clear, defer and wait for a valid descriptor
 * 5. DMA packet data from buffer address, accumulating in write_buffer
 * 6. On E (end of message):
 *    - Check for loopback mode (EL=1 or IL=0)
 *    - Check for setup packet (S bit)
 *    - Either loopback/setup locally, or send via pcap
 * 7. Write status words
 *
 * LOOPBACK LOGIC:
 * Loopback is enabled when EL=1 (external loopback) or when IL=0
 * (internal loopback). Setup packets always loop back regardless of CSR.
 *
 * Thread safety:
 *   Access to shared state (csr, xbdl_ba, etc.) is protected by state_mutex.
 *   DMA operations are serialized by dma_mutex in the base class.
 */
bool deqna_c::process_xbdl(void)
{
    // Status for implicit chain (multi-segment packets)
    const uint16_t implicit_chain_status[2] = {static_cast<uint16_t>(QNA_DSC_V | QNA_DSC_C), 1};

    // Track starting address to detect circular chains (OpenSIMH-style)
    uint32_t start_xbdl_ba = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        start_xbdl_ba = xbdl_ba;
    }
    unsigned desc_count = 0;
    const unsigned max_desc_count = 256;  // Sanity limit to prevent infinite loops

    // BUGFIX: Cap TX work per pass so RX/interrupts aren't starved during floods.
    const unsigned packet_budget = tx_slots.value ? static_cast<unsigned>(tx_slots.value) : 8;
    unsigned packets_processed = 0;

    while (true) {
        // Abort immediately if reset is in progress
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;

        uint32_t cur_ba = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = xbdl_ba;
        }

        // Circular ring overrun avoidance:
        // If the TX ring chains back to the start and we've already processed at
        // least one descriptor, stop now to avoid looping indefinitely.
        if (desc_count > 0 && cur_ba == start_xbdl_ba) {
            if (trace.value) {
                DEBUG("DEQNA: TX processed %u descriptors; stopping to avoid overrun (ring chained to %06o)",
                      desc_count, start_xbdl_ba);
            }
            break;
        }

        // Sanity limit: prevent infinite loops through garbage memory
        if (++desc_count > max_desc_count) {
            WARNING("DEQNA: TX descriptor limit reached (%u), stopping", max_desc_count);
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            // XL indicates TX list exhausted/invalid; set XI so the driver wakes.
            note_xl_set("tx_desc_limit", cur_ba, nullptr, 0);
            csr_set_clr(static_cast<uint16_t>(QNA_CSR_XL | QNA_CSR_XI), 0);
            tx_state = tx_state_enum::idle;
            tx_wait_ba = 0;
            tx_wait_until_ns = 0;
            tx_v0_retries = 0;
            write_buffer.len = 0;
            write_buffer.used = 0;
            process_deferred_interrupts();
            return false;
        }

        uint16_t words[QE_RING_WORDS] = {0};
        if (trace.value)
            DEBUG("DEQNA: TX desc_read_words @ %08o words=%u", cur_ba, (unsigned)QE_RING_WORDS);
        if (!desc_read_words(cur_ba, words, QE_RING_WORDS)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            tx_state = tx_state_enum::idle;
            tx_wait_ba = 0;
            tx_wait_until_ns = 0;
            tx_v0_retries = 0;
            process_deferred_interrupts();
            return false;
        }

        // IMPORTANT: Check C (chain) bit BEFORE V (valid) bit!
        // When C=1, this is a chain pointer - follow it regardless of V.
        // SIMH does it this way (see xq_process_xbdl in pdp11_xq.c).
        if (words[1] & QNA_DSC_C) {
            // Mark chain descriptors as consumed once we've read them.
            const uint16_t flag_word = 0xFFFF;
            if (!desc_write_words(cur_ba, &flag_word, 1)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                tx_state = tx_state_enum::idle;
                tx_wait_ba = 0;
                tx_wait_until_ns = 0;
                tx_v0_retries = 0;
                process_deferred_interrupts();
                return false;
            }
            uint32_t next_ba = make_addr(words[1], words[2]) & ~1u;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                xbdl_ba = next_ba;
            }
            continue;
        }

        // Check V (valid) bit - if clear, pause and wait for the driver
        if (~words[1] & QNA_DSC_V) {
            bool do_dump = false;
            uint16_t xmtl = 0;
            uint16_t xmth = 0;
            unsigned prior_retry = 0;
            const uint64_t v0_retry_delay_us = 1000;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                if (trace.value && !tx_invalid_dumped) {
                    tx_invalid_dumped = true;
                    do_dump = true;
                    xmtl = xbdl[0];
                    xmth = xbdl[1];
                }

                prior_retry = tx_v0_retries;
                // Defer while the descriptor is still being committed.
                // Keep retrying until it becomes valid or XMTH is rewritten.
                if (tx_v0_retries < UINT_MAX)
                    tx_v0_retries += 1;
                tx_state = tx_state_enum::wait_valid;
                tx_wait_ba = cur_ba;
                tx_wait_until_ns = timeout_c::abstime_ns() + v0_retry_delay_us * 1000ull;
                write_buffer.len = 0;
                write_buffer.used = 0;
            }

            if (do_dump) {
                DEBUG("DEQNA: TX desc V=0 @%06o XMTH=%06o XMTL=%06o "
                      "w0=%06o w1=%06o w2=%06o w3=%06o w4=%06o w5=%06o defer=%u",
                      cur_ba, xmth, xmtl, words[0], words[1], words[2],
                      words[3], words[4], words[5], prior_retry == 0 ? 1u : 0u);
            }
            process_deferred_interrupts();
            return true;
        }

        // Mark descriptor processed/in-use by writing 0xFFFF to word[0] once V=1.
        // Avoid touching V=0 descriptors so the driver retains ownership.
        const uint16_t flag_word = 0xFFFF;
        if (!desc_write_words(cur_ba, &flag_word, 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            tx_state = tx_state_enum::idle;
            tx_wait_ba = 0;
            tx_wait_until_ns = 0;
            tx_v0_retries = 0;
            process_deferred_interrupts();
            return false;
        }

        // Calculate buffer address and length
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            tx_v0_retries = 0;
            tx_wait_until_ns = 0;
        }
        const bool setup_packet = (words[1] & QNA_DSC_S) != 0;
        uint32_t address = make_addr(words[1], words[2]);
        // Decode buffer length - two's complement (in words), OpenSIMH-style.
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        if (words[1] & QNA_DSC_H) {  // Odd byte at start
            address += 1;
            if (b_length)
                b_length -= 1;
        }
        if (words[1] & QNA_DSC_L) { // Odd byte at end
            if (b_length)
                b_length -= 1;
        }

        size_t buf_offset = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            buf_offset = write_buffer.len;
            if ((buf_offset + b_length) > write_buffer.msg.size())
                b_length = static_cast<uint16_t>(write_buffer.msg.size() - buf_offset);
        }

        if (!dma_read_bytes(address, &write_buffer.msg[buf_offset], b_length)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            process_deferred_interrupts();
            return false;
        }
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            write_buffer.len += b_length;
        }

        if (words[1] & QNA_DSC_E) {
            bool il_clear = false;
            bool el_set = false;
            size_t len_snapshot = 0;
            uint16_t csr_snapshot = 0;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                // Internal loopback is enabled when IL is clear.
                il_clear = (csr & QNA_CSR_IL) == 0;
                el_set = (csr & QNA_CSR_EL) != 0;
                if (write_buffer.len < ETH_MIN_PACKET) {
                    size_t pad = ETH_MIN_PACKET - write_buffer.len;
                    memset(write_buffer.msg.data() + write_buffer.len, 0, pad);
                    write_buffer.len = ETH_MIN_PACKET;
                }
                len_snapshot = write_buffer.len;
                csr_snapshot = csr;
            }
            bool loopback = el_set || il_clear;

            if (trace.value) {
                DEBUG("DEQNA: TX EOMSG len=%u setup=%d loopback=%d (IL_clear=%d EL_set=%d) csr=%06o",
                        static_cast<unsigned>(len_snapshot), setup_packet ? 1 : 0, loopback ? 1 : 0,
                        il_clear ? 1 : 0, el_set ? 1 : 0, csr_snapshot);
            }

            if (loopback || setup_packet) {
                bool enqueued = false;
                // TX status: 0x0000 = used, last segment, no errors
                // For loopback, SIMH sets QE_FAIL (0x0100) as "heartbeat check failure"
                uint16_t write_success[2] = {0x0000, 0x0001};
                if (setup_packet) {
                    process_setup();
                    // Setup packets force loopback regardless of CSR loopback state.
                    enqueue_readq(0, write_buffer.msg.data(), write_buffer.len, 0);
                    enqueued = true;
                    // Setup TX status: word1=0x200C, word2=0x0860 (per SIMH)
                    // Bit 13 (0x2000) is "always set", bits 3:2 (0x000C) are setup-specific
                    write_success[0] = 0x200C;
                    write_success[1] = 0x0860;
                } else {
                    enqueue_readq(1, write_buffer.msg.data(), write_buffer.len, 0);
                    enqueued = true;
                    // Loopback TX status: bit 13 always set (0x2000) + FAIL bit (0x0100) = 0x2100
                    // FAIL bit indicates heartbeat check failure, which is normal for loopback
                    write_success[0] = 0x2100;
                }
                if (trace.value) {
                    DEBUG("DEQNA: TX loopback/setup status st1=%06o st2=%06o desc=%06o",
                          write_success[0], write_success[1], cur_ba + 8);
                }
                if (!desc_write_words(cur_ba + 8, write_success, 2)) {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    nxm_error();
                    tx_state = tx_state_enum::idle;
                    tx_wait_ba = 0;
                    tx_wait_until_ns = 0;
                    tx_v0_retries = 0;
                    process_deferred_interrupts();
                    return false;
                }

                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    write_buffer.len = 0;
                    write_buffer.used = 0;
                    reset_sanity_timer();
                    csr_set_clr(QNA_CSR_XI, 0);  // Set transmit interrupt (deferred)
                    xbdl_ba = cur_ba + QE_RING_BYTES; // Advance to next descriptor
                }

                // Don't call process_rbdl() from the TX path - let the
                // state-machine loop handle it. This avoids bus contention
                // when a TX interrupt is pending, and the queued setup/loopback
                // response will be processed on the next loop iteration.
                (void)enqueued;  // Suppress unused warning
                
                ++packets_processed;
                // Yield after one TX completion so the CPU can acknowledge XI
                // before we start more DMA.
                if (trace.value && packet_budget > 1)
                    DEBUG("DEQNA: TX completion yielding (budget=%u processed=%u)",
                          packet_budget, packets_processed);
                break;

            } else {
                /* If this looks like a DECnet packet (ethertype 0x6003) snapshot rings for diagnosis */
                if (trace.value && write_buffer.len >= 14) {
                    uint16_t ethertype = static_cast<uint16_t>((write_buffer.msg[12] << 8) | write_buffer.msg[13]);
                    if (ethertype == 0x6003) {
                        DEBUG("DEQNA: TX DECnet packet detected (len=%zu) - snapshotting rings before send", write_buffer.len);
                        dump_descriptor_rings("TX DECnet before send");
                        std::string hexdump;
                        size_t dump_len = (write_buffer.len > 64) ? 64 : write_buffer.len;
                        char tmp[8];
                        for (size_t i = 0; i < dump_len; ++i) {
                            snprintf(tmp, sizeof(tmp), "%02x", write_buffer.msg[i]);
                            hexdump += tmp;
                            if (((i + 1) % 8) == 0) hexdump += ' ';
                        }
                        DEBUG("DEQNA: TX DECnet data prefix=%s", hexdump.c_str());
                    }
                }

                if (!pcap.send(write_buffer.msg.data(), write_buffer.len))
                    write_callback(1);
                else
                    write_callback(0);
                ++packets_processed;
                // Yield after one TX completion so the CPU can acknowledge XI
                // before we start more DMA.
                if (trace.value && packet_budget > 1)
                    DEBUG("DEQNA: TX completion yielding (budget=%u processed=%u)",
                          packet_budget, packets_processed);
                break;
            }
        } else {
            if (!desc_write_words(cur_ba + 8, implicit_chain_status, 2)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                tx_state = tx_state_enum::idle;
                tx_wait_ba = 0;
                tx_wait_until_ns = 0;
                tx_v0_retries = 0;
                process_deferred_interrupts();
                return false;
            }
        }

        // Advance to next descriptor
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            xbdl_ba = cur_ba + QE_RING_BYTES;
        }
    }

    // Process deferred interrupts AFTER all DMA operations complete.
    process_deferred_interrupts();

    return true;
}

/*
 * process_setup - Parse and apply setup packet configuration
 *
 * The setup packet is a special 128-byte transmit that configures the
 * receiver's address filter. Format:
 *   Bytes 0-111: Up to 14 MAC addresses (8 bytes each, 6 MAC + 2 padding)
 *                First is the station's own address, rest are multicast/etc.
 *   Bytes 112-127: Extended setup (if present):
 *                  Bit 0: Accept all multicast
 *                  Bit 1: Promiscuous mode
 *                  Bits 2-3: LED control
 *                  Bits 4-6: Sanity timer setting
 *
 * OpenSIMH-compatible: setup options are encoded in the low bits of the
 * setup packet length (write_buffer.len) when the guest provides an extended
 * (>128 byte) setup packet.
 *
 * After processing, update_pcap_filter() is called to apply the new
 * receive filter to the host network interface.
 */
void deqna_c::process_setup(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint8_t *msg = write_buffer.msg.data();
    size_t len = write_buffer.len;

    // Extract MAC addresses from setup packet (unusual byte ordering)
    memset(setup.macs, 0, sizeof(setup.macs));
    for (int i = 0; i < 7; i++) {
        for (int j = 0; j < 6; j++) {
            size_t idx1 = static_cast<size_t>((i + 1) + (j * 8));
            if (idx1 < len)
                setup.macs[i][j] = msg[idx1];
            size_t idx2 = static_cast<size_t>((i + 0x41) + (j * 8));
            if (idx2 < len)
                setup.macs[i + 7][j] = msg[idx2];
        }
    }

    // Setup options are encoded in the low bits of the setup packet length.
    // PROMISCUOUS is always cleared on setup processing; short setup packets
    // are used by some OSes to disable promiscuous mode.
    setup.promiscuous = false;

    uint16_t setup_flags = 0;
    uint16_t led = 0;
    uint16_t san = 0;
    if (len > 128) {
        const uint16_t len16 = static_cast<uint16_t>(len & 0xffff);
        setup_flags = len16;
        setup.multicast = (0 != (setup_flags & QNA_SETUP_MC));
        setup.promiscuous = (0 != (setup_flags & QNA_SETUP_PM));
        led = static_cast<uint16_t>((setup_flags & QNA_SETUP_LD) >> 2);
        san = static_cast<uint16_t>((setup_flags & QNA_SETUP_ST) >> 4);
    }

    // LED control (active low)
    if (led) {
        switch (led) {
        case 1: setup.l1 = false; break;
        case 2: setup.l2 = false; break;
        case 3: setup.l3 = false; break;
        }
    }

    // Sanity timer setting (exponential scale)
    if (san) {
        float secs = 0.25f;
        switch (san) {
        case 0: secs = 0.25f; break;
        case 1: secs = 1.0f; break;
        case 2: secs = 4.0f; break;
        case 3: secs = 16.0f; break;
        case 4: secs = 60.0f; break;
        case 5: secs = 4.0f * 60.0f; break;
        case 6: secs = 16.0f * 60.0f; break;
        case 7: secs = 64.0f * 60.0f; break;
        }
        sanity.quarter_secs = static_cast<int>(secs * 4.0f);
        sanity.max = static_cast<int>(secs * QNA_SERVICE_INTERVAL);
    }

    // Reset sanity timer and enable if SE bit is set
    sanity.timer = sanity.max;
    if (sanity.enabled != 2) {  // Don't override hardware sanity
        if (csr & QNA_CSR_SE)
            sanity.enabled = 1;
        else
            sanity.enabled = 0;
    }

    setup.valid = true;
    // Apply new filter settings to pcap (now that setup.valid is set)
    update_pcap_filter();

    if (trace.value) {
        DEBUG("DEQNA: Setup packet processed: len=%zu promisc=%d multicast=%d flags=%04o",
              len, setup.promiscuous ? 1 : 0, setup.multicast ? 1 : 0, setup_flags);
        dump_descriptor_rings("setup processed");
    }
}

/* process_local - Handle incoming local packets
 *
 * This function processes packets sent to the DEQNA's local
 * protocols: Loopback (0x0090) and Remote Console (0x0260).
 *
 * Returns: true if packet was handled, false otherwise
 */

void deqna_c::dump_descriptor_rings(const char *reason)
{
    if (!trace.value)
        return;

    // Avoid debug DMA while interrupts are pending or DMA is active.
    if (irq || dma_in_progress.load(std::memory_order_acquire) != 0) {
        DEBUG("DEQNA: RING SNAPSHOT skipped (irq=%d dma=%u) reason=%s",
              irq ? 1 : 0,
              dma_in_progress.load(std::memory_order_relaxed),
              reason ? reason : "");
        return;
    }

    uint16_t csr_snapshot;
    uint32_t rbase = 0, xbase = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_snapshot = csr;
        rbase = rbdl_ba;
        xbase = xbdl_ba;
    }

    DEBUG("DEQNA: RING SNAPSHOT (%s) CSR=%06o rbdl=%06o xbdl=%06o", reason, csr_snapshot, rbase, xbase);

    uint16_t w[QE_RING_WORDS];
    uint32_t ba = rbase;
    for (int i = 0; i < 8; ++i) {
        if (ba == 0) break;
        if (!desc_read_words(ba, w, QE_RING_WORDS)) {
            DEBUG("DEQNA: RING SNAP: failed to read RX desc @%06o", ba);
            break;
        }
        DEBUG("DEQNA: RBDL[%d] @%06o -> [%06o %06o %06o %06o %06o %06o]", i, ba, w[0], w[1], w[2], w[3], w[4], w[5]);
        if (w[1] & QNA_DSC_C)
            ba = ((w[1] & 0x3F) << 16) | w[2];
        else
            ba += QE_RING_BYTES;
    }

    ba = xbase;
    for (int i = 0; i < 8; ++i) {
        if (ba == 0) break;
        if (!desc_read_words(ba, w, QE_RING_WORDS)) {
            DEBUG("DEQNA: RING SNAP: failed to read TX desc @%06o", ba);
            break;
        }
        DEBUG("DEQNA: XBDL[%d] @%06o -> [%06o %06o %06o %06o %06o %06o]", i, ba, w[0], w[1], w[2], w[3], w[4], w[5]);
        if (w[1] & QNA_DSC_C)
            ba = ((w[1] & 0x3F) << 16) | w[2];
        else
            ba += QE_RING_BYTES;
    }
}

bool deqna_c::process_local(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (len < 18)
        return false;

    uint16_t protocol = static_cast<uint16_t>(data[12] | (data[13] << 8));
    switch (protocol) {
    case 0x0090:
        return process_loopback(data, len);
    case 0x0260:
        return process_remote_console(data, len);
    default:
        break;
    }
    return false;
}

/* process_loopback - Handle incoming loopback packets
 *
 * This function processes MOP loopback packets (protocol 0x0090).
 * It verifies the function code and swaps source/destination
 * addresses to create the reply packet.
 *
 * Returns: true on success, false on failure
 */

bool deqna_c::process_loopback(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    
    // Minimum length: Ethernet header (14) + MOP header (8) + function code (2)
    if (len < 32)
        return false;

    // Offset to function code is at bytes 14-15 (little-endian)
    size_t offset = static_cast<size_t>(data[14] | (data[15] << 8));
    if (offset + 8 > len)
        return false;

    // Check function code (2 = loopback request)
    uint16_t function = static_cast<uint16_t>(data[offset] | (data[offset + 1] << 8));
    if (function != 2)
        return false;

    // Construct reply packet by swapping source/destination MACs
    std::vector<uint8_t> reply(data, data + len);
    uint8_t phys[6];
    memcpy(phys, setup.valid ? setup.macs[0] : mac_addr, 6);

    memcpy(&reply[0], &reply[offset + 2], 6);
    memcpy(&reply[6], phys, 6);
    memcpy(&reply[offset + 2], phys, 6);
    reply[offset] = 0x01;
    offset = static_cast<uint16_t>(offset + 8);
    reply[14] = static_cast<uint8_t>(offset & 0xFF);
    reply[15] = static_cast<uint8_t>((offset >> 8) & 0xFF);

    // Send the reply packet
    return pcap.send(reply.data(), reply.size());
}

/* process_remote_console - Handle incoming remote console packets
 *
 * This function processes MOP remote console packets (protocol 0x0260).
 * It verifies the command code and responds to system ID requests
 * or resets the controller as requested.
 *
 * Returns: true on success, false on failure
 */

bool deqna_c::process_remote_console(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    
    // Minimum length: Ethernet header (14) + MOP header (6)
    if (len < 20)
        return false;

    // Command code is at byte 16
    uint8_t code = data[16];
    switch (code) {
    case 0x05: {
        uint16_t receipt = static_cast<uint16_t>(data[18] | (data[19] << 8));
        return send_system_id(&data[6], receipt);
    }
    case 0x06:
        reset_controller();
        return true;
    default:
        break;
    }
    return false;
}

/* send_system_id - Send system ID response packet
 *
 * This function constructs and sends a MOP system ID response
 * packet to the specified destination MAC address.
 *
 * Returns: true on success, false on failure
 */ 

bool deqna_c::send_system_id(const uint8_t *dest, uint16_t receipt_id)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    std::vector<uint8_t> system_id(60, 0);
    uint8_t *msg = system_id.data();
    static uint16_t receipt = 0;

    memcpy(&msg[0], dest, 6);
    memcpy(&msg[6], setup.valid ? setup.macs[0] : mac_addr, 6);
    msg[12] = 0x60;
    msg[13] = 0x02;
    msg[14] = 0x1C;
    msg[15] = 0x00;
    msg[16] = 0x07;
    msg[17] = 0x00;
    if (receipt_id) {
        msg[18] = static_cast<uint8_t>(receipt_id & 0xFF);
        msg[19] = static_cast<uint8_t>((receipt_id >> 8) & 0xFF);
    } else {
        msg[18] = static_cast<uint8_t>(receipt & 0xFF);
        msg[19] = static_cast<uint8_t>((receipt++ >> 8) & 0xFF);
    }

    msg[20] = 0x01;
    msg[21] = 0x00;
    msg[22] = 0x03;
    msg[23] = 0x03;
    msg[24] = 0x01;
    msg[25] = 0x00;

    msg[26] = 0x02;
    msg[27] = 0x00;
    msg[28] = 0x02;
    msg[29] = 0x00;
    msg[30] = 0x00;

    msg[31] = 0x07;
    msg[32] = 0x00;
    msg[33] = 0x06;
    memcpy(&msg[34], mac_addr, 6);

    msg[40] = 37;
    msg[41] = 0x00;
    msg[42] = 0x01;
    msg[43] = 0x11;

    return pcap.send(system_id.data(), system_id.size());
}

/*
 * worker - Entry point for the single state-machine worker loop
 *
 * TX and RX are interleaved deterministically to avoid DMA/IACK deadlock
 * and to keep the driver serviced under heavy traffic.
 */
void deqna_c::worker(unsigned instance)
{
    if (trace.value)
        DEBUG("DEQNA: %s worker(%u) start", DEQNA_VERSION, instance);
    deqna_thread_ctx = "main";
    worker_init_realtime_priority(rt_device);

    uint8_t pkt_buf[2048];
    while (!workers_terminate) {
        if (reset_in_progress.load(std::memory_order_acquire)) {
            timeout_c::wait_ms(1);
            continue;
        }

        service_timers();
        service_intr_complete();
        apply_pending_reg_writes();
        process_deferred_interrupts();  // Process any pending interrupt state changes

        if (init_asserted || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        if (wait_for_interrupt_ack())
            continue;

        // Check for pending TX dispatch or re-probe
        bool do_dispatch = false;
        bool do_process = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (tx_kick) {
                tx_kick = false;
                tx_state = tx_state_enum::active;
                tx_wait_until_ns = 0;
                do_dispatch = true;
            } else if (tx_state == tx_state_enum::wait_valid) {
                if (tx_v0_retries != 0) {
                    const uint64_t now_ns = timeout_c::abstime_ns();
                    if (tx_wait_until_ns == 0 || now_ns >= tx_wait_until_ns) {
                        tx_state = tx_state_enum::active;
                        tx_wait_until_ns = 0;
                        do_process = true;
                    }
                }
            } else if (tx_state == tx_state_enum::active) {
                do_process = true;
            }
        }
        if (do_dispatch) {
            if (!dispatch_xbdl()) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                tx_state = tx_state_enum::idle;
            }
            process_deferred_interrupts();
        } else if (do_process) {
            if (!process_xbdl()) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                if (tx_state != tx_state_enum::wait_valid)
                    tx_state = tx_state_enum::idle;
            }
            process_deferred_interrupts();
        }

        // Check for pending RX list dispatch
        bool do_rbdl = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (rbdl_pending) {
                if (trace.value)
                    DEBUG("DEQNA: RX list pending set (csr=%06o)", csr);
                rbdl_pending = false;
                do_rbdl = true;
            }
        }
        if (do_rbdl)
            dispatch_rbdl();

        // Poll for one incoming packet from network
        // Only poll if receiver is enabled (RE=1) - don't queue packets before driver is ready.
        // NOTE: We check RE but NOT RL here. RL=1 means no descriptors available,
        // but we should still accept packets into our internal queue. The real DEQNA
        // has internal buffers that hold packets even when descriptor list is exhausted.
        // When driver provides new descriptors (clears RL), we deliver queued packets.
        size_t len = 0;
        bool capture_enabled = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (csr & QNA_CSR_RE) {
                if (!rx_delay_active || timeout_c::abstime_ns() >= rx_enable_deadline_ns)
                    capture_enabled = true;
            }
        }
#ifdef HAVE_PCAP
        if (pcap.is_open() && capture_enabled) {
            if (!pcap.poll(pkt_buf, sizeof(pkt_buf), &len)) {
                WARNING("DEQNA: pcap poll error: %s", pcap.last_error().c_str());
                timeout_c::wait_ms(10);
                continue;
            }
            if (len > 0) {
                bool should_accept = false;
                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    should_accept = accept_packet(pkt_buf, len);
                }
                if (should_accept) {
                    // Try to handle MOP protocols locally first
                    bool consumed = process_local(pkt_buf, len);
                    if (!consumed)
                        enqueue_readq(2, pkt_buf, len, 0);
                }
            }
        }
#endif

        // Process receive ring - delivers queued packets to descriptors
        process_rbdl();
        process_deferred_interrupts();  // Ensure RI interrupt is delivered

        // When packets are queued and RL is clear, keep draining immediately
        // to avoid RX backlog during broadcast floods.
        bool has_packets = false;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            has_packets = !read_queue.empty();
        }
        bool driver_ready = false;
        if (has_packets) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            driver_ready = !(csr & QNA_CSR_RL);
        }
        if (!has_packets || !driver_ready)
            timeout_c::wait_ms(1);
    }
}
