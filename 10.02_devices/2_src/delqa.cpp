/*
 * DEQNA Ethernet Controller Emulation for QUniBone
 * (c) Dave Plummer, davepl@davepl.com, Plummer's Software LLC, 2026
 * Contributed under the GPL2 License
 *
 * This is a clean-room implementation based on:
 *   - DEC DELQA/DEQNA hardware documentation
 *   - DELQA User's Guide (EK-DELQA-UG)
 *   - DEQNA User's Guide (EK-DEQNA-UG)
 *   - Q-bus specification
 *
 * BEHAVIORAL REFERENCE NOTE:
 * Where DEC documentation was ambiguous about corner-case behavior, the
 * OpenSIMH pdp11_xq.c emulator (by David T. Hittner) was used as a behavioral
 * reference to ensure compatibility with software that depends on specific
 * timing or status word semantics. No code was copied from OpenSIMH; the
 * implementations differ fundamentally in language (C++ vs C), architecture
 * (QUniBone worker threads vs SimH polling), DMA interface (PRU-based bus
 * mastering vs Map_ReadW/WriteW), and data structures (std::deque vs ethq_*).
 *
 * This file is part of the QUniBone project, licensed under GPLv2.
 *
 * IMPLEMENTATION NOTES:
 * ---------------------
 * This file implements the DELQA (M7516) and DEQNA (M7504) Ethernet controller
 * emulation. Key design decisions follow OpenSIMH behavior where DEC hardware
 * documentation is ambiguous:
 *
 * 1. LOOPBACK DETECTION: Loopback mode is active when IL=0 (internal) OR EL=1
 *    (external), independent of the RE (receive enable) bit. This differs from
 *    some interpretations that require RE=1 or use AND logic.
 *
 * 2. DESCRIPTOR BASE RECALCULATION: When dispatch_rbdl() or dispatch_xbdl()
 *    is called, the descriptor base address is recalculated from the RCLL/RCLH
 *    or XMTL/XMTH registers. This allows the driver to update the ring pointer
 *    by writing the high register again.
 *
 * 3. BOOT ROM STATUS: When delivering boot ROM data, the first segment returns
 *    status 0xC000 (bits 15,14 set = not last segment) and the second returns
 *    0x8000 (bit 15 set = last segment, bootrom special).
 *
 * 4. RX STATUS WORDS: Normal packets use 0x0000 for last segment, 0xC000 for
 *    not-last (multi-buffer packets). Errors add appropriate error bits.
 *
 * 5. DEFERRED REGISTER WRITES: CSR and VAR are processed immediately since
 *    they don't trigger DMA. Other registers (RCLL/H, XMTL/H) are queued and
 *    processed by worker threads to avoid DMA deadlocks where the PRU waits
 *    for bus grant while the CPU polls CSR.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <algorithm>
#include <vector>
#include <utility>

#include "logger.hpp"
#include "utils.hpp"
#include "timeout.hpp"
#include "qunibus.h"
#include "qunibusadapter.hpp"
#include "ddrmem.h"
#include "delqa.hpp"
#include "delqa_bootrom.h"

#if !defined(QBUS)
#error "DELQA is a QBUS-only device"
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
static const size_t XQ_MAX_RCV_PACKET = 1600;  // Buffer size for oversized frames
static const size_t XQ_LONG_PACKET = 0x0600;   // 1536 bytes - jumbo threshold

/*
 * Queue and timer constants
 */
static const unsigned XQ_QUE_MAX = 500;         // Max packets in RX queue
static const unsigned XQ_SERVICE_INTERVAL = 100; // Timer service rate (Hz)
static const unsigned XQ_SYSTEM_ID_SECS = 540;   // MOP system ID interval (9 min)
static const unsigned XQ_HW_SANITY_SECS = 240;   // Hardware sanity timeout (4 min)

/*
 * Descriptor ring control bits (word 1 of descriptor)
 * These are mapped from delqa_regs.h QE_RING_* constants for clarity.
 */
static const uint16_t XQ_DSC_V = QE_RING_VALID;     // Descriptor is valid
static const uint16_t XQ_DSC_C = QE_RING_CHAIN;     // Chain to address in words 1,2
static const uint16_t XQ_DSC_E = QE_RING_EOMSG;     // End of message (last segment)
static const uint16_t XQ_DSC_S = QE_RING_SETUP;     // Setup packet (TX only)
static const uint16_t XQ_DSC_L = QE_RING_ODD_END;   // Odd byte at end (subtract 1)
static const uint16_t XQ_DSC_H = QE_RING_ODD_BEGIN; // Odd byte at start (subtract 1)

/*
 * CSR (Control/Status Register) bit definitions
 * Mapped from delqa_regs.h QE_* constants for code clarity.
 */
static const uint16_t XQ_CSR_RI = QE_RCV_INT;       // Receive interrupt pending
static const uint16_t XQ_CSR_PE = QE_PARITY;        // Parity error
static const uint16_t XQ_CSR_CA = QE_CARRIER;       // Carrier detect
static const uint16_t XQ_CSR_OK = QE_OK;            // Transceiver OK
static const uint16_t XQ_CSR_SE = QE_STIM_ENABLE;   // Sanity timer enable
static const uint16_t XQ_CSR_EL = QE_ELOOP;         // External loopback
static const uint16_t XQ_CSR_IL = QE_ILOOP;         // Internal loopback
static const uint16_t XQ_CSR_XI = QE_XMIT_INT;      // Transmit interrupt pending
static const uint16_t XQ_CSR_IE = QE_INT_ENABLE;    // Interrupt enable
static const uint16_t XQ_CSR_RL = QE_RL_INVALID;    // Receive list invalid
static const uint16_t XQ_CSR_XL = QE_XL_INVALID;    // Transmit list invalid
static const uint16_t XQ_CSR_BD = QE_LOAD_ROM;      // Boot/diagnostic ROM bit
static const uint16_t XQ_CSR_NI = QE_NEX_MEM_INT;   // Non-existent memory interrupt
static const uint16_t XQ_CSR_SR = QE_RESET;         // Software reset
static const uint16_t XQ_CSR_RE = QE_RCV_ENABLE;    // Receive enable

static const uint16_t XQ_CSR_RO = QE_CSR_RO;        // Read-only bits mask
static const uint16_t XQ_CSR_RW = QE_CSR_RW;        // Read-write bits mask
static const uint16_t XQ_CSR_W1 = QE_CSR_W1;        // Write-1-to-clear bits mask
static const uint16_t XQ_CSR_BP = QE_CSR_BP;        // Boot/diag ROM request bits
static const uint16_t XQ_CSR_XIRI = (XQ_CSR_XI | XQ_CSR_RI);  // Any interrupt pending

/*
 * VAR (Vector Address Register) bit definitions
 */
static const uint16_t XQ_VEC_MS = QE_VEC_MS;  // Mode select (1=DELQA, 0=DEQNA compat)
static const uint16_t XQ_VEC_OS = QE_VEC_OS;  // Option switch
static const uint16_t XQ_VEC_RS = QE_VEC_RS;  // Request self-test
static const uint16_t XQ_VEC_ST = QE_VEC_ST;  // Self-test status
static const uint16_t XQ_VEC_IV = QE_VEC_IV;  // Interrupt vector mask
static const uint16_t XQ_VEC_RO = QE_VEC_RO;  // Read-only bits mask
static const uint16_t XQ_VEC_RW = QE_VEC_RW;  // Read-write bits mask

/*
 * Version string - increment on each code change to verify running code freshness
 */
static const char *DELQA_VERSION = "v012";  // Added comprehensive documentation

/*
 * Setup packet bit definitions (length field encodes these)
 */
static const uint16_t XQ_SETUP_MC = 0x0001;  // Accept all multicast
static const uint16_t XQ_SETUP_PM = 0x0002;  // Promiscuous mode
static const uint16_t XQ_SETUP_LD = 0x000C;  // LED control bits
static const uint16_t XQ_SETUP_ST = 0x0070;  // Sanity timer setting

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

static bool mac_is_zero(const uint8_t *mac)
{
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

/*
 * DELQA Constructor
 * ------------------
 * Initializes the device with:
 *   - Two worker threads (RX and TX)
 *   - Eight device registers (SA0-5, VAR, CSR)
 *   - Default MAC address (OpenSIMH XQA0 default: 08:00:2B:AA:BB:CC)
 *   - Packet buffers sized for maximum Ethernet frames
 */
delqa_c::delqa_c() : qunibusdevice_c()
{
    set_workers_count(2);  // Instance 0 = RX, Instance 1 = TX

    name.value = "delqa";
    type_name.value = "DELQA";
    log_label = "delqa";

    set_default_bus_params(DELQA_DEFAULT_ADDR, DELQA_DEFAULT_SLOT, DELQA_DEFAULT_VECTOR, DELQA_DEFAULT_LEVEL);
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

    // OpenSIMH default MAC for XQA0 (DELQA)
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

delqa_c::~delqa_c()
{
#ifdef HAVE_PCAP
    pcap.close();
#endif
}

bool delqa_c::parse_mac(const std::string &text, uint8_t out[6])
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

bool delqa_c::on_param_changed(parameter_c *param)
{
    if (param == &priority_slot) {
        dma_request.set_priority_slot(priority_slot.new_value);
        intr_request.set_priority_slot(priority_slot.new_value);
    } else if (param == &intr_level) {
        intr_request.set_level(intr_level.new_value);
    } else if (param == &intr_vector) {
        intr_request.set_vector(intr_vector.new_value);
    } else if (param == &ifname) {
        if (handle) {
            WARNING("DELQA: ifname cannot be changed while device is installed");
            return false;
        }
    } else if (param == &promisc) {
        update_pcap_filter();
    } else if (param == &mac) {
        if (mac.new_value.empty()) {
            mac_override = false;
        } else if (!parse_mac(mac.new_value, mac_addr)) {
            ERROR("DELQA: invalid MAC format '%s'", mac.new_value.c_str());
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

bool delqa_c::on_before_install(void)
{
#ifndef HAVE_PCAP
    ERROR("DELQA: libpcap support not compiled in - install libpcap-dev and rebuild with HAVE_PCAP");
    return false;
#else
    if (ifname.value.empty()) {
        ERROR("DELQA: ifname must be set");
        return false;
    }

    if (!pcap.open(ifname.value, promisc.value, 2048, 1)) {
        ERROR("DELQA: failed to open pcap on %s: %s", ifname.value.c_str(),
              pcap.last_error().c_str());
        return false;
    }

    INFO("DELQA: PCAP opened successfully on interface %s", ifname.value.c_str());

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

void delqa_c::on_after_install(void)
{
    reset_controller();
}

void delqa_c::on_after_uninstall(void)
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

void delqa_c::on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge)
{
    UNUSED(aclo_edge);
    if (dclo_edge == SIGNAL_EDGE_RAISING)
        reset_controller();
}

void delqa_c::on_init_changed(void)
{
    if (init_asserted)
        reset_controller();
}

void delqa_c::update_mac_checksum(void)
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

void delqa_c::update_station_regs(void)
{
    if (!handle)
        return;

    for (int i = 0; i < 6; ++i) {
        uint8_t value = mac_addr[i];
        if (i < 2 && (csr & XQ_CSR_EL))
            value = mac_checksum[i];
        uint16_t word = static_cast<uint16_t>(0xff00 | value);
        set_register_dati_value(reg_sta_addr[i], word, "update_station_regs");
    }
}

void delqa_c::update_vector_reg(void)
{
    if (!handle)
        return;
    set_register_dati_value(reg_vector, var, "update_vector_reg");
}

void delqa_c::update_csr_reg(void)
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
void delqa_c::update_transceiver_bits(void)
{
    if (pcap.is_open())
        csr |= XQ_CSR_OK;
    else
        csr &= ~XQ_CSR_OK;

    csr &= ~XQ_CSR_CA;  // Always report carrier present
}

/*
 * Interrupt management
 * ---------------------
 * Interrupts are level-sensitive: asserted when IE=1 and (RI|XI) != 0.
 * set_int/clr_int update the internal irq flag and signal the bus.
 */
void delqa_c::set_int(void)
{
    irq = true;
    if (trace.value)
        WARNING("DELQA: INTR assert, csr=%06o ie=%d", csr, (csr & XQ_CSR_IE) ? 1 : 0);
    update_intr();
}

void delqa_c::clr_int(void)
{
    irq = false;
    if (trace.value)
        WARNING("DELQA: INTR deassert, csr=%06o ie=%d", csr, (csr & XQ_CSR_IE) ? 1 : 0);
    update_intr();
}

/*
 * csr_set_clr - Atomically set and clear CSR bits with interrupt side effects
 *
 * This function handles the complex interrupt logic:
 * - If IE transitions, update interrupt state accordingly
 * - If RI or XI change while IE=1, assert/deassert interrupt
 * - Always update transceiver bits and register read value after
 */
void delqa_c::csr_set_clr(uint16_t set_bits, uint16_t clear_bits)
{
    uint16_t saved_csr = csr;
    csr = static_cast<uint16_t>((csr | set_bits) & ~clear_bits);

    // Handle interrupt enable changes
    if ((saved_csr ^ csr) & XQ_CSR_IE) {
        if ((clear_bits & XQ_CSR_IE) && irq)
            clr_int();
        if ((set_bits & XQ_CSR_IE) && (csr & XQ_CSR_XIRI) && !irq)
            set_int();
    } else {
        // IE unchanged - check for RI/XI changes
        if (csr & XQ_CSR_IE) {
            if (((saved_csr ^ csr) & (set_bits & XQ_CSR_XIRI)) && !irq) {
                set_int();
            } else if (((saved_csr ^ csr) & (clear_bits & XQ_CSR_XIRI)) &&
                       !(csr & XQ_CSR_XIRI) && irq) {
                clr_int();
            }
        }
    }

    update_transceiver_bits();
    update_csr_reg();

    if (trace.value && ((saved_csr ^ csr) & (XQ_CSR_RL | XQ_CSR_XL | XQ_CSR_RI | XQ_CSR_XI))) {
        WARNING("DELQA: CSR change prev=%06o now=%06o set=%06o clr=%06o",
                saved_csr, csr, set_bits, clear_bits);
    }
}

void delqa_c::nxm_error(void)
{
    const uint16_t set_bits = XQ_CSR_XI | XQ_CSR_XL | XQ_CSR_RL;
    csr_set_clr(set_bits, 0);
    stats.fail++;
    stat_tx_errors.value = stats.fail;
}

bool delqa_c::rx_ready(void)
{
    if (!(csr & XQ_CSR_RE))
        return false;
    if (!rx_delay_active)
        return true;
    if (timeout_c::abstime_ns() >= rx_enable_deadline_ns) {
        rx_delay_active = false;
        return true;
    }
    return false;
}

void delqa_c::start_rx_delay(void)
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
 */
void delqa_c::update_intr(void)
{
    bool level = irq;

    switch (intr_request.edge_detect(level)) {
    case intr_request_c::INTERRUPT_EDGE_RAISING:
        if (trace.value) {
            INFO("DELQA: INTR assert, csr=%06o vec=%03o level=%d",
                 csr, intr_request.get_vector(), intr_request.get_level());
        }
        qunibusadapter->INTR(intr_request, nullptr, 0);
        break;
    case intr_request_c::INTERRUPT_EDGE_FALLING:
        if (trace.value) {
            INFO("DELQA: INTR deassert, csr=%06o", csr);
        }
        qunibusadapter->cancel_INTR(intr_request);
        break;
    default:
        break;
    }
}

/*
 * reset_sanity_timer - Reset the watchdog timer
 *
 * Called after each successful transmit. If the timer expires before
 * the next TX, the controller is reset (prevents hung driver situations).
 */
void delqa_c::reset_sanity_timer(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!sanity.enabled)
        return;
    sanity.timer = sanity.max;
}

/*
 * service_timers - Periodic timer service (called from RX worker)
 *
 * Handles:
 * - Sanity timer: decrements and resets controller on expiry
 * - System ID timer: sends MOP system ID multicast every ~9 minutes
 */
void delqa_c::service_timers(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (sanity.enabled) {
        if (--sanity.timer <= 0) {
            WARNING("DELQA: sanity timer expired");
            reset_controller();
            return;
        }
    }

    // Send MOP system ID periodically (DECnet requirement)
    if (--idtmr <= 0) {
        const uint8_t mop_multicast[6] = {0xAB, 0x00, 0x00, 0x02, 0x00, 0x00};
        send_system_id(mop_multicast, 0);
        idtmr = static_cast<int>(XQ_SYSTEM_ID_SECS * XQ_SERVICE_INTERVAL);
    }
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
void delqa_c::reset_controller(void)
{
    reset_in_progress.store(true, std::memory_order_release);
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    // Clear descriptor ring pointers
    rbdl[0] = 0;
    rbdl[1] = 0;
    xbdl[0] = 0;
    xbdl[1] = 0;

    // Initialize VAR with DELQA mode bits and configured vector
    var = static_cast<uint16_t>(XQ_VEC_MS | XQ_VEC_OS | (intr_vector.value & XQ_VEC_IV));
    // Initialize CSR with both lists invalid
    csr = static_cast<uint16_t>(XQ_CSR_RL | XQ_CSR_XL);

    update_mac_checksum();
    update_transceiver_bits();
    update_station_regs();
    update_vector_reg();
    update_csr_reg();

    rbdl_ba = 0;
    xbdl_ba = 0;
    irq = false;
    intr_request.edge_detect_reset();
    intr_request.set_vector(var & XQ_VEC_IV);

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        if (!read_queue.empty()) {
            WARNING("DELQA: reset_controller clearing RX queue (size=%zu)", read_queue.size());
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
    xbdl_pending = false;
    bootrom_pending = false;

    sanity.enabled = 0;
    sanity.quarter_secs = XQ_HW_SANITY_SECS * 4;
    sanity.max = static_cast<int>(XQ_HW_SANITY_SECS * XQ_SERVICE_INTERVAL);
    sanity.timer = sanity.max;

    idtmr = static_cast<int>(XQ_SYSTEM_ID_SECS * XQ_SERVICE_INTERVAL);

    if (pcap.is_open())
        csr_set_clr(XQ_CSR_OK, 0);

    update_pcap_filter();
    reset_in_progress.store(false, std::memory_order_release);
}

/*
 * sw_reset - Software reset
 *
 * Clears all state, sets RL and XL (lists invalid), and updates all registers.
 * Called when software writes to the CSR reset bit.
 */

void delqa_c::sw_reset(void)
{
    reset_in_progress.store(true, std::memory_order_release);
    const uint16_t set_bits = XQ_CSR_XL | XQ_CSR_RL;

    csr_set_clr(set_bits, static_cast<uint16_t>(~set_bits));

    if (pcap.is_open())
        csr_set_clr(XQ_CSR_OK, 0);

    clr_int();

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        if (!read_queue.empty()) {
            WARNING("DELQA: sw_reset clearing RX queue (size=%zu)", read_queue.size());
        }
        read_queue.clear();
        read_queue_loss = 0;
    }

    setup.multicast = false;
    setup.promiscuous = false;

    update_pcap_filter();
    reset_in_progress.store(false, std::memory_order_release);
}

/* update_pcap_filter - Update libpcap filter based on current setup
 *
 * Constructs a pcap filter string based on the current MAC address,
 * promiscuous mode, and multicast settings. Applies the filter to
 * the pcap interface.
 */

void delqa_c::update_pcap_filter(void)
{
#ifdef HAVE_PCAP
    if (!pcap.is_open())
        return;

    if (promisc.value || setup.promiscuous) {
        if (!pcap.set_filter("ip or not ip")) {
            WARNING("DELQA: pcap filter set failed: %s", pcap.last_error().c_str());
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

    add_mac(mac_addr);
    if (setup.valid) {
        for (int i = 0; i < XQ_FILTER_MAX; ++i) {
            if (!mac_is_zero(setup.macs[i]))
                add_mac(setup.macs[i]);
        }
    }

    if (filter.empty())
        filter = "ip or not ip";

    if (!pcap.set_filter(filter)) {
        WARNING("DELQA: pcap filter set failed: %s", pcap.last_error().c_str());
    }
#endif
}

/* make_addr - Construct a 22-bit address from high and low words   
 *
 * Takes into account the qunibus address width to mask off unused bits in the high word.
 */

uint32_t delqa_c::make_addr(uint16_t hi, uint16_t lo) const
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
 * Processes writes to the DELQA registers, updating internal state
 * as needed. Writes to RCLH and XMTH trigger processing of the
 * respective descriptor rings.
 */

void delqa_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    UNUSED(access);
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    uint16_t val = get_register_dato_value(device_reg);
    if (device_reg->index == DELQA_REG_VECTOR || device_reg->index == DELQA_REG_CSR) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        handle_register_write(static_cast<uint8_t>(device_reg->index), val);
        return;
    }
    if (device_reg->index < 8) {
        pending_reg_value[device_reg->index].store(val, std::memory_order_relaxed);
        pending_reg_mask.fetch_or(static_cast<uint16_t>(1u << device_reg->index),
                std::memory_order_release);
    }
}

/* handle_register_write - Process writes to DELQA registers    
 *
 * Updates internal state based on register writes. Called from
 * on_after_register_access after acquiring state mutex.
 */

void delqa_c::handle_register_write(uint8_t reg_index, uint16_t val)
{
    if (trace.value) {
        static const char *reg_names[] = {
            "STA0", "STA1", "RCLL", "RCLH", "XMTL", "XMTH", "VAR", "CSR"
        };
        const char *rname = (reg_index < 8) ? reg_names[reg_index] : "???";
        INFO("DELQA: Write %s (reg %d) = %06o", rname, reg_index, val);
    }

    switch (reg_index) {
    case DELQA_REG_RCVLIST_LO:
        rbdl[0] = val;
        break;
    case DELQA_REG_RCVLIST_HI:
        rbdl[1] = val;
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
        csr_set_clr(0, XQ_CSR_RL);
        rbdl_pending = true;
        if (trace.value)
            WARNING("DELQA: RX list base set to %06o (csr=%06o)", rbdl_ba, csr);
        break;
    case DELQA_REG_XMTLIST_LO:
        xbdl[0] = val;
        break;
    case DELQA_REG_XMTLIST_HI:
        xbdl[1] = val;
        xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
        csr_set_clr(0, XQ_CSR_XL);
        xbdl_pending = true;
        if (trace.value)
            WARNING("DELQA: TX list base set to %06o (csr=%06o)", xbdl_ba, csr);
        break;
    case DELQA_REG_VECTOR: {
        uint16_t old_var = var;
        uint16_t new_var;

        new_var = static_cast<uint16_t>((var & XQ_VEC_RO) | (val & XQ_VEC_RW));
        if (!(new_var & XQ_VEC_MS))
            new_var &= ~(XQ_VEC_OS | XQ_VEC_RS | XQ_VEC_ST);

        if ((old_var ^ new_var) & XQ_VEC_MS) {
            if (!(new_var & XQ_VEC_MS))
                deqna_lock = true;
            else
                deqna_lock = false;
        }

        if (new_var & XQ_VEC_RS)
            new_var &= ~XQ_VEC_RS;

        var = new_var;
        update_vector_reg();
        intr_request.set_vector(var & XQ_VEC_IV);
        break;
    }
    case DELQA_REG_CSR: {
        uint16_t prev = csr;
        uint16_t set_bits = val & XQ_CSR_RW;
        uint16_t clr_bits = static_cast<uint16_t>(((val ^ XQ_CSR_RW) & XQ_CSR_RW) |
                                                  (val & XQ_CSR_W1) |
                                                  ((val & XQ_CSR_XI) ? XQ_CSR_NI : 0));

        if ((prev & XQ_CSR_SR) && !(val & XQ_CSR_SR)) {
            sw_reset();
            return;
        }

        csr_set_clr(set_bits, clr_bits);

        if ((prev ^ csr) & XQ_CSR_RE) {
            if (csr & XQ_CSR_RE)
                start_rx_delay();
            else
                rx_delay_active = false;
        }

        if ((prev ^ csr) & XQ_CSR_EL)
            update_station_regs();

        if ((csr & XQ_CSR_BP) == XQ_CSR_BP) {
            if (trace.value)
                WARNING("DELQA: Boot/diagnostic ROM request (BP bits set)");
            bootrom_pending = true;
        }
        break;
    }
    default:
        break;
    }
}

/* apply_pending_reg_writes - Apply pending register writes
 *
 * Processes any pending register writes that were deferred
 * from on_after_register_access. Called from worker threads
 * to ensure register writes are handled in a thread-safe manner.
 */

void delqa_c::apply_pending_reg_writes(void)
{
    uint16_t mask = pending_reg_mask.exchange(0, std::memory_order_acquire);
    if (!mask)
        return;

    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    for (uint8_t idx = 0; idx < 8; ++idx) {
        if (mask & static_cast<uint16_t>(1u << idx)) {
            uint16_t val = pending_reg_value[idx].load(std::memory_order_relaxed);
            handle_register_write(idx, val);
        }
    }
}

/* dma_read_words - Perform a DMA read operation
 *
 * Reads 'wordcount' words from 'addr' into 'buffer' using DMA.
 * Returns true on success, false on failure (e.g., NXM).
 * Handles DDR memory accesses directly if applicable.
 */

bool delqa_c::dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;
    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
    uint64_t max = qunibus->addr_space_byte_count;
    if (max == 0 || addr64 >= max || byte_count > max - addr64)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr64 >= ddrmem->qunibus_startaddr &&
        (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->exam(addr + static_cast<uint32_t>(i * 2), &buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
//    WARNING("DELQA: DMA read_words addr=%06o words=%zu", addr, wordcount);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
//    WARNING("DELQA: DMA read_words done addr=%06o ok=%d", addr, dma_request.success ? 1 : 0);
    return dma_request.success;
}

/* dma_write_words - Perform a DMA write operation
 *
 * Writes 'wordcount' words from 'buffer' to 'addr' using DMA.
 * Returns true on success, false on failure (e.g., NXM).
 * Handles DDR memory accesses directly if applicable.
 */

bool delqa_c::dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;
    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
    uint64_t max = qunibus->addr_space_byte_count;
    if (max == 0 || addr64 >= max || byte_count > max - addr64)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr64 >= ddrmem->qunibus_startaddr &&
        (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
//    WARNING("DELQA: DMA write_words addr=%06o words=%zu", addr, wordcount);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATO, addr,
            const_cast<uint16_t *>(buffer), wordcount);
//    WARNING("DELQA: DMA write_words done addr=%06o ok=%d", addr, dma_request.success ? 1 : 0);
    return dma_request.success;
}

/* desc_read_words - Perform a descriptor read operation
 *
 * Reads 'wordcount' words from 'addr' into 'buffer' using DMA.
 * Returns true on success, false on failure (e.g., NXM).
 * Handles DDR memory accesses directly if applicable.
 */

bool delqa_c::desc_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;
    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
    uint64_t max = qunibus->addr_space_byte_count;
    if (max == 0 || addr64 >= max || byte_count > max - addr64)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr64 >= ddrmem->qunibus_startaddr &&
        (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->exam(addr + static_cast<uint32_t>(i * 2), &buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_desc_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
    return dma_desc_request.success;
}

/* desc_write_words - Perform a descriptor write operation
 *
 * Writes 'wordcount' words from 'buffer' to 'addr' using DMA.
 * Returns true on success, false on failure (e.g., NXM).
 * Handles DDR memory accesses directly if applicable.
 */

bool delqa_c::desc_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;
    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
    uint64_t max = qunibus->addr_space_byte_count;
    if (max == 0 || addr64 >= max || byte_count > max - addr64)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr64 >= ddrmem->qunibus_startaddr &&
        (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_desc_request, true, QUNIBUS_CYCLE_DATO, addr,
            const_cast<uint16_t *>(buffer), wordcount);
    return dma_desc_request.success;
}

/* dma_read_bytes - Perform a DMA read operation for bytes  
 *
 * Reads 'len' bytes from 'addr' into 'buffer' using DMA.
 * Returns true on success, false on failure (e.g., NXM).
 * Handles odd-length reads by reading an extra word if needed.
 */

bool delqa_c::dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;
    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(len);
    uint64_t max = qunibus->addr_space_byte_count;
    if (max == 0 || addr64 >= max || byte_count > max - addr64)
        return false;

    size_t full_words = len / 2;
    if (full_words) {
        std::vector<uint16_t> words(full_words);
        if (!dma_read_words(addr, words.data(), full_words))
            return false;
        for (size_t i = 0; i < full_words; ++i) {
            buffer[2 * i] = word_low(words[i]);
            buffer[2 * i + 1] = word_high(words[i]);
        }
    }

    if (len & 1) {
        uint16_t word = 0;
        if (!dma_read_words(addr + full_words * 2, &word, 1))
            return false;
        buffer[len - 1] = word_low(word);
    }
    return true;
}

/* dma_write_bytes - Perform a DMA write operation for bytes  
 *
 * Writes 'len' bytes from 'buffer' to 'addr' using DMA.
 * Returns true on success, false on failure (e.g., NXM).
 * Handles odd-length writes by reading-modifying-writing an extra word if needed.
 */

bool delqa_c::dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;
    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(len);
    uint64_t max = qunibus->addr_space_byte_count;
    if (max == 0 || addr64 >= max || byte_count > max - addr64)
        return false;

    const size_t max_words_per_dma = 64;
    size_t full_words = len / 2;
    if (full_words) {
        size_t word_index = 0;
        while (word_index < full_words) {
            size_t chunk_words = full_words - word_index;
            if (chunk_words > max_words_per_dma)
                chunk_words = max_words_per_dma;

            std::vector<uint16_t> words(chunk_words);
            for (size_t i = 0; i < chunk_words; ++i) {
                size_t byte_index = (word_index + i) * 2;
                words[i] = static_cast<uint16_t>(buffer[byte_index])
                        | static_cast<uint16_t>(buffer[byte_index + 1] << 8);
            }

            uint32_t addr_offset = static_cast<uint32_t>(word_index * 2);
            if (!dma_write_words(addr + addr_offset, words.data(), chunk_words))
                return false;

            word_index += chunk_words;
        }
    }

    if (len & 1) {
        uint16_t word = 0;
        if (!dma_read_words(addr + full_words * 2, &word, 1))
            return false;
        word = static_cast<uint16_t>((word & 0xff00) | buffer[len - 1]);
        if (!dma_write_words(addr + full_words * 2, &word, 1))
            return false;
    }

    return true;
}

/*
 * enqueue_readq - Add a received packet to the RX queue
 *
 * @param type   Packet type: 0=setup echo, 1=loopback, 2=normal
 * @param data   Packet data pointer
 * @param len    Packet length in bytes
 * @param status Status code (unused, for future expansion)
 *
 * If the queue is full (XQ_QUE_MAX), the oldest packet is dropped.
 * This ensures we don't block indefinitely when the driver is slow
 * to provide RX descriptors.
 */
void delqa_c::enqueue_readq(int type, const uint8_t *data, size_t len, int status)
{
    std::lock_guard<std::mutex> lock(queue_mutex);  // Fix: Use queue_mutex for queue access
    if (trace.value) {
        WARNING("DELQA: Enqueue RX type=%d len=%zu status=%06o queue=%zu",
                type, len, static_cast<uint16_t>(status), read_queue.size());
    }

    if (read_queue.size() >= XQ_QUE_MAX) {
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
    read_queue.push_back(std::move(item));
}

/*
 * dispatch_rbdl - Start RX descriptor ring processing
 *
 * Called when:
 * - RCLH register is written (driver provides new RX ring)
 * - Packets are waiting in queue and RL is clear
 *
 * SimH-compatible behavior:
 * 1. Clear RL bit (list is now valid)
 * 2. Recalculate rbdl_ba from RCLH:RCLL registers (allows driver to
 *    update ring pointer by writing RCLH again)
 * 3. Read first descriptor (but don't write 0xFFFF flag yet)
 * 4. If packets are queued, call process_rbdl() to deliver them
 *
 * Returns: true on success, false on NXM error
 */
bool delqa_c::dispatch_rbdl(void)
{
    uint32_t cur_ba = 0;
    uint16_t csr_snapshot = 0;
    size_t queue_size = 0;
    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        queue_size = read_queue.size();
    }
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        // SimH: clear RL and recalculate rbdl_ba from base registers
        csr_set_clr(0, XQ_CSR_RL);
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
        cur_ba = rbdl_ba;
        csr_snapshot = csr;
    }
    if (cur_ba == 0)
        return false;

    if (trace.value) {
        WARNING("DELQA: RX list dispatch at %06o (csr=%06o queue=%zu)",
                cur_ba, csr_snapshot, queue_size);
        WARNING("DELQA: RX list dispatch after RL clear at %06o (csr=%06o)",
                cur_ba, csr_snapshot);
    }

    // SimH: only READ the descriptor in dispatch, don't write 0xFFFF yet
    uint16_t words[4] = {0};
    for (size_t i = 0; i < 4; ++i) {
        if (!desc_read_words(cur_ba + static_cast<uint32_t>(i * 2), &words[i], 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(XQ_CSR_RL, 0);  // Mark list invalid on NXM
            return false;
        }
    }

    if (trace.value) {
        WARNING("DELQA: RX dispatch read words0=%06o words1=%06o words2=%06o words3=%06o",
                words[0], words[1], words[2], words[3]);
    }

    // Process any waiting packets in receive queue
    bool do_process = false;
    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        do_process = !read_queue.empty();
    }
    if (do_process)
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
 */
bool delqa_c::process_rbdl(void)
{
    bool ri_pending = false;
    while (true) {
        uint32_t cur_ba = 0;
        size_t queue_size = 0;
        uint16_t csr_snapshot = 0;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            queue_size = read_queue.size();
        }
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = rbdl_ba;
            csr_snapshot = csr;
        }
        if (trace.value) {
            WARNING("DELQA: RX process start at %06o (queue=%zu csr=%06o)",
                    cur_ba, queue_size, csr_snapshot);
        }
        if (queue_size == 0) {
            if (trace.value) {
                WARNING("DELQA: RX process idle at %06o (queue empty, csr=%06o)",
                        cur_ba, csr_snapshot);
            }
            break;
        }
        uint16_t words[QE_RING_WORDS] = {0};
        uint16_t flag = 0xFFFF;  // Device ownership flag

        // Write flag to claim descriptor
        if (trace.value)
            WARNING("DELQA: RX desc fetch at %06o (pre-write)", cur_ba);
        if (!desc_write_words(cur_ba, &flag, 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(XQ_CSR_RL, 0);
            return false;
        }
        if (trace.value)
            WARNING("DELQA: RX desc fetch at %06o (pre-read)", cur_ba);
        for (size_t i = 1; i < QE_RING_WORDS; ++i) {
            if (!desc_read_words(cur_ba + 2 + static_cast<uint32_t>((i - 1) * 2), &words[i], 1)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                csr_set_clr(XQ_CSR_RL, 0);
                return false;
            }
        }
        if (trace.value) {
            WARNING("DELQA: RX desc %06o words1=%06o words2=%06o words3=%06o",
                    cur_ba, words[1], words[2], words[3]);
        }

        if (~words[1] & XQ_DSC_V) {
            if (trace.value) {
                WARNING("DELQA: RX descriptor at %06o not valid (addr_hi=%06o)",
                        cur_ba, words[1]);
            }
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                csr_set_clr(XQ_CSR_RL, 0);
            }
            return false;
        }

        if (words[1] & XQ_DSC_C) {
            uint32_t next_ba = make_addr(words[1], words[2]);
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                rbdl_ba = next_ba;
            }
            continue;
        }

        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue.empty()) {
                if (trace.value) {
                    WARNING("DELQA: RX list idle at %06o (queue empty)",
                            cur_ba);
                }
                break;
            }
        }

        if (!desc_read_words(cur_ba + 8, &words[4], 2)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(XQ_CSR_RL, 0);
            return false;
        }

        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        if (words[1] & XQ_DSC_H)
            b_length -= 1;
        if (words[1] & XQ_DSC_L)
            b_length -= 1;

        queue_item item;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue.empty()) {
                if (trace.value) {
                    WARNING("DELQA: RX list idle at %06o (queue empty)",
                            cur_ba);
                }
                break;
            }
            item = std::move(read_queue.front());
            read_queue.pop_front();
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
        size_t remaining = item.packet.len - used_before;
        bool overflow = false;
        if (rbl > b_length) {
            rbl = b_length;
            overflow = true;
        }
        item.packet.used = used_before + rbl;
        if (overflow)
            item.packet.used = item.packet.len;

        bool dma_failed = false;
        if (!dma_write_bytes(address, rbuf, rbl)) {
            // Treat RX buffer DMA failure as a dropped packet so we can still
            // write status back to the descriptor instead of raising NI.
            dma_failed = true;
            rbl = 0;
            item.packet.used = item.packet.len;
        }

        // Status word 1: start with 0 (last segment, no errors), add type-specific bits
        words[4] = 0;
        switch (item.type) {
        case 0:
            stats.setup++;
            words[4] |= 0x2700;
            break;
        case 1:
            stats.loop++;
            words[4] |= 0x2000;
            words[4] |= static_cast<uint16_t>(rbl & 0x0700);
            break;
        case 2:
        default:
            rbl -= 60;
            words[4] |= static_cast<uint16_t>(rbl & 0x0700);
            break;
        }

        if (dma_failed) {
            words[4] |= QE_RST_LASTERR;
            words[4] |= QE_DISCARD;
        } else if (overflow) {
            words[4] |= QE_RST_LASTERR;
            words[4] |= QE_OVF | QE_DISCARD;
        } else if (item.packet.used < item.packet.len) {
            words[4] |= QE_RST_LASTNOT;  // 0xC000 = not last segment
        }
        words[5] = static_cast<uint16_t>(((rbl & 0x00FF) << 8) | (rbl & 0x00FF));

        bool loss = false;
        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue_loss) {
                loss = true;
                read_queue_loss = 0;
            }
        }
        if (loss)
            words[4] |= 0x0001;

        if (!desc_write_words(cur_ba + 8, &words[4], 2)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(XQ_CSR_RL, 0);
            return false;
        }

        if (trace.value) {
            WARNING("DELQA: RX desc %06o writeback status1=%06o status2=%06o bytes=%u",
                    cur_ba, words[4], words[5], static_cast<unsigned>(rbl));
        }

        if (item.packet.used < item.packet.len) {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            read_queue.push_front(std::move(item));
        }

        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = cur_ba + QE_RING_BYTES;
        }
        ri_pending = true;
    }

    if (ri_pending) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(XQ_CSR_RI, 0);
    }

    return true;
}

void delqa_c::touch_rbdl_if_idle(void)
{
    // SimH doesn't have this function - descriptors are only touched when processing packets
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
        WARNING("DELQA: RX idle at %06o (queue empty)", rbdl_ba);
    }
}

/*
 * dispatch_xbdl - Start TX descriptor ring processing
 *
 * Called when XMTH register is written (driver provides new TX ring).
 *
 * SimH-compatible behavior:
 * 1. Clear XL bit (list is now valid)
 * 2. Recalculate xbdl_ba from XMTH:XMTL registers
 * 3. Reset write_buffer for new packet assembly
 * 4. Call process_xbdl() to transmit queued packets
 *
 * Returns: true on success, false on NXM error
 */
bool delqa_c::dispatch_xbdl(void)
{
    uint32_t cur_ba = 0;
    uint16_t csr_snapshot = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, XQ_CSR_XL);

        // SimH: Always recalculate xbdl_ba from base registers when dispatching
        xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
        cur_ba = xbdl_ba;
        csr_snapshot = csr;

        write_buffer.len = 0;
        write_buffer.used = 0;
    }
    if (cur_ba == 0)
        return false;

    if (trace.value)
        WARNING("DELQA: TX list dispatch at %06o (csr=%06o)", cur_ba, csr_snapshot);

    return process_xbdl();
}

/*
 * write_callback - Handle TX completion (success or failure)
 *
 * @param status  0 = success, non-zero = failure
 *
 * Called after pcap.send() completes. Updates descriptor status words,
 * clears V bit to return descriptor to driver, sets XI interrupt,
 * and continues processing any remaining TX descriptors.
 *
 * TDR (Transmit Delay Report) is a rough estimate of transmission time
 * in bit times, used by the driver for collision backoff calculations.
 */
void delqa_c::write_callback(int status)
{
    uint32_t cur_ba = 0;
    size_t len_snapshot = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        cur_ba = xbdl_ba;
        len_snapshot = write_buffer.len;
    }
    const uint16_t TDR = static_cast<uint16_t>(100 + len_snapshot * 8);
    uint16_t write_success[2] = {0, static_cast<uint16_t>(TDR & 0x03FF)};
    uint16_t write_failure[2] = {XQ_DSC_C, static_cast<uint16_t>(TDR & 0x03FF)};

    stats.xmit++;
    stat_tx_frames.value = stats.xmit;

    // Write status words back to descriptor
    if (!desc_write_words(cur_ba + 8, (status == 0) ? write_success : write_failure, 2)) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        nxm_error();
        return;
    }

    // Clear V bit to return descriptor to driver
    {
        uint16_t word1 = 0;
        if (desc_read_words(cur_ba + 2, &word1, 1)) {
            word1 = static_cast<uint16_t>(word1 & ~XQ_DSC_V);
            desc_write_words(cur_ba + 2, &word1, 1);
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        if (status != 0) {
            stats.fail++;
            stat_tx_errors.value = stats.fail;
        }

        csr_set_clr(XQ_CSR_XI, 0);  // Set transmit interrupt
        write_buffer.len = 0;
        write_buffer.used = 0;
        xbdl_ba = cur_ba + QE_RING_BYTES;  // Advance to next descriptor
    }

    reset_sanity_timer();

    process_xbdl();  // Continue processing remaining TX descriptors
}

/*
 * process_xbdl - Process TX descriptors and transmit packets
 *
 * This is the main TX processing loop. For each descriptor:
 * 1. Read all descriptor words
 * 2. Write 0xFFFF flag to claim descriptor
 * 3. Check V (valid) bit - if clear, set XL and stop
 * 4. Handle C (chain) bit - follow chain to next descriptor
 * 5. DMA packet data from buffer address, accumulating in write_buffer
 * 6. On E (end of message):
 *    - Check for loopback mode (IL=0 OR EL=1)
 *    - Check for setup packet (S bit)
 *    - Either loopback/setup locally, or send via pcap
 * 7. Write status words and clear V bit
 *
 * LOOPBACK LOGIC (SimH-compatible):
 * Loopback is enabled when IL=0 (internal loopback) OR EL=1 (external
 * loopback). This is independent of RE (receive enable). Many sources
 * incorrectly describe this as AND logic or requiring RE=1.
 */
bool delqa_c::process_xbdl(void)
{
    // Status for implicit chain (multi-segment packets)
    const uint16_t implicit_chain_status[2] = {static_cast<uint16_t>(XQ_DSC_V | XQ_DSC_C), 1};

    while (true) {
        uint32_t cur_ba = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = xbdl_ba;
        }
        uint16_t words[QE_RING_WORDS] = {0};
        if (!desc_read_words(cur_ba, words, QE_RING_WORDS)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            return false;
        }

        // Claim descriptor with 0xFFFF flag
        uint16_t flag = 0xFFFF;
        if (!desc_write_words(cur_ba, &flag, 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            return false;
        }

        // Check V (valid) bit - if clear, end of list
        if (~words[1] & XQ_DSC_V) {
            if (trace.value) {
                WARNING("DELQA: TX descriptor at %06o not valid (addr_hi=%06o)",
                        cur_ba, words[1]);
            }
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                csr_set_clr(XQ_CSR_XL, 0);  // Mark list invalid
            }
            return false;
        }

        // Calculate buffer address and length
        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);  // One's complement
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        if (words[1] & XQ_DSC_H)  // Odd byte at start
            b_length -= 1;
        if (words[1] & XQ_DSC_L)  // Odd byte at end
            b_length -= 1;

        // Handle C (chain) bit - follow chain pointer
        if (words[1] & XQ_DSC_C) {
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                xbdl_ba = address;
            }
            continue;
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
            return false;
        }
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            write_buffer.len += b_length;
        }

        if (words[1] & XQ_DSC_E) {
            // SimH: loopback if IL=0 (internal) OR EL=1 (external), independent of RE
            bool il_clear = false;
            bool el_set = false;
            size_t len_snapshot = 0;
            uint16_t csr_snapshot = 0;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                il_clear = !(csr & XQ_CSR_IL);
                el_set = (csr & XQ_CSR_EL) != 0;
                len_snapshot = write_buffer.len;
                csr_snapshot = csr;
            }
            bool loopback = il_clear || el_set;
            bool setup_packet = (words[1] & XQ_DSC_S) != 0;

            if (trace.value) {
                WARNING("DELQA: TX EOMSG len=%u setup=%d loopback=%d (IL_clear=%d EL_set=%d) csr=%06o",
                        static_cast<unsigned>(len_snapshot), setup_packet ? 1 : 0, loopback ? 1 : 0,
                        il_clear ? 1 : 0, el_set ? 1 : 0, csr_snapshot);
            }

        if (loopback || setup_packet) {
            if (setup_packet) {
                process_setup();
                enqueue_readq(0, write_buffer.msg.data(), write_buffer.len, 0);
            } else {
                    enqueue_readq(1, write_buffer.msg.data(), write_buffer.len, 0);
                }

                uint16_t write_success[2] = {0, 1};
                if (!desc_write_words(cur_ba + 8, write_success, 2)) {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    nxm_error();
                    return false;
                }

                {
                    uint16_t word1 = 0;
                    if (desc_read_words(cur_ba + 2, &word1, 1)) {
                        word1 = static_cast<uint16_t>(word1 & ~XQ_DSC_V);
                        desc_write_words(cur_ba + 2, &word1, 1);
                    }
                }

                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    write_buffer.len = 0;
                    write_buffer.used = 0;
                    reset_sanity_timer();
                    csr_set_clr(XQ_CSR_XI, 0);
                }

                bool do_process = false;
                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    do_process = !(csr & XQ_CSR_RL);
                }
                if (do_process)
                    process_rbdl();

            } else {
                if (!pcap.send(write_buffer.msg.data(), write_buffer.len))
                    write_callback(1);
                else
                    write_callback(0);
                return true;
            }
        } else {
            if (!desc_write_words(cur_ba + 8, implicit_chain_status, 2)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                return false;
            }

            // Clear V bit to return descriptor
            {
                uint16_t word1 = 0;
                if (desc_read_words(cur_ba + 2, &word1, 1)) {
                    word1 = static_cast<uint16_t>(word1 & ~XQ_DSC_V);
                    desc_write_words(cur_ba + 2, &word1, 1);
                }
            }
        }

        // Advance to next descriptor
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            xbdl_ba = cur_ba + QE_RING_BYTES;
        }
    }
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
 * After processing, update_pcap_filter() is called to apply the new
 * receive filter to the host network interface.
 */
void delqa_c::process_setup(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint8_t *msg = write_buffer.msg.data();
    size_t len = write_buffer.len;

    // Extract MAC addresses from setup packet (unusual byte ordering)
    memset(setup.macs, 0, sizeof(setup.macs));
    for (int i = 0; i < 7; i++)
        for (int j = 0; j < 6; j++) {
            setup.macs[i][j] = msg[(i + 1) + (j * 8)];
            if (len > 112)
                setup.macs[i + 7][j] = msg[(i + 0x41) + (j * 8)];
        }

    // Parse extended setup fields (if present)
    setup.promiscuous = false;
    if (len > 128) {
        uint16_t l = static_cast<uint16_t>(len);
        uint16_t led = static_cast<uint16_t>((l & XQ_SETUP_LD) >> 2);
        uint16_t san = static_cast<uint16_t>((l & XQ_SETUP_ST) >> 4);
        float secs = 0.25f;

        setup.multicast = (0 != (l & XQ_SETUP_MC));
        setup.promiscuous = (0 != (l & XQ_SETUP_PM));

        // LED control (active low)
        if (led) {
            switch (led) {
            case 1: setup.l1 = false; break;
            case 2: setup.l2 = false; break;
            case 3: setup.l3 = false; break;
            }
        }

        // Sanity timer setting (exponential scale)
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
        sanity.max = static_cast<int>(secs * XQ_SERVICE_INTERVAL);
    }

    // Reset sanity timer and enable if SE bit is set
    sanity.timer = sanity.max;
    if (sanity.enabled != 2) {  // Don't override hardware sanity
        if (csr & XQ_CSR_SE)
            sanity.enabled = 1;
        else
            sanity.enabled = 0;
    }

    // Apply new filter settings to pcap
    update_pcap_filter();
    setup.valid = true;

    if (trace.value) {
        WARNING("DELQA: Setup packet processed: len=%zu, promisc=%d multicast=%d",
                len, setup.promiscuous ? 1 : 0, setup.multicast ? 1 : 0);
    }
}

bool delqa_c::ensure_bootrom_image(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (bootrom_ready)
        return true;

    bootrom_image.resize(sizeof(delqa_bootrom));
    memcpy(bootrom_image.data(), delqa_bootrom, sizeof(delqa_bootrom));

    uint16_t *words = reinterpret_cast<uint16_t *>(bootrom_image.data());
    for (size_t i = 0; i < sizeof(delqa_bootrom) / 2; i++) {
        if (words[i] == 011200) {
            words[i] = 005000;
            break;
        }
    }

    uint8_t *bytes = bootrom_image.data();
    int checksum = 0;
    for (size_t i = 0; i < sizeof(delqa_bootrom) - 2; i++)
        checksum += bytes[i];

    words[(sizeof(delqa_bootrom) / 2) - 1] = static_cast<uint16_t>(checksum);

    bootrom_ready = true;
    return true;
}

/*
 * process_bootrom - Deliver bootrom image via RX descriptors
 *
 * This function is called when the driver enables the receiver
 * (RE=1) and the bootrom image has not yet been delivered.
 * The bootrom is delivered in two segments via the RX descriptor ring.
 *
 * Returns: true on success, false on NXM error
 */

bool delqa_c::process_bootrom(void)
{
    if (!ensure_bootrom_image())
        return false;

    uint16_t words[QE_RING_WORDS] = {0};
    uint16_t flag = 0xFFFF;

    for (int part = 0; part < 2; ++part) {
        uint32_t cur_ba = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = rbdl_ba;
        }
        if (trace.value)
            WARNING("DELQA: RX list dispatch pre-write flag at %06o", cur_ba);
        if (!desc_write_words(cur_ba, &flag, 1)) {
            WARNING("DELQA: RX list dispatch flag write failed at %06o", cur_ba);
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            return false;
        }
        if (trace.value)
            WARNING("DELQA: RX list dispatch pre-read desc at %06o", cur_ba);
        for (size_t i = 1; i < QE_RING_WORDS; ++i) {
            if (!desc_read_words(cur_ba + 2 + static_cast<uint32_t>((i - 1) * 2), &words[i], 1)) {
                WARNING("DELQA: RX list dispatch desc read failed at %06o", cur_ba);
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                return false;
            }
        }
        if (trace.value) {
            WARNING("DELQA: RX dispatch read words0=%06o words1=%06o words2=%06o words3=%06o",
                    flag, words[1], words[2], words[3]);
        }

        if (~words[1] & XQ_DSC_V) {
            if (trace.value) {
                WARNING("DELQA: Bootrom RX descriptor at %06o not valid (addr_hi=%06o)",
                        cur_ba, words[1]);
            }
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                csr_set_clr(XQ_CSR_RL, 0);
            }
            return false;
        }

        if (!desc_read_words(cur_ba + 8, &words[4], 2)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            return false;
        }

        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        if (words[1] & XQ_DSC_H)
            b_length -= 1;
        if (words[1] & XQ_DSC_L)
            b_length -= 1;

        if (b_length < (sizeof(delqa_bootrom) / 2)) {
            WARNING("DELQA: Bootrom RX buffer too small at %06o (len=%u)",
                    cur_ba, b_length);
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                csr_set_clr(XQ_CSR_RL, 0);
            }
            return false;
        }

        const uint8_t *src = bootrom_image.data() + part * (sizeof(delqa_bootrom) / 2);
        const size_t bootrom_half = sizeof(delqa_bootrom) / 2;
        const size_t chunk_bytes = 512;
        for (size_t offset = 0; offset < bootrom_half; offset += chunk_bytes) {
            size_t len = bootrom_half - offset;
            if (len > chunk_bytes)
                len = chunk_bytes;
            if (!dma_write_bytes(address + offset, src + offset, len)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                return false;
            }
        }

        // Status word 1 for bootrom: DELQA sets bit 15 on both packets,
        // and additionally bit 14 if not the last segment.
        // First descriptor = 0xC000 (bits 15,14), Second = 0x8000 (bit 15 only)
        if (part == 0)
            words[4] = QE_RST_LASTNOT;  // 0xC000 = not last segment
        else
            words[4] = QE_RST_UNUSED;   // 0x8000 = last segment (bootrom special)
        words[5] = 0;
        if (!desc_write_words(cur_ba + 8, &words[4], 2)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            return false;
        }

        if (trace.value) {
            uint32_t remaining = (sizeof(delqa_bootrom) / 2) * (1 - part);
            WARNING("DELQA: Bootrom desc_addr=%06o status1=%06o status2=%06o remaining=%u",
                    cur_ba, words[4], words[5], remaining);
        }

        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = cur_ba + QE_RING_BYTES;
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(XQ_CSR_RI, 0);
    }
    reset_sanity_timer();
    return true;
}

/* process_local - Handle incoming local packets
 *
 * This function processes packets sent to the DELQA's local
 * protocols: Loopback (0x0090) and Remote Console (0x0260).
 *
 * Returns: true if packet was handled, false otherwise
 */

bool delqa_c::process_local(const uint8_t *data, size_t len)
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

bool delqa_c::process_loopback(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (len < 32)
        return false;

    size_t offset = static_cast<size_t>(data[14] | (data[15] << 8));
    if (offset + 8 > len)
        return false;

    uint16_t function = static_cast<uint16_t>(data[offset] | (data[offset + 1] << 8));
    if (function != 2)
        return false;

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

bool delqa_c::process_remote_console(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (len < 20)
        return false;

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

bool delqa_c::send_system_id(const uint8_t *dest, uint16_t receipt_id)
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
 * worker - Entry point for worker threads
 *
 * The DELQA uses two worker threads to handle RX and TX independently:
 *   Instance 0 (worker_rx): Handles receive operations
 *   Instance 1 (worker_tx): Handles transmit operations
 *
 * This separation allows TX to proceed while RX is blocked and vice versa.
 */
void delqa_c::worker(unsigned instance)
{
    if (trace.value)
        WARNING("DELQA: %s worker(%u) start", DELQA_VERSION, instance);
    if (instance == 0)
        worker_rx();
    else
        worker_tx();
}

/*
 * worker_rx - RX worker thread main loop
 *
 * Responsibilities:
 * 1. Service timers (sanity, system ID)
 * 2. Process pending register writes
 * 3. Handle boot ROM requests
 * 4. Dispatch RX ring when RCLH is written
 * 5. Poll pcap for incoming packets
 * 6. Process MOP protocol packets locally (loopback, remote console)
 * 7. Queue normal packets for delivery to host
 * 8. Deliver queued packets to RX descriptors
 *
 * The loop runs every 10ms when idle, faster when processing packets.
 */
void delqa_c::worker_rx(void)
{
    worker_init_realtime_priority(rt_device);
    bool rx_blocked_logged = false;

    while (!workers_terminate) {
        if (reset_in_progress.load(std::memory_order_acquire)) {
            timeout_c::wait_ms(1);
            continue;
        }
        service_timers();           // Sanity timer, system ID timer
        apply_pending_reg_writes(); // Process deferred register writes

        // Pause during BINIT
        if (qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        // Check for pending operations
        bool do_bootrom = false;
        bool do_rbdl = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (bootrom_pending) {
                bootrom_pending = false;
                do_bootrom = true;
            } else if (rbdl_pending) {
                if (trace.value)
                    WARNING("DELQA: RX list pending set (csr=%06o)", csr);
                rbdl_pending = false;
                do_rbdl = true;
            }
        }

        // Process boot ROM request
        if (do_bootrom) {
            process_bootrom();
            continue;
        }

        // Dispatch RX ring
        if (do_rbdl)
            dispatch_rbdl();

        // Check if receiver is ready (RE=1 and delay expired)
        if (!rx_ready()) {
            bool has_queued = false;
            {
                std::lock_guard<std::mutex> queue_lock(queue_mutex);
                has_queued = !read_queue.empty();
            }
            if (has_queued && !rx_blocked_logged) {
                if (trace.value) {
                    WARNING("DELQA: RX blocked (RE=0) with queued packets");
                }
                rx_blocked_logged = true;
            }
            timeout_c::wait_ms(1);
            continue;
        }
        rx_blocked_logged = false;

#ifdef HAVE_PCAP
        if (pcap.is_open()) {
            // Deliver any queued packets first
            bool do_process = false;
            bool rx_list_ready = false;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                rx_list_ready = !(csr & XQ_CSR_RL);
            }
            {
                std::lock_guard<std::mutex> queue_lock(queue_mutex);
                do_process = !read_queue.empty();
            }
            if (do_process && rx_list_ready)
                process_rbdl();

            // Poll for incoming packets from network
            while (true) {
                size_t len = 0;
                if (!pcap.poll(read_buffer.msg.data(), read_buffer.msg.size(), &len)) {
                    WARNING("DELQA: pcap poll error: %s", pcap.last_error().c_str());
                    break;
                }
                if (len == 0)
                    break;  // No more packets

                stats.recv++;
                stat_rx_frames.value = stats.recv;

                read_buffer.len = len;
                read_buffer.used = 0;

                // Try to handle MOP protocols locally
                bool consumed = process_local(read_buffer.msg.data(), read_buffer.len);
                if (!consumed)
                    enqueue_readq(2, read_buffer.msg.data(), read_buffer.len, 0);
            }

            // Deliver newly queued packets
            {
                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    rx_list_ready = !(csr & XQ_CSR_RL);
                }
                {
                    std::lock_guard<std::mutex> queue_lock(queue_mutex);
                    do_process = !read_queue.empty();
                }
                do_process = do_process && rx_list_ready;
            }
            if (do_process)
                process_rbdl();
        }
#endif

        timeout_c::wait_ms(10);  // Idle poll rate
    }
}

/*
 * worker_tx - TX worker thread main loop
 *
 * Responsibilities:
 * 1. Process pending register writes
 * 2. Dispatch TX ring when XMTH is written
 *
 * TX is simpler than RX - just wait for XMTH write and process descriptors.
 * Runs every 1ms to minimize transmit latency.
 */
void delqa_c::worker_tx(void)
{
    worker_init_realtime_priority(rt_device);

    while (!workers_terminate) {
        if (reset_in_progress.load(std::memory_order_acquire)) {
            timeout_c::wait_ms(1);
            continue;
        }
        apply_pending_reg_writes();

        // Pause during BINIT
        if (qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        // Check for pending TX dispatch
        bool do_xbdl = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (xbdl_pending) {
                xbdl_pending = false;
                do_xbdl = true;
            }
        }
        if (do_xbdl)
            dispatch_xbdl();

        timeout_c::wait_ms(1);  // Fast poll for low TX latency
    }
}
