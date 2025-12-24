/*
 * DEUNA Ethernet Controller Emulation for QUniBone
 * (c) Dave Plummer, davepl@davepl.com, Plummer's Software LLC, 2026
 * Contributed under the GPL2 License
 *
 * This is a clean-room implementation based on:
 *   - DEC DEUNA User's Guide (EK-DEUNA-UG)
 *   - UNIBUS specification
 *   - OpenSIMH pdp11_xu.c behavioral reference (no code copied)
 *
 * Theory of Operation
 * -------------------
 * The DEUNA exposes four UNIBUS registers (PCSR0-3). PCSR0 is the command/status
 * register (port commands, interrupts, W1C bits). PCSR2/3 provide the PCBB
 * pointer, which is a UNIBUS address to the PCB command block. The driver
 * programs PCSR2/3, then issues PCSR0 GETPCBB/GETCMD commands to let the
 * controller fetch the PCB and perform a command (configure, set mode, etc).
 *
 * Once configured, RX and TX use descriptor rings in PDP-11 memory. The device
 * DMA-reads descriptors and buffers, then DMA-writes status and ownership
 * back to the rings. RX frames are sourced from libpcap and queued before
 * being copied into host memory. TX frames are DMA-read and injected via pcap.
 *
 * Two worker threads drive the device: instance 0 handles RX (pcap poll, queue,
 * process_receive), instance 1 handles TX (process_transmit). All UNIBUS
 * register writes are captured in order and replayed by the workers to preserve
 * PCSR2/3 -> PCSR0 command sequencing (critical for GETPCBB).
 *
 * Interrupt behavior mirrors hardware: PCSR0 summary bits and INTE gate the
 * UNIBUS interrupt. The code maintains PCSR0/1 state and updates the visible
 * register latches after each operation.
 *
 * Defaults are set for operator convenience (ifname=eth0, promisc on, etc),
 * but the driver can override MAC and mode via PCB commands. Reset and INIT
 * reset all state, descriptor pointers, and statistics.
 *
 * This file is part of the QUniBone project, licensed under GPLv2.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <algorithm>
#include <vector>
#include <chrono>
#include <condition_variable>

#include "logger.hpp"
#include "utils.hpp"
#include "timeout.hpp"
#include "qunibus.h"
#include "qunibusadapter.hpp"
#include "ddrmem.h"
#include "deuna.hpp"

#if !defined(UNIBUS)
#error "DEUNA is a UNIBUS-only device"
#endif

/*
 * Ethernet framing constants
 */
static const size_t ETH_MIN_PACKET = 60;    // Minimum Ethernet frame (no CRC)
static const size_t ETH_MAX_PACKET = 1514;  // Maximum Ethernet frame (no CRC)
static const size_t ETH_FRAME_SIZE = 1518;  // Frame + CRC space
static const size_t XU_MAX_RCV_PACKET = 1600;

/*
 * Queue and timer constants
 */
static const unsigned XU_QUE_MAX = 500;

/*
 * Default DEUNA hardware address (DEC OUI)
 */
static const uint8_t DEUNA_DEFAULT_MAC[6] = {0x08, 0x00, 0x2b, 0xcc, 0xdd, 0xee};

/*
 * PCSR0 register definitions
 */
static const uint16_t PCSR0_SERI = 0100000;  // Status Error Interrupt
static const uint16_t PCSR0_PCEI = 0040000;  // Port Command Error Interrupt
static const uint16_t PCSR0_RXI  = 0020000;  // Receive Interrupt
static const uint16_t PCSR0_TXI  = 0010000;  // Transmit Interrupt
static const uint16_t PCSR0_DNI  = 0004000;  // Done Interrupt
static const uint16_t PCSR0_RCBI = 0002000;  // Receive Buffer Unavailable
static const uint16_t PCSR0_FATL = 0001000;  // Fatal Internal Error
static const uint16_t PCSR0_USCI = 0000400;  // Unsolicited State Change Interrupt
static const uint16_t PCSR0_INTR = 0000200;  // Interrupt Summary
static const uint16_t PCSR0_INTE = 0000100;  // Interrupt Enable
static const uint16_t PCSR0_RSET = 0000040;  // Reset
static const uint16_t PCSR0_PCMD = 0000017;  // Port Command field
static const uint16_t PCSR0_W1C_MASK = 0177400; // Write-1-to-clear bits

/*
 * PCSR0 Port Commands
 */
static const uint16_t CMD_NOOP     = 000;
static const uint16_t CMD_GETPCBB  = 001;
static const uint16_t CMD_GETCMD   = 002;
static const uint16_t CMD_SELFTEST = 003;
static const uint16_t CMD_START    = 004;
static const uint16_t CMD_BOOT     = 005;
static const uint16_t CMD_PDMD     = 010;
static const uint16_t CMD_HALT     = 016;
static const uint16_t CMD_STOP     = 017;

/*
 * PCSR1 register definitions
 */
static const uint16_t PCSR1_XPWR  = 0100000;  // Transceiver power failure
static const uint16_t PCSR1_ICAB  = 0040000;  // Port/Link cable failure
static const uint16_t PCSR1_ECOD  = 0037400;  // Self-test error code
static const uint16_t PCSR1_PCTO  = 0000200;  // Port Command Timeout
static const uint16_t PCSR1_TYPE  = 0000160;  // Interface type
static const uint16_t PCSR1_STATE = 0000017;  // State

static const uint16_t TYPE_DEUNA = (0 << 4);
static const uint16_t TYPE_DELUA = (1 << 4);

static const uint16_t STATE_RESET   = 000;
static const uint16_t STATE_PLOAD   = 001;
static const uint16_t STATE_READY   = 002;
static const uint16_t STATE_RUNNING = 003;
static const uint16_t STATE_UHALT   = 005;
static const uint16_t STATE_NHALT   = 006;
static const uint16_t STATE_NUHALT  = 007;
static const uint16_t STATE_HALT    = 010;
static const uint16_t STATE_SLOAD   = 017;

/*
 * Status register definitions
 */
static const uint16_t STAT_ERRS = 0100000;
static const uint16_t STAT_MERR = 0040000;
static const uint16_t STAT_BABL = 0020000;
static const uint16_t STAT_CERR = 0010000;
static const uint16_t STAT_TMOT = 0004000;
static const uint16_t STAT_RRNG = 0001000;
static const uint16_t STAT_TRNG = 0000400;
static const uint16_t STAT_PTCH = 0000200;
static const uint16_t STAT_RRAM = 0000100;
static const uint16_t STAT_RREV = 0000077;

/*
 * Mode register definitions
 */
static const uint16_t MODE_PROM = 0100000; // Promiscuous mode
static const uint16_t MODE_ENAL = 0040000; // Enable all multicast
static const uint16_t MODE_DRDC = 0020000; // Disable data chaining
static const uint16_t MODE_TPAD = 0010000; // Transmit pad enable
static const uint16_t MODE_ECT  = 0004000; // Enable collision test
static const uint16_t MODE_DMNT = 0001000; // Disable maintenance message
static const uint16_t MODE_INTL = 0000200; // Internal loopback enable
static const uint16_t MODE_DTCR = 0000010; // Disable transmit CRC
static const uint16_t MODE_LOOP = 0000004; // Internal loopback mode
static const uint16_t MODE_HDPX = 0000001; // Half duplex

/*
 * Function Code definitions
 */
static const uint16_t FC_NOOP     = 0000000;
static const uint16_t FC_LSM      = 0000001;
static const uint16_t FC_RDPA     = 0000002;
static const uint16_t FC_RPA      = 0000004;
static const uint16_t FC_WPA      = 0000005;
static const uint16_t FC_RMAL     = 0000006;
static const uint16_t FC_WMAL     = 0000007;
static const uint16_t FC_RRF      = 0000010;
static const uint16_t FC_WRF      = 0000011;
static const uint16_t FC_RDCTR    = 0000012;
static const uint16_t FC_RDCLCTR  = 0000013;
static const uint16_t FC_RMODE    = 0000014;
static const uint16_t FC_WMODE    = 0000015;
static const uint16_t FC_RSTAT    = 0000016;
static const uint16_t FC_RCSTAT   = 0000017;
static const uint16_t FC_DIM      = 0000020;
static const uint16_t FC_LIM      = 0000021;
static const uint16_t FC_RSID     = 0000022;
static const uint16_t FC_WSID     = 0000023;
static const uint16_t FC_RLSA     = 0000024;
static const uint16_t FC_WLSA     = 0000025;

/*
 * Transmitter Ring definitions
 */
static const uint16_t TXR_OWN  = 0100000;
static const uint16_t TXR_ERRS = 0040000;
static const uint16_t TXR_MTCH = 0020000;
static const uint16_t TXR_MORE = 0010000;
static const uint16_t TXR_ONE  = 0004000;
static const uint16_t TXR_DEF  = 0002000;
static const uint16_t TXR_STF  = 0001000;
static const uint16_t TXR_ENF  = 0000400;

static const uint16_t TXR_BUFL = 0100000;
static const uint16_t TXR_UBTO = 0040000;
static const uint16_t TXR_UFLO = 0020000;
static const uint16_t TXR_LCOL = 0010000;
static const uint16_t TXR_LCAR = 0004000;
static const uint16_t TXR_RTRY = 0002000;
static const uint16_t TXR_TDR  = 0001777;

/*
 * Receiver Ring definitions
 */
static const uint16_t RXR_OWN  = 0100000;
static const uint16_t RXR_ERRS = 0040000;
static const uint16_t RXR_FRAM = 0020000;
static const uint16_t RXR_OFLO = 0010000;
static const uint16_t RXR_CRC  = 0004000;
static const uint16_t RXR_STF  = 0001000;
static const uint16_t RXR_ENF  = 0000400;

static const uint16_t RXR_BUFL = 0100000;
static const uint16_t RXR_UBTO = 0040000;
static const uint16_t RXR_NCHN = 0020000;
static const uint16_t RXR_OVRN = 0010000;
static const uint16_t RXR_MLEN = 0007777;

/*
 * Version string
 */
static const char *DEUNA_VERSION = "v001";

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
 * DEUNA Constructor
 */
/*
 * deuna_c::deuna_c
 * Purpose: construct the DEUNA device with sane defaults and register layout.
 * Behavior: initializes registers, defaults, MAC, and buffers for emulation.
 * Notes: sets host-interface defaults (e.g., ifname) and DEC-range MAC.
 */
deuna_c::deuna_c() : qunibusdevice_c()
{
    set_workers_count(2);  // Instance 0 = RX, Instance 1 = TX

    name.value = "deuna";
    type_name.value = "DEUNA";
    log_label = "deuna";

    set_default_bus_params(DEUNA_DEFAULT_ADDR, DEUNA_DEFAULT_SLOT, DEUNA_DEFAULT_VECTOR, DEUNA_DEFAULT_LEVEL);
    dma_request.set_priority_slot(priority_slot.value);
    dma_desc_request.set_priority_slot(priority_slot.value);
    intr_request.set_priority_slot(priority_slot.value);
    intr_request.set_level(intr_level.value);
    intr_request.set_vector(intr_vector.value);

    /*
     * Register layout (4 registers, 8 bytes total at base address):
     *   +0: PCSR0
     *   +2: PCSR1
     *   +4: PCSR2
     *   +6: PCSR3
     */
    register_count = 4;

    reg_pcsr0 = &(this->registers[0]);
    strcpy(reg_pcsr0->name, "PCSR0");
    reg_pcsr0->active_on_dati = false;
    reg_pcsr0->active_on_dato = true;
    reg_pcsr0->reset_value = 0;
    reg_pcsr0->writable_bits = 0xffff;

    reg_pcsr1 = &(this->registers[1]);
    strcpy(reg_pcsr1->name, "PCSR1");
    reg_pcsr1->active_on_dati = false;
    reg_pcsr1->active_on_dato = false;
    reg_pcsr1->reset_value = 0;
    reg_pcsr1->writable_bits = 0x0000;  // Read-only

    reg_pcsr2 = &(this->registers[2]);
    strcpy(reg_pcsr2->name, "PCSR2");
    reg_pcsr2->active_on_dati = false;
    reg_pcsr2->active_on_dato = true;
    reg_pcsr2->reset_value = 0;
    reg_pcsr2->writable_bits = 0xffff;

    reg_pcsr3 = &(this->registers[3]);
    strcpy(reg_pcsr3->name, "PCSR3");
    reg_pcsr3->active_on_dati = false;
    reg_pcsr3->active_on_dato = true;
    reg_pcsr3->reset_value = 0;
    reg_pcsr3->writable_bits = 0x0003;

    ifname.value = "eth0";
    mac.value = "";
    promisc.value = true;
    rx_slots.value = 0;
    tx_slots.value = 0;
    trace.value = false;

    /* Default MAC in DEC range */
    memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));

    read_buffer.msg.reserve(XU_MAX_RCV_PACKET);
    write_buffer.msg.reserve(XU_MAX_RCV_PACKET);
}

/*
 * deuna_c::~deuna_c
 * Purpose: clean shutdown of DEUNA resources.
 * Behavior: closes pcap handle if compiled in.
 * Notes: workers are managed by the base framework; this just releases pcap.
 */
deuna_c::~deuna_c()
{
#ifdef HAVE_PCAP
    pcap.close();
#endif
}

/*
 * deuna_c::parse_mac
 * Purpose: accept operator-provided MAC strings for overrides.
 * Behavior: parses aa:bb:cc:dd:ee:ff into six bytes; returns false on error.
 * Notes: empty string is treated as "no override" and returns false.
 */
bool deuna_c::parse_mac(const std::string &text, uint8_t out[6])
{
    if (text.empty())
        return false;

    unsigned b[6] = {0};
    if (sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;

    for (int i = 0; i < 6; ++i) {
        if (b[i] > 0xff)
            return false;
        out[i] = static_cast<uint8_t>(b[i]);
    }
    return true;
}

/*
 * deuna_c::on_param_changed
 * Purpose: react to menu/runtime parameter changes.
 * Behavior: updates DMA/interrupt routing, MAC override, and pcap filtering.
 * Notes: ifname is locked while installed; MAC parsing is strict.
 */
bool deuna_c::on_param_changed(parameter_c *param)
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
            WARNING("DEUNA: ifname cannot be changed while device is installed");
            return false;
        }
    } else if (param == &mac) {
        if (mac.new_value.empty()) {
            mac_override = false;
            memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));
            memcpy(setup.macs[0], mac_addr, sizeof(mac_addr));
            setup.valid = true;
            if (setup.mac_count < 2)
                setup.mac_count = 2;
            update_pcap_filter();
        } else {
            uint8_t parsed[6] = {0};
            if (!parse_mac(mac.new_value, parsed)) {
                ERROR("DEUNA: invalid MAC format '%s'", mac.new_value.c_str());
                return false;
            }
            mac_override = true;
            memcpy(mac_addr, parsed, sizeof(mac_addr));
            memcpy(setup.macs[0], parsed, sizeof(mac_addr));
            setup.valid = true;
            update_pcap_filter();
        }
    } else if (param == &promisc) {
        update_pcap_filter();
    }

    return qunibusdevice_c::on_param_changed(param);
}

/*
 * deuna_c::on_before_install
 * Purpose: validate config and open host networking before device is active.
 * Behavior: ensures pcap support, ifname set, and opens pcap handle.
 * Notes: failure here prevents device installation and avoids a stuck PDP-11.
 */
bool deuna_c::on_before_install(void)
{
#ifndef HAVE_PCAP
    ERROR("DEUNA: libpcap support not compiled in - install libpcap-dev and rebuild with HAVE_PCAP");
    return false;
#else

    if (ifname.value.empty()) {
        ERROR("DEUNA: ifname must be set");
        return false;
    }

    if (!pcap.open(ifname.value, promisc.value, 2048, 1)) {
        ERROR("DEUNA: failed to open pcap on %s: %s", ifname.value.c_str(),
              pcap.last_error().c_str());
        return false;
    }

    INFO("DEUNA: PCAP opened successfully on interface %s", ifname.value.c_str());

    ifname.readonly = true;
    mac.readonly = true;
    promisc.readonly = true;
    rx_slots.readonly = true;
    tx_slots.readonly = true;

    update_transceiver_bits();
    update_pcap_filter();
    update_intr();

    return true;
#endif
}

/*
 * deuna_c::on_after_install
 * Purpose: finalize device state once installed in the UNIBUS.
 * Behavior: marks parameters read-only and updates link status bits.
 * Notes: called after register space is live; avoid heavy operations here.
 */
void deuna_c::on_after_install(void)
{
    reset_controller();
}

/*
 * deuna_c::on_after_uninstall
 * Purpose: unwind installation state.
 * Behavior: clears readonly flags and refreshes status bits.
 * Notes: pcap close is handled in destructor or when disabling.
 */
void deuna_c::on_after_uninstall(void)
{
#ifdef HAVE_PCAP
    pcap.close();
#endif

    ifname.readonly = false;
    mac.readonly = false;
    promisc.readonly = false;
    rx_slots.readonly = false;
    tx_slots.readonly = false;

    update_transceiver_bits();
    update_intr();
}

/*
 * deuna_c::on_power_changed
 * Purpose: respond to UNIBUS power transitions.
 * Behavior: resets controller on DCLO assert edge.
 * Notes: matches DEC power/reset semantics for device state.
 */
void deuna_c::on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge)
{
    UNUSED(aclo_edge);
    if (dclo_edge == SIGNAL_EDGE_RAISING)
        reset_controller();
}

/*
 * deuna_c::on_init_changed
 * Purpose: respond to INIT line assertion.
 * Behavior: resets the controller when INIT is asserted.
 * Notes: keeps device state consistent with PDP-11 initialization.
 */
void deuna_c::on_init_changed(void)
{
    if (init_asserted)
        reset_controller();
}

/*
 * deuna_c::update_pcsr_regs
 * Purpose: sync internal PCS register state to UNIBUS-visible latches.
 * Behavior: copies pcsr0-3 into active DATI/DATO flipflops.
 * Notes: call after any pcsr change to keep the CPU’s view coherent.
 */
void deuna_c::update_pcsr_regs(void)
{
    if (reg_pcsr0) {
        reg_pcsr0->active_dati_flipflops = pcsr0;
        reg_pcsr0->active_dato_flipflops = pcsr0;
    }
    if (reg_pcsr1) {
        reg_pcsr1->active_dati_flipflops = pcsr1;
        reg_pcsr1->active_dato_flipflops = pcsr1;
    }
    if (reg_pcsr2) {
        reg_pcsr2->active_dati_flipflops = pcsr2;
        reg_pcsr2->active_dato_flipflops = pcsr2;
    }
    if (reg_pcsr3) {
        reg_pcsr3->active_dati_flipflops = pcsr3;
        reg_pcsr3->active_dato_flipflops = pcsr3;
    }

    // Also update the PRU-visible register values (only if installed, i.e., pru_iopage_register is set)
    if (reg_pcsr0 && reg_pcsr0->pru_iopage_register)
        reg_pcsr0->pru_iopage_register->value = pcsr0;
    if (reg_pcsr1 && reg_pcsr1->pru_iopage_register)
        reg_pcsr1->pru_iopage_register->value = pcsr1;
    if (reg_pcsr2 && reg_pcsr2->pru_iopage_register)
        reg_pcsr2->pru_iopage_register->value = pcsr2;
    if (reg_pcsr3 && reg_pcsr3->pru_iopage_register)
        reg_pcsr3->pru_iopage_register->value = pcsr3;
}

/*
 * deuna_c::update_transceiver_bits
 * Purpose: reflect link/transceiver status in PCSR1.
 * Behavior: updates XPWR/ICAB bits based on pcap status and overrides.
 * Notes: called on install/uninstall and during reset.
 */
void deuna_c::update_transceiver_bits(void)
{
    if (pcap.is_open())
        pcsr1 &= ~PCSR1_XPWR;
    else
        pcsr1 |= PCSR1_XPWR;
}

/*
 * deuna_c::update_intr
 * Purpose: raise/cancel UNIBUS interrupt based on pcsr0 status.
 * Behavior: sets INTR summary and signals/cancels interrupt requests.
 * Notes: requires pcsr0 W1C and INTE semantics to be respected.
 */
void deuna_c::update_intr(void)
{
    const bool any = (pcsr0 & PCSR0_W1C_MASK) != 0;
    if (any)
        pcsr0 |= PCSR0_INTR;
    else
        pcsr0 &= ~PCSR0_INTR;

    // Make CSR view consistent before toggling interrupt line
    update_pcsr_regs();

    if (!qunibusadapter)
        return;

    const bool inte = (pcsr0 & PCSR0_INTE) != 0;
    if (!inte) {
        if (trace.value && any)
            WARNING("DEUNA: INTR suppressed (INTE=0) pcsr0=%06o", pcsr0);
        if (irq) {
            qunibusadapter->cancel_INTR(intr_request);
            irq = false;
            if (trace.value)
                WARNING("DEUNA: INTR deassert pcsr0=%06o", pcsr0);
        }
        return;
    }

    // Force a deassert/assert cycle to re-arm level-sensitive interrupt delivery
    if (irq) {
        qunibusadapter->cancel_INTR(intr_request);
        irq = false;
    }

    if (any) {
        qunibusadapter->INTR(intr_request, reg_pcsr0, pcsr0);
        irq = true;
        if (trace.value)
            WARNING("DEUNA: INTR assert pcsr0=%06o vec=%03o level=%d", pcsr0, intr_vector.value, intr_level.value);
    }
}

/*
 * deuna_c::reset_controller
 * Purpose: central reset path for DEUNA state.
 * Behavior: reinitializes pcsr state, descriptor pointers, filters, and stats.
 * Notes: called on INIT, power transitions, and software reset.
 */
void deuna_c::reset_controller(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (trace.value)
        WARNING("DEUNA: reset_controller called");

    pcsr0 = PCSR0_DNI;  // Done on reset
    pcsr1 = TYPE_DEUNA | STATE_READY;
    update_transceiver_bits();

    pcsr2 = 0;
    pcsr3 = 0;
    mode = 0;
    stat = 0;

    pcbb = 0;
    tdrb = 0;
    telen = 0;
    trlen = 0;
    txnext = 0;
    rdrb = 0;
    relen = 0;
    rrlen = 0;
    rxnext = 0;

    read_queue.clear();
    read_queue_loss = 0;

    setup = setup_state();
    if (!mac_override && mac_is_zero(mac_addr))
        memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));
    memcpy(setup.macs[0], mac_addr, sizeof(mac_addr));
    for (int i = 0; i < 6; ++i)
        setup.macs[1][i] = 0xff;
    setup.mac_count = 2;
    setup.valid = true;

    stats = stats_state();
    stats.last_update_ns = timeout_c::abstime_ns();

    memset(load_server, 0, sizeof(load_server));

    update_pcap_filter();
    update_intr();
}

/*
 * deuna_c::on_after_register_access
 * Purpose: capture UNIBUS register writes from the PDP-11.
 * Behavior: queues writes for worker thread processing to avoid DMA deadlock.
 * Notes: must be fast to not block the UNIBUS callback path.
 */
void deuna_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    if (!device_reg)
        return;

    uint8_t reg_index = device_reg->index;
    if (reg_index >= 4)
        return;

    uint16_t val = device_reg->active_dato_flipflops;
    uint16_t w1c_snapshot = 0;

    if (reg_index == DEUNA_REG_PCSR0) {
        uint16_t w1c_mask = 0;
        if (access == DATO_WORD || access == DATO_BYTEH)
            w1c_mask = static_cast<uint16_t>(val & PCSR0_W1C_MASK);
        if (w1c_mask) {
            uint16_t before = __atomic_fetch_and(&pcsr0,
                static_cast<uint16_t>(~w1c_mask), __ATOMIC_RELAXED);
            uint16_t cleared = static_cast<uint16_t>(before & w1c_mask);
            if (trace.value && cleared)
                WARNING("DEUNA: W1C immediate clear bits=%06o (was pcsr0=%06o)", cleared, before);
            update_intr();
        }
    }

    if (trace.value) {
        const char *rname = "?";
        if (reg_index == DEUNA_REG_PCSR0) rname = "PCSR0";
        else if (reg_index == DEUNA_REG_PCSR1) rname = "PCSR1";
        else if (reg_index == DEUNA_REG_PCSR2) rname = "PCSR2";
        else if (reg_index == DEUNA_REG_PCSR3) rname = "PCSR3";
        WARNING("DEUNA: on_after_register_access %s = %06o (access=%d)", rname, val, access);
    }

    // Queue the register write for worker thread processing.
    // We cannot process synchronously because commands may need DMA,
    // and DMA requires the UNIBUS which we're currently blocking.
    {
        std::lock_guard<std::mutex> lock(pending_reg_mutex);
        pending_reg_write write;
        write.reg_index = reg_index;
        write.value = val;
        write.access = static_cast<uint8_t>(access);
        write.w1c_snapshot = w1c_snapshot;
        pending_reg_queue.push_back(write);
    }
    
    // Signal the worker thread to wake up immediately
    pending_cmd_cv.notify_one();
}

/*
 * deuna_c::handle_register_write
 * Purpose: implement PCSR0-3 semantics for writes.
 * Behavior: updates pcsr fields, latches commands, and triggers actions.
 * Notes: pcbb/cmd sequencing depends on write order; keep W1C rules intact.
 */
void deuna_c::handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access,
        uint16_t w1c_snapshot)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (trace.value) {
        const char *rname = "?";
        if (reg_index == DEUNA_REG_PCSR0) rname = "PCSR0";
        else if (reg_index == DEUNA_REG_PCSR1) rname = "PCSR1";
        else if (reg_index == DEUNA_REG_PCSR2) rname = "PCSR2";
        else if (reg_index == DEUNA_REG_PCSR3) rname = "PCSR3";
        WARNING("DEUNA: Write %s (reg %d) = %06o", rname, reg_index, val);
    }

    switch (reg_index) {
    case DEUNA_REG_PCSR0: {
        if (access == DATO_BYTEH) {
            uint16_t cleared = w1c_snapshot;
            if (trace.value && cleared)
                WARNING("DEUNA: W1C BYTEH clear bits=%06o (was pcsr0=%06o)", cleared, pcsr0);
            pcsr0 &= static_cast<uint16_t>(~w1c_snapshot);
            update_intr();
            return;
        }

        uint16_t data = val;
        if (access == DATO_BYTEL)
            data = static_cast<uint16_t>((pcsr0 & 0xff00) | (val & 0x00ff));

        if (access == DATO_WORD) {
            uint16_t cleared = w1c_snapshot;
            if (trace.value && cleared)
                WARNING("DEUNA: W1C WORD clear bits=%06o (was pcsr0=%06o)", cleared, pcsr0);
            pcsr0 &= static_cast<uint16_t>(~w1c_snapshot);
        }

        if (data & PCSR0_RSET) {
            reset_controller();
            return;
        }

        // Handle INTE interlock: if INTE toggles, no port command is executed.
        if ((pcsr0 ^ data) & PCSR0_INTE) {
            pcsr0 ^= PCSR0_INTE;
            pcsr0 |= PCSR0_DNI;
        } else {
            pcsr0 &= ~PCSR0_PCMD;
            pcsr0 |= (data & PCSR0_PCMD);
            uint16_t cmd = pcsr0 & PCSR0_PCMD;
            if (cmd != CMD_NOOP) {
                if (trace.value)
                    WARNING("DEUNA: PCSR0 write cmd=%03o, pcsr0=%06o", cmd, pcsr0);
                
                // Commands that require DMA must be queued for worker thread.
                // Commands that don't need DMA can be processed immediately.
                bool needs_dma = (cmd == CMD_GETCMD || cmd == CMD_PDMD);
                if (needs_dma) {
                    // Queue for worker thread - it will call port_command
                    std::lock_guard<std::mutex> cmdlock(pending_cmd_mutex);
                    pending_cmd = cmd;
                    if (trace.value)
                        WARNING("DEUNA: Queued command %03o for worker", cmd);
                } else {
                    // Safe to execute immediately (no DMA needed)
                    port_command(cmd);
                    if (trace.value)
                        WARNING("DEUNA: PCSR0 after command, pcsr0=%06o", pcsr0);
                }
            } else if (trace.value) {
                WARNING("DEUNA: PCSR0 write with NOOP, pcsr0=%06o", pcsr0);
            }
        }

        update_intr();
        break;
    }
    case DEUNA_REG_PCSR1:
        // read-only
        break;
    case DEUNA_REG_PCSR2:
        pcsr2 = val & 0177776;  // MBZ LSB
        update_pcsr_regs();
        break;
    case DEUNA_REG_PCSR3:
        pcsr3 = val & 0000003;
        update_pcsr_regs();
        break;
    default:
        break;
    }
}

/*
 * deuna_c::apply_pending_reg_writes
 * Purpose: drain queued register writes in original UNIBUS order.
 * Behavior: dequeues and dispatches to handle_register_write.
 * Notes: ordering matters for GETPCBB; this runs in worker threads.
 */
void deuna_c::apply_pending_reg_writes(void)
{
    std::deque<pending_reg_write> writes;
    {
        std::lock_guard<std::mutex> lock(pending_reg_mutex);
        if (pending_reg_queue.empty())
            return;
        writes.swap(pending_reg_queue);
    }

    for (const auto &write : writes) {
        handle_register_write(write.reg_index, write.value,
            static_cast<DATO_ACCESS>(write.access), write.w1c_snapshot);
    }
}

/*
 * deuna_c::process_pending_command
 * Purpose: execute queued port command that requires DMA.
 * Behavior: called by worker thread to safely execute GETCMD/PDMD.
 * Notes: DMA is only safe from worker context, not from UNIBUS callback.
 */
void deuna_c::process_pending_command(void)
{
    uint16_t cmd = 0;
    {
        std::lock_guard<std::mutex> lock(pending_cmd_mutex);
        cmd = pending_cmd;
        pending_cmd = 0;
    }

    if (cmd != 0) {
        if (trace.value)
            WARNING("DEUNA: Worker processing queued command %03o", cmd);
        
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        port_command(cmd);
        
        if (trace.value)
            WARNING("DEUNA: Worker command done, pcsr0=%06o", pcsr0);
    }
}

/*
 * deuna_c::dma_read_words
 * Purpose: DMA read helper for device descriptors and buffers.
 * Behavior: reads from UNIBUS or DDR-backed memory into a word buffer.
 * Notes: returns false on NXM; callers must handle failures.
 */
bool deuna_c::dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr >= ddrmem->qunibus_startaddr &&
        (addr + wordcount * 2 - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->exam(addr + static_cast<uint32_t>(i * 2), &buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
    return dma_request.success;
}

/*
 * deuna_c::dma_write_words
 * Purpose: DMA write helper for descriptors and status back to PDP-11 memory.
 * Behavior: writes word buffers into UNIBUS or DDR-backed memory.
 * Notes: returns false on NXM; callers should set PCEI/ERR as needed.
 */
bool deuna_c::dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr >= ddrmem->qunibus_startaddr &&
        (addr + wordcount * 2 - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATO, addr,
                        const_cast<uint16_t*>(buffer), wordcount);
    return dma_request.success;
}

/*
 * deuna_c::desc_read_words
 * Purpose: descriptor read wrapper with NXM handling.
 * Behavior: performs DMA reads and updates error status on failure.
 * Notes: used by RX/TX descriptor processing; keep error semantics consistent.
 */
bool deuna_c::desc_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr >= ddrmem->qunibus_startaddr &&
        (addr + wordcount * 2 - 2) <= ddrmem->qunibus_endaddr) {
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

/*
 * deuna_c::desc_write_words
 * Purpose: descriptor write wrapper with NXM handling.
 * Behavior: performs DMA writes and updates error status on failure.
 * Notes: used when returning ownership or status to the PDP-11.
 */
bool deuna_c::desc_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    if (ddrmem && ddrmem->enabled &&
        addr >= ddrmem->qunibus_startaddr &&
        (addr + wordcount * 2 - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                return false;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_desc_request, true, QUNIBUS_CYCLE_DATO, addr,
                        const_cast<uint16_t*>(buffer), wordcount);
    return dma_desc_request.success;
}

/*
 * deuna_c::dma_read_bytes
 * Purpose: byte-granular DMA reader for Ethernet frames.
 * Behavior: reads bytes from PDP-11 memory using aligned word reads.
 * Notes: handles odd-byte alignment; expects len <= frame size.
 */
bool deuna_c::dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;

    if (addr + len > qunibus->addr_space_byte_count)
        return false;

    if ((addr & 1) == 0 && (len & 1) == 0) {
        std::vector<uint16_t> tmp(len / 2, 0);
        if (!dma_read_words(addr, tmp.data(), tmp.size()))
            return false;
        for (size_t i = 0; i < len; ++i) {
            size_t word_index = i / 2;
            bool high = (i & 1) != 0;
            uint16_t w = tmp[word_index];
            buffer[i] = high ? static_cast<uint8_t>((w >> 8) & 0xff)
                             : static_cast<uint8_t>(w & 0xff);
        }
        return true;
    }

    std::vector<uint16_t> tmp((len + 1) / 2, 0);
    if (!dma_read_words(addr & ~1u, tmp.data(), tmp.size()))
        return false;

    size_t offset = addr & 1u;
    for (size_t i = 0; i < len; ++i) {
        size_t word_index = (i + offset) / 2;
        bool high = ((i + offset) & 1) != 0;
        uint16_t w = tmp[word_index];
        buffer[i] = high ? static_cast<uint8_t>((w >> 8) & 0xff) : static_cast<uint8_t>(w & 0xff);
    }
    return true;
}

/*
 * deuna_c::dma_write_bytes
 * Purpose: byte-granular DMA writer for Ethernet frames.
 * Behavior: writes bytes into PDP-11 memory using aligned word writes.
 * Notes: handles odd alignment; callers should verify buffer lengths.
 */
bool deuna_c::dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;

    if (addr + len > qunibus->addr_space_byte_count)
        return false;

    if ((addr & 1) == 0 && (len & 1) == 0) {
        std::vector<uint16_t> tmp(len / 2, 0);
        for (size_t i = 0; i < len; ++i) {
            size_t word_index = i / 2;
            bool high = (i & 1) != 0;
            uint16_t w = tmp[word_index];
            if (high)
                w = static_cast<uint16_t>((w & 0x00ff) | (static_cast<uint16_t>(buffer[i]) << 8));
            else
                w = static_cast<uint16_t>((w & 0xff00) | buffer[i]);
            tmp[word_index] = w;
        }
        return dma_write_words(addr, tmp.data(), tmp.size());
    }

    uint32_t aligned = addr & ~1u;
    size_t wordcount = (len + (addr & 1u) + 1) / 2;
    std::vector<uint16_t> tmp(wordcount, 0);

    if (!dma_read_words(aligned, tmp.data(), wordcount))
        return false;

    for (size_t i = 0; i < len; ++i) {
        size_t word_index = (i + (addr & 1u)) / 2;
        bool high = ((i + (addr & 1u)) & 1) != 0;
        uint16_t w = tmp[word_index];
        if (high)
            w = static_cast<uint16_t>((w & 0x00ff) | (static_cast<uint16_t>(buffer[i]) << 8));
        else
            w = static_cast<uint16_t>((w & 0xff00) | buffer[i]);
        tmp[word_index] = w;
    }

    return dma_write_words(aligned, tmp.data(), wordcount);
}

/*
 * deuna_c::cpu_read_words
 * Purpose: CPU-visible read helper for debugging memory mapping issues.
 * Behavior: performs CPU DATI cycles to read words from UNIBUS space.
 * Notes: serialized with DMA to avoid interleaving with device DMA ops.
 */
bool deuna_c::cpu_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    for (size_t i = 0; i < wordcount; ++i) {
        uint16_t word = 0;
        qunibusadapter->cpu_DATA_transfer(*qunibus->dma_request, QUNIBUS_CYCLE_DATI,
                                          addr + static_cast<uint32_t>(i * 2), &word);
        if (!qunibus->dma_request->success)
            return false;
        buffer[i] = word;
    }
    return true;
}

/*
 * deuna_c::cpu_read_bytes
 * Purpose: CPU-visible byte reader layered over cpu_read_words.
 * Behavior: reads aligned words and extracts bytes.
 * Notes: used for diagnostics to compare CPU view with DMA view.
 */
bool deuna_c::cpu_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;

    if (addr + len > qunibus->addr_space_byte_count)
        return false;

    uint32_t aligned = addr & ~1u;
    size_t wordcount = (len + (addr & 1u) + 1) / 2;
    std::vector<uint16_t> tmp(wordcount, 0);
    if (!cpu_read_words(aligned, tmp.data(), wordcount))
        return false;

    size_t offset = addr & 1u;
    for (size_t i = 0; i < len; ++i) {
        size_t word_index = (i + offset) / 2;
        bool high = ((i + offset) & 1) != 0;
        uint16_t w = tmp[word_index];
        buffer[i] = high ? static_cast<uint8_t>((w >> 8) & 0xff)
                         : static_cast<uint8_t>(w & 0xff);
    }
    return true;
}

/*
 * deuna_c::log_pcbb_snapshot
 * Purpose: dump DMA vs CPU-visible snapshots of PCBB and MAC bytes.
 * Behavior: reads PCBB words and the 6-byte MAC via both DMA and CPU paths.
 * Notes: intended for diagnosing mapping mismatches during GETCMD.
 */
void deuna_c::log_pcbb_snapshot(const char *tag, uint32_t addr)
{
    uint16_t dma_words[4] = {0};
    uint16_t cpu_words[4] = {0};
    uint8_t dma_mac[6] = {0};
    uint8_t cpu_mac[6] = {0};

    bool ok_dma = dma_read_words(addr, dma_words, 4);
    bool ok_cpu = cpu_read_words(addr, cpu_words, 4);
    bool ok_dma_mac = dma_read_bytes(addr + 2, dma_mac, 6);
    bool ok_cpu_mac = cpu_read_bytes(addr + 2, cpu_mac, 6);

    WARNING("DEUNA: %s PCBB@%08o dma=%s %06o %06o %06o %06o cpu=%s %06o %06o %06o %06o",
            tag, addr,
            ok_dma ? "ok" : "fail",
            dma_words[0], dma_words[1], dma_words[2], dma_words[3],
            ok_cpu ? "ok" : "fail",
            cpu_words[0], cpu_words[1], cpu_words[2], cpu_words[3]);

    WARNING("DEUNA: %s MAC@%08o dma=%s %02x:%02x:%02x:%02x:%02x:%02x cpu=%s %02x:%02x:%02x:%02x:%02x:%02x",
            tag, addr + 2,
            ok_dma_mac ? "ok" : "fail",
            dma_mac[0], dma_mac[1], dma_mac[2], dma_mac[3], dma_mac[4], dma_mac[5],
            ok_cpu_mac ? "ok" : "fail",
            cpu_mac[0], cpu_mac[1], cpu_mac[2], cpu_mac[3], cpu_mac[4], cpu_mac[5]);

    if (ok_dma && ok_cpu &&
        (dma_words[0] != cpu_words[0] || dma_words[1] != cpu_words[1] ||
         dma_words[2] != cpu_words[2] || dma_words[3] != cpu_words[3])) {
        WARNING("DEUNA: %s PCBB mismatch (DMA vs CPU)", tag);
    }
    if (ok_dma_mac && ok_cpu_mac &&
        memcmp(dma_mac, cpu_mac, sizeof(dma_mac)) != 0) {
        WARNING("DEUNA: %s MAC mismatch (DMA vs CPU)", tag);
    }
}

/*
 * deuna_c::make_addr
 * Purpose: build a PDP-11 physical address from high/low words.
 * Behavior: masks upper bits based on bus width (16/18-bit).
 * Notes: DEUNA uses 18-bit addressing by default.
 */
uint32_t deuna_c::make_addr(uint16_t hi, uint16_t lo) const
{
    uint16_t mask = 0x0003;  // DEUNA uses 18-bit addressing (2 high bits)
    if (qunibus) {
        if (qunibus->addr_width <= 16)
            mask = 0x0000;
        else if (qunibus->addr_width <= 18)
            mask = 0x0003;
    }
    return (static_cast<uint32_t>(hi & mask) << 16) | lo;
}

/*
 * deuna_c::port_command
 * Purpose: execute PCSR0 port commands from the driver.
 * Behavior: handles GETPCBB/GETCMD/START/STOP/etc and updates state.
 * Notes: sets PCSR0.DNI/PCEI and drives state transitions.
 */
void deuna_c::port_command(uint16_t cmd)
{
    uint16_t state = pcsr1 & PCSR1_STATE;

    if (trace.value) {
        const char *cmdname = "?";
        switch (cmd) {
        case CMD_NOOP: cmdname = "NOOP"; break;
        case CMD_GETPCBB: cmdname = "GETPCBB"; break;
        case CMD_GETCMD: cmdname = "GETCMD"; break;
        case CMD_SELFTEST: cmdname = "SELFTEST"; break;
        case CMD_START: cmdname = "START"; break;
        case CMD_BOOT: cmdname = "BOOT"; break;
        case CMD_PDMD: cmdname = "PDMD"; break;
        case CMD_HALT: cmdname = "HALT"; break;
        case CMD_STOP: cmdname = "STOP"; break;
        }
        WARNING("DEUNA: port_command(%s/%03o) state=%03o pcsr0=%06o", cmdname, cmd, state, pcsr0);
    }

    switch (cmd) {
    case CMD_PDMD:
        if (trace.value) {
            WARNING("DEUNA: PDMD tdrb=%08o telen=%u trlen=%u txnext=%u",
                    tdrb, telen, trlen, txnext);
        }
        process_transmit();
        pcsr0 |= PCSR0_DNI;
        break;
    case CMD_GETCMD:
        if (!execute_command())
            pcsr0 |= PCSR0_PCEI;
        pcsr0 |= PCSR0_DNI;
        break;
    case CMD_GETPCBB:
        pcbb = (static_cast<uint32_t>(pcsr3) << 16) | pcsr2;
        pcsr0 |= PCSR0_DNI;
        if (trace.value)
            WARNING("DEUNA: GETPCBB pcbb=%08o (pcsr2=%06o pcsr3=%06o) pcsr0=%06o", pcbb, pcsr2, pcsr3, pcsr0);
        break;
    case CMD_SELFTEST:
        pcsr0 |= PCSR0_DNI;
        pcsr0 &= ~PCSR0_USCI;
        pcsr0 &= ~PCSR0_FATL;
        pcsr1 &= ~PCSR1_STATE;
        pcsr1 |= STATE_READY;
        break;
    case CMD_START:
        if (state == STATE_READY) {
            pcsr1 &= ~PCSR1_STATE;
            pcsr1 |= STATE_RUNNING;
            pcsr0 |= PCSR0_DNI;
            rxnext = 0;
            txnext = 0;
        } else {
            pcsr0 |= PCSR0_PCEI;
        }
        break;
    case CMD_HALT:
        if (state == STATE_READY || state == STATE_RUNNING) {
            pcsr1 &= ~PCSR1_STATE;
            pcsr1 |= STATE_HALT;
            pcsr0 |= PCSR0_DNI;
        } else {
            pcsr0 |= PCSR0_PCEI;
        }
        break;
    case CMD_STOP:
        if (state == STATE_RUNNING) {
            pcsr1 &= ~PCSR1_STATE;
            pcsr1 |= STATE_READY;
            pcsr0 |= PCSR0_DNI;
        } else {
            pcsr0 |= PCSR0_PCEI;
        }
        break;
    case CMD_BOOT:
        pcsr0 |= PCSR0_PCEI;
        break;
    case CMD_NOOP:
        break;
    default:
        pcsr0 |= PCSR0_DNI;
        break;
    }

    // Clear command field after execution - driver expects PCMD=0 when done
    pcsr0 &= ~PCSR0_PCMD;

    if (trace.value)
        WARNING("DEUNA: port_command done, pcsr0=%06o", pcsr0);

    update_intr();
}

/*
 * deuna_c::execute_command
 * Purpose: interpret and execute the PCB command block.
 * Behavior: reads PCB/UDW pointers and services function codes.
 * Notes: returns false on invalid PCB or DMA failure to signal PCEI.
 */
bool deuna_c::execute_command(void)
{
    if (!dma_read_words(pcbb, pcb, 4)) {
        WARNING("DEUNA: PCB read failed pcbb=%08o", pcbb);
        return false;
    }

    if (pcb[0] & 0177400) {
        WARNING("DEUNA: PCB invalid pcbb0=%06o pcbb=%08o", pcb[0], pcbb);
        return false;
    }

    if (trace.value) {
        WARNING("DEUNA: PCB %06o %06o %06o %06o", pcb[0], pcb[1], pcb[2], pcb[3]);
        log_pcbb_snapshot("pre-cmd", pcbb);
    }

    uint16_t fnc = pcb[0] & 0377;
    uint32_t udbb = 0;
    auto get_udb_addr = [&](uint32_t &out) -> bool {
        if ((pcb[1] & 1) || (pcb[2] & 0374))
            return false;
        out = make_addr(pcb[2] & 0x0003, pcb[1] & 0177776);
        return true;
    };

    switch (fnc) {
    case FC_NOOP:
        break;
    case FC_RDPA:
        if (!mac_override && mac_is_zero(mac_addr))
            memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));
        if (trace.value) {
            WARNING("DEUNA: FC_RDPA mac=%02x:%02x:%02x:%02x:%02x:%02x",
                    mac_addr[0], mac_addr[1], mac_addr[2],
                    mac_addr[3], mac_addr[4], mac_addr[5]);
        }
        if (!dma_write_bytes(pcbb + 2, mac_addr, 6))
            return false;
        if (get_udb_addr(udbb) && udbb != pcbb + 2) {
            if (!dma_write_bytes(udbb, mac_addr, 6))
                return false;
        }
        if (trace.value)
            log_pcbb_snapshot("post-rdpa", pcbb);
        break;
    case FC_RPA:
        if (trace.value) {
            WARNING("DEUNA: FC_RPA mac=%02x:%02x:%02x:%02x:%02x:%02x",
                    setup.macs[0][0], setup.macs[0][1], setup.macs[0][2],
                    setup.macs[0][3], setup.macs[0][4], setup.macs[0][5]);
        }
        if (!dma_write_bytes(pcbb + 2, setup.macs[0], 6))
            return false;
        if (get_udb_addr(udbb) && udbb != pcbb + 2) {
            if (!dma_write_bytes(udbb, setup.macs[0], 6))
                return false;
        }
        if (trace.value) {
            uint8_t verify[6] = {0};
            if (dma_read_bytes(pcbb + 2, verify, 6)) {
                WARNING("DEUNA: FC_RPA verify mem=%02x:%02x:%02x:%02x:%02x:%02x",
                        verify[0], verify[1], verify[2],
                        verify[3], verify[4], verify[5]);
            }
            log_pcbb_snapshot("post-rpa", pcbb);
        }
        break;
    case FC_WPA:
        {
            uint8_t tmp[6] = {0};
            if (!dma_read_bytes(pcbb + 2, tmp, 6))
                return false;
            if (trace.value) {
                WARNING("DEUNA: FC_WPA mac=%02x:%02x:%02x:%02x:%02x:%02x",
                        tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);
            }
            if (mac_is_zero(tmp)) {
                memcpy(setup.macs[0], mac_addr, sizeof(mac_addr));
            } else {
                memcpy(setup.macs[0], tmp, sizeof(tmp));
            }
            setup.valid = true;
            if (setup.mac_count < 2)
                setup.mac_count = 2;
            update_pcap_filter();
            if (trace.value)
                log_pcbb_snapshot("post-wpa", pcbb);
        }
        break;
    case FC_RMAL: {
        int mtlen = (pcb[2] & 0xFF00) >> 8;
        if (!get_udb_addr(udbb))
            return false;
        if (mtlen < 0 || mtlen > 10)
            return false;
        if (!dma_write_bytes(udbb, reinterpret_cast<const uint8_t*>(&setup.macs[2]), mtlen * 6))
            return false;
        break;
    }
    case FC_WMAL: {
        int mtlen = (pcb[2] & 0xFF00) >> 8;
        if (mtlen < 0 || mtlen > 10)
            return false;
        if (!get_udb_addr(udbb))
            return false;
        for (int i = 2; i < DEUNA_FILTER_MAX; ++i)
            memset(setup.macs[i], 0, 6);
        if (!dma_read_bytes(udbb, reinterpret_cast<uint8_t*>(&setup.macs[2]), mtlen * 6))
            return false;
        setup.valid = true;
        setup.mac_count = mtlen + 2;
        update_pcap_filter();
        break;
    }
    case FC_RRF:
        if ((pcb[1] & 1) || (pcb[2] & 0374))
            return false;
        udb[0] = tdrb & 0177776;
        udb[1] = static_cast<uint16_t>((telen << 8) + ((tdrb >> 16) & 3));
        udb[2] = static_cast<uint16_t>(trlen);
        udb[3] = rdrb & 0177776;
        udb[4] = static_cast<uint16_t>((relen << 8) + ((rdrb >> 16) & 3));
        udb[5] = static_cast<uint16_t>(rrlen);
        if (!get_udb_addr(udbb))
            return false;
        if (!dma_write_words(udbb, udb, 6))
            return false;
        break;
    case FC_WRF:
        if ((pcb[1] & 1) || (pcb[2] & 0374))
            return false;
        if ((pcsr1 & PCSR1_STATE) == STATE_RUNNING)
            return false;
        if (!get_udb_addr(udbb))
            return false;
        if (!dma_read_words(udbb, udb, 6))
            return false;
        if ((udb[0] & 1) || (udb[1] & 0374) || (udb[3] & 1) || (udb[4] & 0374) || (udb[5] < 2))
            return false;
        tdrb = ((udb[1] & 3) << 16) + (udb[0] & 0177776);
        telen = (udb[1] >> 8) & 0377;
        trlen = udb[2];
        rdrb = ((udb[4] & 3) << 16) + (udb[3] & 0177776);
        relen = (udb[4] >> 8) & 0377;
        rrlen = udb[5];
        rxnext = 0;
        txnext = 0;
        if (trace.value) {
            WARNING("DEUNA: FC_WRF tx tdrb=%08o telen=%u trlen=%u", tdrb, telen, trlen);
            WARNING("DEUNA: FC_WRF rx rdrb=%08o relen=%u rrlen=%u", rdrb, relen, rrlen);
        }
        break;
    case FC_RDCTR:
    case FC_RDCLCTR: {
        memset(udb, 0, sizeof(udb));
        udb[0]  = 68;
        udb[1]  = stats.secs;
        udb[2]  = stats.frecv & 0xffff;
        udb[3]  = stats.frecv >> 16;
        udb[4]  = stats.mfrecv & 0xffff;
        udb[5]  = stats.mfrecv >> 16;
        udb[6]  = stats.rxerf;
        udb[7]  = stats.frecve;
        udb[8]  = stats.rbytes & 0xffff;
        udb[9]  = stats.rbytes >> 16;
        udb[10] = stats.mrbytes & 0xffff;
        udb[11] = stats.mrbytes >> 16;
        udb[12] = stats.rlossi;
        udb[13] = stats.rlossl;
        udb[14] = stats.ftrans & 0xffff;
        udb[15] = stats.ftrans >> 16;
        udb[16] = stats.mftrans & 0xffff;
        udb[17] = stats.mftrans >> 16;
        udb[18] = stats.ftrans3 & 0xffff;
        udb[19] = stats.ftrans3 >> 16;
        udb[20] = stats.ftrans2 & 0xffff;
        udb[21] = stats.ftrans2 >> 16;
        udb[22] = stats.ftransd & 0xffff;
        udb[23] = stats.ftransd >> 16;
        udb[24] = stats.tbytes & 0xffff;
        udb[25] = stats.tbytes >> 16;
        udb[26] = stats.mtbytes & 0xffff;
        udb[27] = stats.mtbytes >> 16;
        udb[28] = stats.txerf;
        udb[29] = stats.ftransa;
        udb[30] = stats.txccf;
        udb[31] = 0;
        udb[32] = stats.porterr;
        udb[33] = stats.bablcnt;
        if (!get_udb_addr(udbb))
            return false;
        if (!dma_write_words(udbb, udb, 68))
            return false;
        if (fnc == FC_RDCLCTR) {
            stats = stats_state();
            stats.last_update_ns = timeout_c::abstime_ns();
        }
        break;
    }
    case FC_RMODE: {
        uint16_t value = static_cast<uint16_t>(mode);
        if (!dma_write_words(pcbb + 2, &value, 1))
            return false;
        break;
    }
    case FC_WMODE: {
        uint16_t prev = static_cast<uint16_t>(mode);
        mode = pcb[1];
        setup.promiscuous = (mode & MODE_PROM) != 0;
        setup.multicast = (mode & MODE_ENAL) != 0;
        if (((prev ^ mode) & (MODE_PROM | MODE_ENAL)) != 0)
            update_pcap_filter();
        break;
    }
    case FC_RSTAT:
    case FC_RCSTAT: {
        uint16_t vals[3] = {stat, 10, 32};
        if (!dma_write_words(pcbb + 2, vals, 3))
            return false;
        if (fnc == FC_RCSTAT)
            stat &= 0377;
        break;
    }
    case FC_RSID: {
        memset(udb, 0, sizeof(udb));
        uint16_t mac_w[3] = {0};
        mac_w[0] = static_cast<uint16_t>(mac_addr[0] | (mac_addr[1] << 8));
        mac_w[1] = static_cast<uint16_t>(mac_addr[2] | (mac_addr[3] << 8));
        mac_w[2] = static_cast<uint16_t>(mac_addr[4] | (mac_addr[5] << 8));
        udb[11] = 0x260;
        udb[12] = 28;
        udb[13] = 7;
        udb[14] = 0;
        udb[15] = 1;
        udb[16] = 0x0303;
        udb[17] = 0;
        udb[18] = 2;
        udb[19] = 0x0502;
        udb[20] = 0x0700;
        udb[21] = 0x0600;
        udb[22] = mac_w[0];
        udb[23] = mac_w[1];
        udb[24] = mac_w[2];
        udb[25] = 0x64;
        udb[26] = static_cast<uint16_t>((11 << 8) + 1);
        if (!get_udb_addr(udbb))
            return false;
        if (!dma_write_words(udbb, udb, 52))
            return false;
        break;
    }
    case FC_WSID: {
        uint16_t pltlen = pcb[3];
        if (!get_udb_addr(udbb))
            return false;
        if (pltlen > DEUNA_UDB_WORDS)
            return false;
        if (!dma_read_words(udbb, udb, pltlen))
            return false;
        break;
    }
    case FC_RLSA: {
        static const uint8_t mcast_load_server[6] = {0xAB, 0x00, 0x00, 0x01, 0x00, 0x00};
        const uint8_t *src = mac_is_zero(load_server) ? mcast_load_server : load_server;
        if (!dma_write_bytes(pcbb + 2, src, 6))
            return false;
        break;
    }
    case FC_WLSA:
        if (!dma_read_bytes(pcbb + 2, load_server, 6))
            return false;
        break;
    case FC_LSM:
    case FC_DIM:
    case FC_LIM:
        break;
    default:
        return false;
    }

    return true;
}

/*
 * deuna_c::enqueue_readq
 * Purpose: stage a received Ethernet frame for later RX processing.
 * Behavior: copies data into the read queue with length and flags.
 * Notes: queue overflow increments loss counters.
 */
void deuna_c::enqueue_readq(const uint8_t *data, size_t len, bool loopback)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (!data || len == 0)
        return;

    if (len > ETH_MAX_PACKET)
        len = ETH_MAX_PACKET;

    queue_item item;
    item.loopback = loopback;
    item.packet.msg.assign(data, data + len);
    if (item.packet.msg.size() < ETH_MIN_PACKET)
        item.packet.msg.resize(ETH_MIN_PACKET, 0);
    item.packet.len = item.packet.msg.size();
    item.packet.crc_len = std::min(item.packet.len + 4, ETH_FRAME_SIZE);
    if (item.packet.msg.size() < item.packet.crc_len)
        item.packet.msg.resize(item.packet.crc_len, 0);
    read_queue.push_back(item);

    if (read_queue.size() > XU_QUE_MAX) {
        read_queue.pop_front();
        read_queue_loss++;
        stats.rlossl++;
        stat_rx_errors.value = stats.rlossl;
    }
}

/*
 * deuna_c::accept_packet
 * Purpose: decide whether a host frame should be delivered to the emulated NIC.
 * Behavior: checks length, broadcast/multicast rules, and filter setup.
 * Notes: assumes data points to a full Ethernet frame.
 */
bool deuna_c::accept_packet(const uint8_t *data, size_t len) const
{
    if (!data || len < 6)
        return false;

    if (setup.promiscuous)
        return true;

    const uint8_t *dst = data;
    if (!mac_is_zero(mac_addr) && mac_equal(dst, mac_addr))
        return true;

    if (mac_is_broadcast(dst))
        return true;

    if (mac_is_multicast(dst) && setup.multicast)
        return true;

    for (int i = 0; i < setup.mac_count; ++i) {
        if (!mac_is_zero(setup.macs[i]) && mac_equal(dst, setup.macs[i]))
            return true;
    }

    return false;
}

/*
 * deuna_c::update_pcap_filter
 * Purpose: configure libpcap filter based on current setup and mode.
 * Behavior: builds and applies a filter string or falls back to promisc.
 * Notes: failures are logged but do not abort the device.
 */
void deuna_c::update_pcap_filter(void)
{
#ifdef HAVE_PCAP
    if (!pcap.is_open())
        return;

    if (setup.promiscuous) {
        if (!pcap.set_filter("ip or not ip"))
            WARNING("DEUNA: pcap filter set failed: %s", pcap.last_error().c_str());
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
        for (int i = 0; i < setup.mac_count; ++i) {
            if (!mac_is_zero(setup.macs[i]) && !mac_equal(setup.macs[i], mac_addr))
                add_mac(setup.macs[i]);
        }
    }

    if (filter.empty())
        filter = "ip or not ip";

    if (!pcap.set_filter(filter))
        WARNING("DEUNA: pcap filter set failed: %s", pcap.last_error().c_str());
#endif
}

/*
 * deuna_c::process_receive
 * Purpose: move queued frames into the RX descriptor ring.
 * Behavior: pulls from read_queue, DMA-writes buffers, updates status.
 * Notes: only runs when state is RUNNING; returns false on ring errors.
 */
bool deuna_c::process_receive(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if ((pcsr1 & PCSR1_STATE) != STATE_RUNNING)
        return false;

    if (read_queue.empty())
        return false;

    if (rrlen == 0 || relen == 0)
        return false;
    if (relen < 4) {
        stat |= STAT_ERRS | STAT_RRNG;
        pcsr0 |= PCSR0_SERI;
        return false;
    }

    unsigned limit = rx_slots.value ? rx_slots.value : rrlen;
    unsigned processed = 0;
    queue_item *item = nullptr;

    while (!read_queue.empty() && (limit == 0 || processed < limit)) {
        uint32_t desc_addr = rdrb + (relen * 2) * rxnext;
        std::vector<uint16_t> desc(relen, 0);
        if (!desc_read_words(desc_addr, desc.data(), relen)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_RRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }
        rxhdr[0] = desc[0];
        rxhdr[1] = desc[1];
        rxhdr[2] = desc[2];
        rxhdr[3] = desc[3];

        if (!(rxhdr[2] & RXR_OWN))
            break;

        if (!item)
            item = &read_queue.front();

        uint16_t slen = rxhdr[0];
        uint32_t segb = make_addr(rxhdr[2] & 0x0003, rxhdr[1]);

        rxhdr[2] &= static_cast<uint16_t>(~(RXR_FRAM | RXR_OFLO | RXR_CRC | RXR_STF | RXR_ENF | RXR_ERRS));
        rxhdr[3] &= static_cast<uint16_t>(~(RXR_BUFL | RXR_UBTO | RXR_NCHN | RXR_OVRN | RXR_MLEN));

        if (item->packet.used == 0)
            rxhdr[2] |= RXR_STF;

        size_t remaining = item->packet.crc_len - item->packet.used;
        size_t wlen = std::min(static_cast<size_t>(slen), remaining);

        if (wlen > 0) {
            if (!dma_write_bytes(segb, &item->packet.msg[item->packet.used], wlen)) {
                stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_RRNG;
                pcsr0 |= PCSR0_SERI;
                break;
            }
        }

        item->packet.used += wlen;
        rxhdr[3] |= static_cast<uint16_t>(item->packet.crc_len & RXR_MLEN);

        bool end_of_frame = (item->packet.used >= item->packet.crc_len) || (mode & MODE_DRDC);
        if (end_of_frame) {
            rxhdr[2] |= RXR_ENF;
            if ((mode & MODE_DRDC) && item->packet.used < item->packet.crc_len) {
                rxhdr[3] |= RXR_NCHN;
                rxhdr[2] |= RXR_ERRS;
                stats.frecve++;
            }

            stats.frecv++;
            stats.rbytes += static_cast<uint32_t>(item->packet.len > 14 ? item->packet.len - 14 : 0);
            if (mac_is_multicast(item->packet.msg.data())) {
                stats.mfrecv++;
                stats.mrbytes += static_cast<uint32_t>(item->packet.len > 14 ? item->packet.len - 14 : 0);
            }

            pcsr0 |= PCSR0_RXI;
            stat_rx_frames.value = stats.frecv;
            stat_rx_errors.value = stats.frecve + stats.rlossl;

            read_queue.pop_front();
            item = nullptr;
        }

        rxhdr[2] &= ~RXR_OWN;
        desc[0] = rxhdr[0];
        desc[1] = rxhdr[1];
        desc[2] = rxhdr[2];
        desc[3] = rxhdr[3];
        if (!desc_write_words(desc_addr, desc.data(), relen)) {
            pcsr0 |= PCSR0_PCEI;
            break;
        }

        rxnext++;
        if (rxnext >= rrlen)
            rxnext = 0;

        processed++;
    }

    update_intr();
    return true;
}

/*
 * deuna_c::process_transmit
 * Purpose: send frames from the TX descriptor ring to the host.
 * Behavior: reads descriptors, DMA-reads buffers, and injects via pcap.
 * Notes: updates TX stats and sets PCSR0 flags on errors.
 */
bool deuna_c::process_transmit(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if ((pcsr1 & PCSR1_STATE) != STATE_RUNNING)
        return false;

    if (trlen == 0 || telen == 0)
        return false;
    if (telen < 4) {
        stat |= STAT_ERRS | STAT_TRNG;
        pcsr0 |= PCSR0_SERI;
        return false;
    }

    unsigned limit = tx_slots.value ? tx_slots.value : trlen;
    unsigned processed = 0;
    bool txi_set = false;

    bool giant = false;
    bool runt = false;

    static unsigned tx_not_owned_squelch = 0;
    static unsigned tx_ring_dump_squelch = 0;
    auto find_owned_desc = [&](unsigned &owned_index) -> bool {
        if (trlen == 0)
            return false;
        for (unsigned i = 0; i < trlen; ++i) {
            uint32_t probe_addr = tdrb + (telen * 2) * i;
            uint16_t probe[4] = {0};
            if (!desc_read_words(probe_addr, probe, 4))
                continue;
            if (probe[2] & TXR_OWN) {
                owned_index = i;
                return true;
            }
        }
        return false;
    };
    if (trace.value && tx_not_owned_squelch < 4) {
        WARNING("DEUNA: TX start tdrb=%08o telen=%u trlen=%u txnext=%u limit=%u",
                tdrb, telen, trlen, txnext, limit);
    }

    while (limit == 0 || processed < limit) {
        uint32_t desc_addr = tdrb + (telen * 2) * txnext;
        std::vector<uint16_t> desc(telen, 0);
        if (!desc_read_words(desc_addr, desc.data(), telen)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_TRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }
        txhdr[0] = desc[0];
        txhdr[1] = desc[1];
        txhdr[2] = desc[2];
        txhdr[3] = desc[3];

        if (!(txhdr[2] & TXR_OWN)) {
            unsigned owned_index = 0;
            if (find_owned_desc(owned_index)) {
                if (trace.value && tx_not_owned_squelch < 4) {
                    WARNING("DEUNA: TX desc not owned at txnext=%u, jumping to owned=%u",
                            txnext, owned_index);
                }
                txnext = owned_index;
                tx_not_owned_squelch = 0;
                continue;
            }
            if (trace.value && tx_ring_dump_squelch < 2) {
                WARNING("DEUNA: TX ring has no owned descriptors, dumping ring");
                dump_tx_ring(8);
                tx_ring_dump_squelch++;
            }
            if (trace.value && tx_not_owned_squelch < 4) {
                WARNING("DEUNA: TX desc addr=%08o w0=%06o w1=%06o w2=%06o w3=%06o",
                        desc_addr, txhdr[0], txhdr[1], txhdr[2], txhdr[3]);
                WARNING("DEUNA: TX desc not owned, stopping at txnext=%u", txnext);
                tx_not_owned_squelch++;
            }
            break;
        }
        if (trace.value) {
            WARNING("DEUNA: TX desc addr=%08o w0=%06o w1=%06o w2=%06o w3=%06o",
                    desc_addr, txhdr[0], txhdr[1], txhdr[2], txhdr[3]);
        }

        uint16_t slen = txhdr[0];
        uint32_t segb = make_addr(txhdr[2] & 0x0003, txhdr[1]);
        size_t wlen = slen;

        txhdr[2] &= static_cast<uint16_t>(~(TXR_ERRS | TXR_MTCH | TXR_MORE | TXR_ONE | TXR_DEF));
        txhdr[3] &= static_cast<uint16_t>(~(TXR_BUFL | TXR_UBTO | TXR_UFLO | TXR_LCOL | TXR_LCAR | TXR_RTRY | TXR_TDR));

        if (txhdr[2] & TXR_STF) {
            write_buffer.msg.assign(ETH_FRAME_SIZE, 0);
            write_buffer.len = 0;
            write_buffer.used = 0;
            giant = false;
            runt = false;
        }

        if (write_buffer.len >= ETH_MAX_PACKET) {
            wlen = 0;
            giant = true;
        } else if (write_buffer.len + wlen > ETH_MAX_PACKET) {
            wlen = ETH_MAX_PACKET - write_buffer.len;
            giant = true;
        }

        if (wlen > 0) {
            if (!dma_read_bytes(segb, write_buffer.msg.data() + write_buffer.len, wlen)) {
                stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_TRNG;
                pcsr0 |= PCSR0_SERI;
                break;
            }
        }

        write_buffer.len += wlen;

        if (txhdr[2] & TXR_ENF) {
            if (write_buffer.len < ETH_MIN_PACKET) {
                write_buffer.len = ETH_MIN_PACKET;
                if ((mode & MODE_TPAD) == 0)
                    runt = true;
            }

            if (write_buffer.len >= 12 && !mac_is_zero(setup.macs[0])) {
                memcpy(write_buffer.msg.data() + 6, setup.macs[0], 6);
            }

            if ((mode & MODE_LOOP) && (mode & MODE_INTL)) {
                enqueue_readq(write_buffer.msg.data(), write_buffer.len, true);
            } else {
                if (!pcap.is_open() || !pcap.send(write_buffer.msg.data(), write_buffer.len)) {
                    if (!pcap.is_open()) {
                        WARNING("DEUNA: TX pcap not open");
                    } else {
                        WARNING("DEUNA: TX pcap send failed: %s", pcap.last_error().c_str());
                    }
                    txhdr[3] |= TXR_RTRY;
                    txhdr[2] |= TXR_ERRS;
                    stats.ftransa++;
                }
            }

            if (giant || runt) {
                txhdr[3] |= TXR_BUFL;
                txhdr[2] |= TXR_ERRS;
                stats.txerf |= 0x0010;
            }

            for (int i = 0; i < setup.mac_count; ++i) {
                if (mac_equal(write_buffer.msg.data(), setup.macs[i])) {
                    txhdr[2] |= TXR_MTCH;
                    break;
                }
            }

            pcsr0 |= PCSR0_TXI;
            txi_set = true;
            stats.ftrans++;
            stats.tbytes += static_cast<uint32_t>(write_buffer.len > 14 ? write_buffer.len - 14 : 0);
            if (mac_is_multicast(write_buffer.msg.data())) {
                stats.mftrans++;
                stats.mtbytes += static_cast<uint32_t>(write_buffer.len > 14 ? write_buffer.len - 14 : 0);
            }

            stat_tx_frames.value = stats.ftrans;
            stat_tx_errors.value = stats.ftransa;
        }

        txhdr[2] &= ~TXR_OWN;
        desc[0] = txhdr[0];
        desc[1] = txhdr[1];
        desc[2] = txhdr[2];
        desc[3] = txhdr[3];
        if (!desc_write_words(desc_addr, desc.data(), telen)) {
            pcsr0 |= PCSR0_PCEI;
            stats.ftransa++;
            break;
        }

        if (trace.value) {
            WARNING("DEUNA: TX desc writeback addr=%08o w2=%06o w3=%06o",
                    desc_addr, txhdr[2], txhdr[3]);
        }

        txnext++;
        if (txnext >= trlen)
            txnext = 0;

        processed++;
    }

    if (processed > 0 && !txi_set) {
        pcsr0 |= PCSR0_TXI;
    }

    update_intr();
    return true;
}

/*
 * deuna_c::dump_tx_ring
 * Purpose: trace TX ring descriptor ownership and headers for debugging.
 * Behavior: reads up to max_entries descriptors and logs their header words.
 * Notes: trace-only diagnostic to correlate driver-owned vs device-owned slots.
 */
void deuna_c::dump_tx_ring(unsigned max_entries)
{
    if (trlen == 0 || telen < 4) {
        WARNING("DEUNA: TX ring dump skipped (trlen=%u telen=%u)", trlen, telen);
        return;
    }

    unsigned count = std::min(max_entries, trlen);
    for (unsigned i = 0; i < count; ++i) {
        uint32_t desc_addr = tdrb + (telen * 2) * i;
        uint16_t words[4] = {0};
        if (!desc_read_words(desc_addr, words, 4)) {
            WARNING("DEUNA: TX ring[%u] addr=%08o read failed", i, desc_addr);
            continue;
        }
        WARNING("DEUNA: TX ring[%u] addr=%08o w0=%06o w1=%06o w2=%06o w3=%06o",
                i, desc_addr, words[0], words[1], words[2], words[3]);
    }
}

/*
 * deuna_c::service_timers
 * Purpose: maintain DEUNA stats timebase.
 * Behavior: updates seconds counter based on monotonic time.
 * Notes: invoked in RX thread to amortize timer work.
 */
void deuna_c::service_timers(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    uint64_t now = timeout_c::abstime_ns();
    if (stats.last_update_ns == 0)
        stats.last_update_ns = now;

    uint64_t elapsed_ns = now - stats.last_update_ns;
    if (elapsed_ns >= 1000000000ULL) {
        stats.secs += static_cast<uint32_t>(elapsed_ns / 1000000000ULL);
        stats.last_update_ns = now;
    }
}

/*
 * deuna_c::worker
 * Purpose: worker thread entrypoint dispatcher.
 * Behavior: routes instance 0 to RX and instance 1 to TX.
 * Notes: trace is emitted here to tag worker startup.
 */
void deuna_c::worker(unsigned instance)
{
    if (trace.value)
        WARNING("DEUNA: %s worker(%u) start", DEUNA_VERSION, instance);
    if (instance == 0)
        worker_rx();
    else
        worker_tx();
}

/*
 * deuna_c::worker_rx
 * Purpose: RX thread loop for pcap polling and receive ring processing.
 * Behavior: polls pcap, enqueues frames, runs process_receive, and services timers.
 * Notes: runs at RT priority; keep per-iteration work short.
 */
void deuna_c::worker_rx(void)
{
    worker_init_realtime_priority(rt_device);

    uint8_t pkt_buf[2048];
    while (!workers_terminate) {
        service_timers();

        if (init_asserted) {
            timeout_c::wait_ms(1);
            continue;
        }

        size_t len = 0;
        if (pcap.is_open()) {
            if (!pcap.poll(pkt_buf, sizeof(pkt_buf), &len)) {
                WARNING("DEUNA: pcap poll error: %s", pcap.last_error().c_str());
                timeout_c::wait_ms(10);
                continue;
            }
            if (len > 0) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                if (accept_packet(pkt_buf, len))
                    enqueue_readq(pkt_buf, len, false);
            }
        }

        process_receive();
        timeout_c::wait_ms(1);
    }
}

/*
 * deuna_c::worker_tx
 * Purpose: TX thread loop for descriptor-driven transmit and command processing.
 * Behavior: processes queued register writes and port commands, then handles TX.
 * Notes: uses condition variable for low-latency wakeup on new commands.
 */
void deuna_c::worker_tx(void)
{
    worker_init_realtime_priority(rt_device);

    while (!workers_terminate) {
        // Wait for work with a short timeout (for periodic TX polling)
        {
            std::unique_lock<std::mutex> lock(pending_cmd_mutex);
            pending_cmd_cv.wait_for(lock, std::chrono::microseconds(100));
        }

        if (init_asserted) {
            timeout_c::wait_ms(1);
            continue;
        }

        // Process any queued register writes first (maintains PCSR2/3 -> PCSR0 ordering)
        apply_pending_reg_writes();
        
        // Process any pending DMA-requiring command
        process_pending_command();

        // Normal TX ring processing
        process_transmit();
    }
}
