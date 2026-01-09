/*
 * DEUNA Ethernet Controller Emulation for QUniBone
 * (c) Dave Plummer, davepl@davepl.com, Plummer's Software LLC, 2026
 * Contributed under the GPL2 License
 *
 * Clean-sheet implementation based on:
 *   - DEC DEUNA/DELUA User's Guide
 *   - UNIBUS specification
 *   - OpenSIMH pdp11_xu (behavior reference)
 *
 * This version keeps the implementation compact and deterministic:
 *   - 4-word descriptors are the canonical format; 5-word descriptors are
 *     accepted but only words 0-3 are interpreted (word 4 preserved).
 *   - Descriptor ownership is always in word 2 (TXR_OWN/RXR_OWN).
 *   - Ring processing follows the OpenSIMH model for RX/TX.
 *   - Unknown or undocumented behaviors are omitted.
 */

#include <string.h>
#include <stdio.h>
#include <algorithm>
#include <vector>
#include <string>
#include <utility>

#include "deuna_bootrom.h"
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

/*
 * Queue and internal memory constants
 */
static const unsigned UNA_QUE_MAX = 500;
static const size_t DEUNA_WCS_WORDS = 8192;
static const size_t DEUNA_LINK_WORDS = 1024;

/*
 * Descriptor sizes (words)
 */
static const unsigned DEUNA_DESC_WORDS = 4;
static const unsigned DEUNA_DESC_WORDS_EXT = 5;  // 2.11BSD uses 5-word descriptors

static inline bool deuna_desc_words_supported(unsigned words)
{
    return words == DEUNA_DESC_WORDS || words == DEUNA_DESC_WORDS_EXT;
}

/*
 * Version string - bump to verify running code
 */
static const char *DEUNA_VERSION = "v101";

/*
 * Default DEUNA hardware address (DEC OUI)
 */
static const uint8_t DEUNA_DEFAULT_MAC[6] = {0x44, 0x41, 0x56, 0x45, 0x50, 0x4c};

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
static const uint16_t PCSR1_STATE = 0000017;  // State

static const uint16_t TYPE_DEUNA = (0 << 4);

static const uint16_t STATE_READY   = 002;
static const uint16_t STATE_RUNNING = 003;
static const uint16_t STATE_HALT    = 010;

/*
 * Status register definitions
 */
static const uint16_t STAT_ERRS = 0100000;
static const uint16_t STAT_MERR = 0040000;
static const uint16_t STAT_TMOT = 0004000;
static const uint16_t STAT_RRNG = 0001000;
static const uint16_t STAT_TRNG = 0000400;

/*
 * Mode register definitions
 */
static const uint16_t MODE_PROM = 0100000; // Promiscuous mode
static const uint16_t MODE_ENAL = 0040000; // Enable all multicast
static const uint16_t MODE_DRDC = 0020000; // Disable data chaining
static const uint16_t MODE_TPAD = 0010000; // Transmit pad enable
static const uint16_t MODE_INTL = 0000200; // Internal loopback [DELUA]
static const uint16_t MODE_LOOP = 0000004; // Internal loopback mode

/*
 * Function codes (GETCMD)
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
 * Descriptor status bits (word 2 and 3)
 */
static const uint16_t TXR_OWN   = 0100000;  // w2: owned by controller
static const uint16_t TXR_ERRS  = 0040000;  // w2: error summary
static const uint16_t TXR_MTCH  = 0020000;  // w2: station match
static const uint16_t TXR_MORE  = 0010000;  // w2: multiple retries
static const uint16_t TXR_ONE   = 0004000;  // w2: one collision
static const uint16_t TXR_DEF   = 0002000;  // w2: deferred
static const uint16_t TXR_STF   = 0001000;  // w2: start of frame
static const uint16_t TXR_ENF   = 0000400;  // w2: end of frame

static const uint16_t TXR_BUFL  = 0100000;  // w3: buffer length error
static const uint16_t TXR_UBTO  = 0040000;  // w3: UNIBUS timeout
static const uint16_t TXR_UFLO  = 0020000;  // w3: underflow
static const uint16_t TXR_LCOL  = 0010000;  // w3: late collision
static const uint16_t TXR_LCAR  = 0004000;  // w3: lost carrier
static const uint16_t TXR_RTRY  = 0002000;  // w3: retry failure
static const uint16_t TXR_TDR   = 0001777;  // w3: TDR value

static const uint16_t RXR_OWN   = 0100000;  // w2: owned by controller
static const uint16_t RXR_ERRS  = 0040000;  // w2: error summary
static const uint16_t RXR_FRAM  = 0020000;  // w2: frame error
static const uint16_t RXR_OFLO  = 0010000;  // w2: message overflow
static const uint16_t RXR_CRC   = 0004000;  // w2: CRC error
static const uint16_t RXR_STF   = 0001000;  // w2: start of frame
static const uint16_t RXR_ENF   = 0000400;  // w2: end of frame

static const uint16_t RXR_BUFL  = 0100000;  // w3: buffer length error
static const uint16_t RXR_UBTO  = 0040000;  // w3: UNIBUS timeout
static const uint16_t RXR_NCHN  = 0020000;  // w3: no data chaining
static const uint16_t RXR_OVRN  = 0010000;  // w3: overrun
static const uint16_t RXR_MLEN  = 0007777;  // w3: message length

static bool mac_is_zero(const uint8_t *mac)
{
    for (int i = 0; i < 6; ++i) {
        if (mac[i] != 0)
            return false;
    }
    return true;
}

static bool mac_is_broadcast(const uint8_t *mac)
{
    for (int i = 0; i < 6; ++i) {
        if (mac[i] != 0xff)
            return false;
    }
    return true;
}

static bool mac_is_multicast(const uint8_t *mac)
{
    return (mac[0] & 0x01) != 0;
}

static bool mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

/*
 * DEUNA Constructor
 */
deuna_c::deuna_c() : dec_ether_base_c()
{
    set_workers_count(2);  // Instance 0 = RX, Instance 1 = TX

    name.value = "deuna";
    type_name.value = "DEUNA";
    log_label = "deuna";

    set_default_bus_params(DEUNA_DEFAULT_ADDR, DEUNA_DEFAULT_SLOT,
            DEUNA_DEFAULT_VECTOR, DEUNA_DEFAULT_LEVEL);

    dma_request.set_priority_slot(priority_slot.value);
    dma_desc_request.set_priority_slot(priority_slot.value);
    intr_request.set_priority_slot(priority_slot.value);
    intr_request.set_level(intr_level.value);
    intr_request.set_vector(intr_vector.value);

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
    reg_pcsr1->writable_bits = 0x0000;

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
    intr_dma_holdoff_us.value = 200;
    trace.value = false;

    memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));

    read_buffer.msg.resize(ETH_FRAME_SIZE);
    write_buffer.msg.resize(ETH_FRAME_SIZE);

    wcs_mem.assign(DEUNA_WCS_WORDS, 0);
    link_mem.assign(DEUNA_LINK_WORDS, 0);

    init_internal_memory();
}

deuna_c::~deuna_c()
{
#ifdef HAVE_PCAP
    pcap.close();
#endif
}

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
            WARNING("DEUNA: ifname cannot be changed while installed");
            return false;
        }
    } else if (param == &mac) {
        if (mac.new_value.empty()) {
            mac_override = false;
            memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));
        } else {
            uint8_t parsed[6] = {0};
            if (!parse_mac(mac.new_value, parsed)) {
                ERROR("DEUNA: invalid MAC format '%s'", mac.new_value.c_str());
                return false;
            }
            mac_override = true;
            memcpy(mac_addr, parsed, sizeof(mac_addr));
        }
        memcpy(setup.macs[0], mac_addr, sizeof(mac_addr));
        setup.valid = true;
        setup.mac_count = 1;
        update_pcap_filter();
    } else if (param == &promisc) {
        update_pcap_filter();
    }

    return qunibusdevice_c::on_param_changed(param);
}

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
        ERROR("DEUNA: failed to open pcap on %s: %s",
              ifname.value.c_str(), pcap.last_error().c_str());
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

    return true;
#endif
}

void deuna_c::on_after_install(void)
{
    INFO("DEUNA: Installed %s", DEUNA_VERSION);
    reset_controller();
}

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
}

void deuna_c::on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge)
{
    UNUSED(aclo_edge);
    if (dclo_edge == SIGNAL_EDGE_RAISING)
        reset_controller();
}

void deuna_c::on_init_changed(void)
{
    if (init_asserted)
        reset_controller();
}

void deuna_c::update_pcsr_regs(void)
{
    if (!reg_pcsr0 || !reg_pcsr0->pru_iopage_register)
        return;

    set_register_dati_value(reg_pcsr0, pcsr0, "pcsr0");
    set_register_dati_value(reg_pcsr1, pcsr1, "pcsr1");
    set_register_dati_value(reg_pcsr2, pcsr2, "pcsr2");
    set_register_dati_value(reg_pcsr3, pcsr3, "pcsr3");
}

void deuna_c::update_transceiver_bits(void)
{
    if (pcap.is_open()) {
        pcsr1 &= ~(PCSR1_XPWR | PCSR1_ICAB);
    } else {
        pcsr1 |= PCSR1_XPWR;
    }
}

void deuna_c::update_intr(void)
{
    const bool pending = (pcsr0 & PCSR0_W1C_MASK) != 0;
    if (pending)
        pcsr0 |= PCSR0_INTR;
    else
        pcsr0 &= ~PCSR0_INTR;

    update_pcsr_regs();

    if (!qunibusadapter)
        return;

    const bool inte = (pcsr0 & PCSR0_INTE) != 0;
    const bool dma_ok = (dma_in_progress.load(std::memory_order_relaxed) == 0);

    if (!pending || !inte || !dma_ok) {
        if (irq) {
            qunibusadapter->cancel_INTR(intr_request);
            irq = false;
        }
        note_intr_deasserted();
        return;
    }

    if (irq) {
        qunibusadapter->cancel_INTR(intr_request);
        irq = false;
    }

    note_intr_asserted();
    qunibusadapter->INTR(intr_request, reg_pcsr0, pcsr0);
    irq = true;
}

void deuna_c::reset_controller(void)
{
    reset_in_progress.store(true, std::memory_order_release);

    std::lock_guard<std::recursive_mutex> state_lock(state_mutex);

    {
        std::lock_guard<std::mutex> reg_lock(pending_reg_mutex);
        pending_reg_queue.clear();
    }
    {
        std::lock_guard<std::mutex> cmd_lock(pending_cmd_mutex);
        pending_cmd = 0;
    }

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        read_queue.clear();
        read_queue_loss = 0;
    }

    dma_in_progress.store(0, std::memory_order_release);
    intr_request.edge_detect_reset();
    note_intr_deasserted();

    pcsr0 = PCSR0_DNI;
    pcsr1 = TYPE_DEUNA | STATE_READY;
    pcsr2 = 0;
    pcsr3 = 0;
    mode = 0;
    stat = 0;
    irq = false;

    pcbb = 0;
    tdrb = 0;
    telen = 0;
    trlen = 0;
    txnext = 0;
    rdrb = 0;
    relen = 0;
    rrlen = 0;
    rxnext = 0;

    memset(pcb, 0, sizeof(pcb));
    memset(udb, 0, sizeof(udb));
    memset(rxhdr, 0, sizeof(rxhdr));
    memset(txhdr, 0, sizeof(txhdr));

    if (!mac_override)
        memcpy(mac_addr, DEUNA_DEFAULT_MAC, sizeof(mac_addr));
    setup.valid = true;
    setup.promiscuous = false;
    setup.multicast = false;
    setup.mac_count = 1;
    memset(setup.macs, 0, sizeof(setup.macs));
    memcpy(setup.macs[0], mac_addr, sizeof(mac_addr));

    stats = stats_state();
    stats.last_update_ns = timeout_c::abstime_ns();
    stat_rx_frames.value = 0;
    stat_tx_frames.value = 0;
    stat_rx_errors.value = 0;
    stat_tx_errors.value = 0;

    update_transceiver_bits();
    update_pcap_filter();
    update_intr();

    reset_in_progress.store(false, std::memory_order_release);
}

void deuna_c::init_internal_memory(void)
{
    wcs_mem.assign(DEUNA_WCS_WORDS, 0);
    link_mem.assign(DEUNA_LINK_WORDS, 0);
}

void deuna_c::on_after_register_access(qunibusdevice_register_t *device_reg,
        uint8_t qunibus_control, DATO_ACCESS access)
{
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    uint16_t val = get_register_dato_value(device_reg);
    uint16_t w1c_snapshot = 0;
    if (device_reg->index == DEUNA_REG_PCSR0) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        w1c_snapshot = pcsr0;
    }

    std::lock_guard<std::mutex> lock(pending_reg_mutex);
    pending_reg_write write;
    write.reg_index = static_cast<uint8_t>(device_reg->index);
    write.value = val;
    write.access = static_cast<uint8_t>(access);
    write.w1c_snapshot = w1c_snapshot;
    pending_reg_queue.push_back(write);

    pending_cmd_cv.notify_one();
}

void deuna_c::handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access,
        uint16_t w1c_snapshot)
{
    const uint16_t byte_mask =
        (access == DATO_WORD) ? 0xffff :
        (access == DATO_BYTEH) ? 0xff00 :
        0x00ff;

    if (trace.value) {
        static const char *reg_names[] = {"PCSR0", "PCSR1", "PCSR2", "PCSR3"};
        const char *rname = (reg_index < 4) ? reg_names[reg_index] : "?";
        DEBUG("DEUNA: Write %s (reg %u) = %06o access=%d", rname, reg_index, val, access);
    }

    switch (reg_index) {
    case DEUNA_REG_PCSR0: {
        const uint16_t w1c_bits = static_cast<uint16_t>(val & PCSR0_W1C_MASK & byte_mask);
        const uint16_t snapshot = w1c_snapshot ? w1c_snapshot : pcsr0;
        pcsr0 &= static_cast<uint16_t>(~(w1c_bits & snapshot));

        if ((byte_mask & PCSR0_RSET) && (val & PCSR0_RSET)) {
            reset_controller();
            return;
        }

        if (byte_mask & PCSR0_INTE) {
            const bool old_inte = (pcsr0 & PCSR0_INTE) != 0;
            const bool new_inte = (val & PCSR0_INTE) != 0;
            if (old_inte != new_inte) {
                if (new_inte)
                    pcsr0 |= PCSR0_INTE;
                else
                    pcsr0 &= ~PCSR0_INTE;
                pcsr0 |= PCSR0_DNI;
                update_intr();
                return;
            }
        }

        if (byte_mask & 0x00ff) {
            pcsr0 &= ~PCSR0_PCMD;
            pcsr0 |= (val & PCSR0_PCMD);
            port_command(pcsr0 & PCSR0_PCMD);
        }

        update_intr();
        break;
    }
    case DEUNA_REG_PCSR2: {
        uint16_t merged = pcsr2;
        if (access == DATO_WORD)
            merged = val;
        else if (access == DATO_BYTEH)
            merged = static_cast<uint16_t>((pcsr2 & 0x00ff) | (val & 0xff00));
        else
            merged = static_cast<uint16_t>((pcsr2 & 0xff00) | (val & 0x00ff));
        pcsr2 = merged & 0177776;
        update_pcsr_regs();
        break;
    }
    case DEUNA_REG_PCSR3: {
        uint16_t merged = pcsr3;
        if (access == DATO_WORD)
            merged = val;
        else if (access == DATO_BYTEH)
            merged = static_cast<uint16_t>((pcsr3 & 0x00ff) | (val & 0xff00));
        else
            merged = static_cast<uint16_t>((pcsr3 & 0xff00) | (val & 0x00ff));
        pcsr3 = merged & 0000003;
        update_pcsr_regs();
        break;
    }
    default:
        break;
    }
}

void deuna_c::apply_pending_reg_writes(void)
{
    std::deque<pending_reg_write> writes;
    {
        std::lock_guard<std::mutex> lock(pending_reg_mutex);
        if (pending_reg_queue.empty())
            return;
        writes.swap(pending_reg_queue);
    }

    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    for (const auto &write : writes) {
        handle_register_write(write.reg_index, write.value,
                static_cast<DATO_ACCESS>(write.access), write.w1c_snapshot);
    }
}

void deuna_c::process_pending_command(void)
{
    uint16_t cmd = 0;
    {
        std::lock_guard<std::mutex> lock(pending_cmd_mutex);
        cmd = pending_cmd;
        pending_cmd = 0;
    }
    if (cmd != 0)
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        port_command(cmd);
        update_intr();
    }
}

bool deuna_c::cpu_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    return dma_read_words(addr, buffer, wordcount);
}

bool deuna_c::cpu_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
{
    return dma_read_bytes(addr, buffer, len);
}

bool deuna_c::process_bootrom(uint32_t dst_addr)
{
    if (dst_addr == 0 || deuna_bootrom_size == 0)
        return false;
    if (!addr_in_ram(dst_addr, deuna_bootrom_size))
        return false;

    const size_t chunk_bytes = 512;
    for (size_t offset = 0; offset < deuna_bootrom_size; offset += chunk_bytes) {
        size_t len = deuna_bootrom_size - offset;
        if (len > chunk_bytes)
            len = chunk_bytes;
        if (!dma_write_bytes(dst_addr + static_cast<uint32_t>(offset),
                             &deuna_bootrom[offset], len)) {
            return false;
        }
    }

    return true;
}

bool deuna_c::load_system_microcode(uint32_t udbb)
{
    if (udbb != 0) {
        if (transfer_internal_memory(udbb, true))
            return true;
    }

    size_t word_count = deuna_bootrom_size / 2;
    size_t limit = word_count;
    if (limit > wcs_mem.size())
        limit = wcs_mem.size();
    for (size_t i = 0; i < limit; ++i) {
        uint16_t word = static_cast<uint16_t>(deuna_bootrom[i * 2] |
                                              (static_cast<uint16_t>(deuna_bootrom[i * 2 + 1]) << 8));
        wcs_mem[i] = word;
    }
    return true;
}

bool deuna_c::transfer_internal_memory(uint32_t udbb, bool to_internal)
{
    uint16_t hdr[4] = {0};
    if (!dma_read_words(udbb, hdr, 4))
        return false;

    uint16_t mem_addr = hdr[0];
    uint16_t wordcount = hdr[1];
    uint32_t host_addr = make_addr(hdr[3], hdr[2] & 0177776);

    if (wordcount == 0 || host_addr == 0)
        return false;
    if (!addr_in_ram(host_addr, static_cast<size_t>(wordcount) * 2u))
        return false;

    bool link = (mem_addr & 0x8000u) != 0;
    size_t offset = mem_addr & 0x7fffu;
    std::vector<uint16_t> *mem = link ? &link_mem : &wcs_mem;
    if (offset + wordcount > mem->size())
        return false;

    if (to_internal) {
        std::vector<uint16_t> tmp(wordcount, 0);
        if (!dma_read_words(host_addr, tmp.data(), wordcount))
            return false;
        for (size_t i = 0; i < wordcount; ++i)
            (*mem)[offset + i] = tmp[i];
    } else {
        std::vector<uint16_t> tmp(wordcount, 0);
        for (size_t i = 0; i < wordcount; ++i)
            tmp[i] = (*mem)[offset + i];
        if (!dma_write_words(host_addr, tmp.data(), wordcount))
            return false;
    }

    return true;
}

void deuna_c::log_pcbb_snapshot(const char *tag, uint32_t addr)
{
    if (!trace.value)
        return;

    uint16_t words[4] = {0};
    if (!dma_read_words(addr, words, 4))
        return;
    WARNING("DEUNA: %s PCBB@%08o %06o %06o %06o %06o",
            tag, addr, words[0], words[1], words[2], words[3]);
}

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

void deuna_c::port_command(uint16_t cmd)
{
    uint16_t state = pcsr1 & PCSR1_STATE;

    switch (cmd) {
    case CMD_PDMD:
        process_transmit(0);
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
        break;
    case CMD_SELFTEST:
        init_internal_memory();
        pcsr0 |= PCSR0_DNI;
        pcsr0 &= ~(PCSR0_USCI | PCSR0_FATL);
        pcsr1 = (pcsr1 & ~PCSR1_STATE) | STATE_READY;
        break;
    case CMD_START:
        if (state == STATE_READY) {
            pcsr1 = (pcsr1 & ~PCSR1_STATE) | STATE_RUNNING;
            pcsr0 |= PCSR0_DNI;
            rxnext = 0;
            txnext = 0;
        } else {
            pcsr0 |= PCSR0_PCEI;
        }
        break;
    case CMD_HALT:
        if (state == STATE_READY || state == STATE_RUNNING) {
            pcsr1 = (pcsr1 & ~PCSR1_STATE) | STATE_HALT;
            pcsr0 |= PCSR0_DNI;
        } else {
            pcsr0 |= PCSR0_PCEI;
        }
        break;
    case CMD_STOP:
        if (state == STATE_RUNNING) {
            pcsr1 = (pcsr1 & ~PCSR1_STATE) | STATE_READY;
            pcsr0 |= PCSR0_DNI;
        } else {
            pcsr0 |= PCSR0_PCEI;
        }
        break;
    case CMD_BOOT: {
        uint32_t boot_addr = (static_cast<uint32_t>(pcsr3) << 16) | (pcsr2 & 0177776);
        if (!process_bootrom(boot_addr))
            pcsr0 |= PCSR0_PCEI;
        else
            pcsr0 |= PCSR0_DNI;
        break;
    }
    case CMD_NOOP:
        break;
    default:
        pcsr0 |= PCSR0_DNI;
        break;
    }

    pcsr0 &= ~PCSR0_PCMD;
}

bool deuna_c::execute_command(void)
{
    if (pcbb == 0 || !addr_in_ram(pcbb, 8))
        return false;

    if (!dma_read_words(pcbb, pcb, 4))
        return false;

    if (pcb[0] & 0177400)
        return false;

    uint16_t fnc = pcb[0] & 0377;
    uint32_t udbb = 0;

    auto get_udb_addr = [&](uint32_t &out, size_t bytes) -> bool {
        if ((pcb[1] & 1) || (pcb[2] & 0374))
            return false;
        out = make_addr(pcb[2], pcb[1] & 0177776);
        if (out == 0)
            return false;
        return addr_in_ram(out, bytes);
    };

    switch (fnc) {
    case FC_NOOP:
        break;
    case FC_RDPA:
        if (!dma_write_bytes(pcbb + 2, mac_addr, 6))
            return false;
        break;
    case FC_RPA:
        if (mac_is_zero(setup.macs[0])) {
            if (!dma_write_bytes(pcbb + 2, mac_addr, 6))
                return false;
        } else if (!dma_write_bytes(pcbb + 2, setup.macs[0], 6)) {
            return false;
        }
        break;
    case FC_WPA: {
        uint8_t tmp[6] = {0};
        if (!dma_read_bytes(pcbb + 2, tmp, 6))
            return false;
        if (mac_override || mac_is_zero(tmp))
            memcpy(setup.macs[0], mac_addr, sizeof(mac_addr));
        else
            memcpy(setup.macs[0], tmp, sizeof(tmp));
        setup.valid = true;
        setup.mac_count = 1;
        update_pcap_filter();
        break;
    }
    case FC_RMAL: {
        int mtlen = (pcb[2] & 0xFF00) >> 8;
        if (mtlen > 10)
            return false;
        if (!get_udb_addr(udbb, static_cast<size_t>(mtlen) * 6))
            return false;
        if (!dma_write_bytes(udbb, reinterpret_cast<const uint8_t*>(&setup.macs[2]), mtlen * 6))
            return false;
        break;
    }
    case FC_WMAL: {
        int mtlen = (pcb[2] & 0xFF00) >> 8;
        if (mtlen > 10)
            return false;
        if (!get_udb_addr(udbb, static_cast<size_t>(mtlen) * 6))
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
        if (!get_udb_addr(udbb, 12))
            return false;
        if (!dma_write_words(udbb, udb, 6))
            return false;
        break;
    case FC_WRF: {
        if ((pcb[1] & 1) || (pcb[2] & 0374))
            return false;
        if ((pcsr1 & PCSR1_STATE) == STATE_RUNNING)
            return false;
        if (!get_udb_addr(udbb, 12))
            return false;
        if (!dma_read_words(udbb, udb, 6))
            return false;
        if ((udb[0] & 1) || (udb[1] & 0374) || (udb[3] & 1) || (udb[4] & 0374) || (udb[5] < 2))
            return false;
        uint32_t new_tdrb = ((udb[1] & 3) << 16) + (udb[0] & 0177776);
        uint32_t new_telen = (udb[1] >> 8) & 0377;
        uint32_t new_trlen = udb[2];
        uint32_t new_rdrb = ((udb[4] & 3) << 16) + (udb[3] & 0177776);
        uint32_t new_relen = (udb[4] >> 8) & 0377;
        uint32_t new_rrlen = udb[5];
        if (!deuna_desc_words_supported(new_telen) || !deuna_desc_words_supported(new_relen))
            return false;
        auto ring_fits = [&](uint32_t base, uint32_t entry_words, uint32_t count) -> bool {
            if (entry_words == 0 || count == 0)
                return false;
            uint64_t bytes = static_cast<uint64_t>(entry_words) * 2u * count;
            if (!addr_in_ram(base, bytes))
                return false;
            if (qunibus && qunibus->iopage_start_addr && base + bytes > qunibus->iopage_start_addr)
                return false;
            return true;
        };
        if (!ring_fits(new_tdrb, new_telen, new_trlen) ||
            !ring_fits(new_rdrb, new_relen, new_rrlen))
            return false;
        tdrb = new_tdrb;
        telen = new_telen;
        trlen = new_trlen;
        rdrb = new_rdrb;
        relen = new_relen;
        rrlen = new_rrlen;
        rxnext = 0;
        txnext = 0;
        break;
    }
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
        if (!get_udb_addr(udbb, 68u * 2u))
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
        if (!get_udb_addr(udbb, 52u * 2u))
            return false;
        if (!dma_write_words(udbb, udb, 52))
            return false;
        break;
    }
    case FC_WSID: {
        uint16_t pltlen = pcb[3];
        if (pltlen == 0 || pltlen > DEUNA_UDB_WORDS)
            return false;
        if (!get_udb_addr(udbb, static_cast<size_t>(pltlen) * 2u))
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
        if (get_udb_addr(udbb, 8)) {
            if (!load_system_microcode(udbb))
                return false;
        } else {
            if (!load_system_microcode(0))
                return false;
        }
        break;
    case FC_DIM:
        if (!get_udb_addr(udbb, 8))
            return false;
        if (!transfer_internal_memory(udbb, false))
            return false;
        break;
    case FC_LIM:
        if (!get_udb_addr(udbb, 8))
            return false;
        if (!transfer_internal_memory(udbb, true))
            return false;
        break;
    default:
        return false;
    }

    return true;
}

void deuna_c::enqueue_readq(const uint8_t *data, size_t len, bool loopback)
{
    if (!data || len == 0)
        return;

    if (len > ETH_MAX_PACKET)
        len = ETH_MAX_PACKET;

    queue_item item;
    item.loopback = loopback;
    item.packet.msg.assign(data, data + len);
    item.packet.len = item.packet.msg.size();
    item.packet.used = 0;
    item.packet.crc_len = item.packet.len;

    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        read_queue.push_back(std::move(item));
        if (read_queue.size() > UNA_QUE_MAX) {
            read_queue.pop_front();
            read_queue_loss++;
        }
    }
}

bool deuna_c::accept_packet(const uint8_t *data, size_t len) const
{
    if (!data || len < 6)
        return false;

    const bool loopback = (mode & MODE_LOOP) != 0 || (mode & MODE_INTL) != 0;
    if (!loopback && len >= 12) {
        const uint8_t *src = data + 6;
        if (!mac_is_zero(mac_addr) && mac_equal(src, mac_addr))
            return false;
        if (!mac_is_zero(setup.macs[0]) && mac_equal(src, setup.macs[0]))
            return false;
    }

    if (setup.promiscuous)
        return true;

    const uint8_t *dst = data;
    if (!mac_is_zero(mac_addr) && mac_equal(dst, mac_addr))
        return true;
    if (!mac_is_zero(setup.macs[0]) && mac_equal(dst, setup.macs[0]))
        return true;
    if (mac_is_broadcast(dst))
        return true;
    if (mac_is_multicast(dst) && setup.multicast)
        return true;

    for (int i = 2; i < DEUNA_FILTER_MAX; ++i) {
        if (!mac_is_zero(setup.macs[i]) && mac_equal(dst, setup.macs[i]))
            return true;
    }

    return false;
}

void deuna_c::update_pcap_filter(void)
{
#ifdef HAVE_PCAP
    if (!pcap.is_open())
        return;

    const uint8_t *phys = !mac_is_zero(mac_addr) ? mac_addr : nullptr;
    const uint8_t *virt = (!mac_is_zero(setup.macs[0])) ? setup.macs[0] : nullptr;

    char srcbuf[160] = {0};
    if (phys && virt && !mac_equal(phys, virt)) {
        snprintf(srcbuf, sizeof(srcbuf),
                 "not (ether src %02x:%02x:%02x:%02x:%02x:%02x or ether src %02x:%02x:%02x:%02x:%02x:%02x)",
                 phys[0], phys[1], phys[2], phys[3], phys[4], phys[5],
                 virt[0], virt[1], virt[2], virt[3], virt[4], virt[5]);
    } else if (phys || virt) {
        const uint8_t *src = phys ? phys : virt;
        snprintf(srcbuf, sizeof(srcbuf), "not ether src %02x:%02x:%02x:%02x:%02x:%02x",
                 src[0], src[1], src[2], src[3], src[4], src[5]);
    }
    const bool have_src_excl = srcbuf[0] != '\0';

    if (setup.promiscuous) {
        std::string filter = "ip or not ip";
        if (have_src_excl)
            filter = std::string(srcbuf) + " and (" + filter + ")";
        if (!pcap.set_filter(filter))
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
        if (!mac_bytes)
            return;
        char buf[64];
        snprintf(buf, sizeof(buf), "ether dst %02x:%02x:%02x:%02x:%02x:%02x",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2],
                 mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        append_term(buf);
    };

    append_term("ether broadcast");
    if (setup.multicast)
        append_term("ether multicast");

    add_mac(phys);
    if (virt && (!phys || !mac_equal(virt, phys)))
        add_mac(virt);
    for (int i = 2; i < DEUNA_FILTER_MAX; ++i) {
        if (!mac_is_zero(setup.macs[i]))
            add_mac(setup.macs[i]);
    }

    if (filter.empty())
        filter = "ip or not ip";

    if (have_src_excl)
        filter = "(" + filter + ") and " + std::string(srcbuf);

    if (!pcap.set_filter(filter))
        WARNING("DEUNA: pcap filter set failed: %s", pcap.last_error().c_str());
#endif
}

bool deuna_c::process_receive(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if ((pcsr1 & PCSR1_STATE) != STATE_RUNNING)
        return false;

    if (rrlen == 0 || relen < DEUNA_DESC_WORDS)
        return false;
    if (!deuna_desc_words_supported(relen)) {
        stat |= STAT_ERRS | STAT_RRNG;
        pcsr0 |= PCSR0_SERI;
        update_intr();
        return false;
    }

    {
        std::lock_guard<std::mutex> qlock(queue_mutex);
        if (read_queue_loss) {
            stats.rlossl += read_queue_loss;
            read_queue_loss = 0;
            stat_rx_errors.value = stats.rlossl;
        }
    }

    unsigned limit = rx_slots.value ? rx_slots.value : rrlen;
    unsigned processed = 0;
    queue_item current;
    bool have_item = false;

    while (processed < limit) {
        if (!have_item) {
            std::lock_guard<std::mutex> qlock(queue_mutex);
            if (read_queue.empty())
                break;
            current = std::move(read_queue.front());
            read_queue.pop_front();
            have_item = true;
        }

        uint32_t desc_addr = rdrb + (relen * 2) * rxnext;
        std::vector<uint16_t> desc(relen, 0);
        if (!desc_read_words(desc_addr, desc.data(), relen)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_RRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }

        if (!(desc[2] & RXR_OWN)) {
            pcsr0 |= PCSR0_RCBI;
            break;
        }
        pcsr0 &= ~PCSR0_RCBI;

        const bool first = (current.packet.used == 0);
        if (first && current.packet.len < ETH_MIN_PACKET) {
            size_t pad = ETH_MIN_PACKET - current.packet.len;
            current.packet.msg.resize(ETH_MIN_PACKET, 0);
            current.packet.len = ETH_MIN_PACKET;
            current.packet.crc_len = current.packet.len;
            (void)pad;
        }

        const size_t remaining = current.packet.len - current.packet.used;
        size_t wlen = remaining;
        const uint16_t slen = desc[0];
        if (wlen > slen)
            wlen = slen;

        uint32_t segb = make_addr(desc[2], desc[1]);
        if (wlen) {
            if (!dma_write_bytes(segb, &current.packet.msg[current.packet.used], wlen)) {
                stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_RRNG;
                pcsr0 |= PCSR0_SERI;
                break;
            }
        }

        current.packet.used += wlen;

        desc[2] &= ~(RXR_ERRS | RXR_FRAM | RXR_OFLO | RXR_CRC | RXR_STF | RXR_ENF);
        desc[3] &= ~(RXR_BUFL | RXR_UBTO | RXR_NCHN | RXR_OVRN | RXR_MLEN);

        if (first)
            desc[2] |= RXR_STF;

        const bool chain_disabled = (mode & MODE_DRDC) != 0;
        bool end = (current.packet.used >= current.packet.len) || chain_disabled;
        if (end) {
            desc[2] |= RXR_ENF;
            if (chain_disabled)
                desc[3] |= RXR_NCHN;
        }

        if (chain_disabled && current.packet.used < current.packet.len) {
            desc[2] |= RXR_OFLO | RXR_ERRS;
            stats.frecve++;
            stats.rxerf |= RXR_OFLO;
            stat_rx_errors.value = stats.rxerf;
        }

        desc[3] |= static_cast<uint16_t>(current.packet.len) & RXR_MLEN;

        if (end) {
            stats.frecv++;
            if (current.packet.len >= 14)
                stats.rbytes += static_cast<uint32_t>(current.packet.len - 14);
            if (current.packet.msg[0] & 1) {
                stats.mfrecv++;
                if (current.packet.len >= 14)
                    stats.mrbytes += static_cast<uint32_t>(current.packet.len - 14);
            }
            stat_rx_frames.value = stats.frecv;
            pcsr0 |= PCSR0_RXI;
        }

        desc[2] &= ~RXR_OWN;
        if (!desc_write_words(desc_addr, desc.data(), relen)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_RRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }

        rxnext = (rxnext + 1) % rrlen;
        processed++;

        if (end) {
            if (current.packet.used < current.packet.len)
                stats.rlossi++;
            have_item = false;
        }
    }

    update_intr();
    return processed > 0;
}

bool deuna_c::process_transmit(unsigned max_descriptors)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if ((pcsr1 & PCSR1_STATE) != STATE_RUNNING)
        return false;

    if (trlen == 0 || telen < DEUNA_DESC_WORDS)
        return false;
    if (!deuna_desc_words_supported(telen)) {
        stat |= STAT_ERRS | STAT_TRNG;
        pcsr0 |= PCSR0_SERI;
        update_intr();
        return false;
    }

    unsigned limit = max_descriptors ? max_descriptors : (tx_slots.value ? tx_slots.value : trlen);
    unsigned processed = 0;

    while (processed < limit) {
        uint32_t desc_addr = tdrb + (telen * 2) * txnext;
        std::vector<uint16_t> desc(telen, 0);
        if (!desc_read_words(desc_addr, desc.data(), telen)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_TRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }

        if (!(desc[2] & TXR_OWN))
            break;

        const uint16_t slen = desc[0];
        uint32_t segb = make_addr(desc[2], desc[1]);

        if (desc[2] & TXR_STF) {
            write_buffer.len = 0;
            write_buffer.used = 0;
            write_buffer.status = 0;
        }

        size_t wlen = slen;
        bool giant = false;
        if (write_buffer.len + wlen > ETH_MAX_PACKET) {
            wlen = ETH_MAX_PACKET - write_buffer.len;
            giant = true;
        }

        if (wlen) {
            if (!dma_read_bytes(segb, &write_buffer.msg[write_buffer.len], wlen)) {
                stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_TRNG;
                pcsr0 |= PCSR0_SERI;
                break;
            }
        }
        write_buffer.len += wlen;

        desc[2] &= ~(TXR_ERRS | TXR_MTCH | TXR_MORE | TXR_ONE | TXR_DEF);
        desc[3] &= ~(TXR_BUFL | TXR_UBTO | TXR_UFLO | TXR_LCOL | TXR_LCAR | TXR_RTRY | TXR_TDR);

        if (desc[2] & TXR_ENF) {
            bool runt = false;
            if (write_buffer.len < ETH_MIN_PACKET) {
                size_t pad = ETH_MIN_PACKET - write_buffer.len;
                memset(&write_buffer.msg[write_buffer.len], 0, pad);
                write_buffer.len = ETH_MIN_PACKET;
                if ((mode & MODE_TPAD) == 0)
                    runt = true;
            }

            const uint8_t *src_mac = !mac_is_zero(setup.macs[0]) ? setup.macs[0] : mac_addr;
            memcpy(write_buffer.msg.data() + 6, src_mac, 6);

            const bool loopback = (mode & MODE_LOOP) != 0 || (mode & MODE_INTL) != 0;
            if (loopback) {
                enqueue_readq(write_buffer.msg.data(), write_buffer.len, true);
            } else {
                if (!pcap.send(write_buffer.msg.data(), write_buffer.len))
                    write_buffer.status = 1;
            }

            if (write_buffer.status != 0) {
                const uint16_t tdr = static_cast<uint16_t>(100 + wlen * 8);
                desc[3] |= TXR_RTRY | (tdr & TXR_TDR);
                desc[2] |= TXR_ERRS;
                stats.txerf |= TXR_RTRY;
                stat_tx_errors.value = stats.txerf;
            }

            if (giant || runt) {
                desc[3] |= TXR_BUFL;
                desc[2] |= TXR_ERRS;
                stats.txerf |= TXR_BUFL;
                stat_tx_errors.value = stats.txerf;
            }

            const uint8_t *dst = write_buffer.msg.data();
            if (!mac_is_zero(mac_addr) && mac_equal(dst, mac_addr))
                desc[2] |= TXR_MTCH;
            if (!mac_is_zero(setup.macs[0]) && mac_equal(dst, setup.macs[0]))
                desc[2] |= TXR_MTCH;
            for (int i = 2; i < DEUNA_FILTER_MAX; ++i) {
                if (!mac_is_zero(setup.macs[i]) && mac_equal(dst, setup.macs[i]))
                    desc[2] |= TXR_MTCH;
            }

            pcsr0 |= PCSR0_TXI;
            stats.ftrans++;
            if (write_buffer.len >= 14)
                stats.tbytes += static_cast<uint32_t>(write_buffer.len - 14);
            if (dst[0] & 1) {
                stats.mftrans++;
                if (write_buffer.len >= 14)
                    stats.mtbytes += static_cast<uint32_t>(write_buffer.len - 14);
            }
            stat_tx_frames.value = stats.ftrans;
        }

        desc[2] &= ~TXR_OWN;
        if (!desc_write_words(desc_addr, desc.data(), telen)) {
            pcsr0 |= PCSR0_PCEI;
            stats.ftransa++;
            break;
        }

        txnext = (txnext + 1) % trlen;
        processed++;
    }

    update_intr();
    return processed > 0;
}

void deuna_c::dump_tx_ring(unsigned max_entries)
{
    if (trlen == 0 || telen < DEUNA_DESC_WORDS)
        return;

    unsigned count = std::min(max_entries, trlen);
    for (unsigned i = 0; i < count; ++i) {
        uint32_t desc_addr = tdrb + (telen * 2) * i;
        std::vector<uint16_t> words(telen, 0);
        if (!desc_read_words(desc_addr, words.data(), telen))
            continue;
        if (telen >= 5) {
            WARNING("DEUNA: TX ring[%u] addr=%08o w0=%06o w1=%06o w2=%06o w3=%06o w4=%06o",
                    i, desc_addr, words[0], words[1], words[2], words[3], words[4]);
        } else {
            WARNING("DEUNA: TX ring[%u] addr=%08o w0=%06o w1=%06o w2=%06o w3=%06o",
                    i, desc_addr, words[0], words[1], words[2], words[3]);
        }
    }
}

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

void deuna_c::worker(unsigned instance)
{
    if (trace.value)
        WARNING("DEUNA: %s worker(%u) start", DEUNA_VERSION, instance);
    if (instance == 0)
        worker_rx();
    else
        worker_tx();
}

void deuna_c::worker_rx(void)
{
    worker_init_realtime_priority(rt_device);

    uint8_t pkt_buf[2048];
    while (!workers_terminate) {
        if (reset_in_progress.load(std::memory_order_acquire)) {
            timeout_c::wait_ms(1);
            continue;
        }
        service_timers();
        apply_pending_reg_writes();
        process_pending_command();

        if (init_asserted || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

#ifdef HAVE_PCAP
        bool running = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            running = ((pcsr1 & PCSR1_STATE) == STATE_RUNNING);
        }
        if (pcap.is_open() && running) {
            size_t len = 0;
            if (!pcap.poll(pkt_buf, sizeof(pkt_buf), &len)) {
                WARNING("DEUNA: pcap poll error: %s", pcap.last_error().c_str());
                timeout_c::wait_ms(10);
                continue;
            }
            if (len > 0) {
                bool should_accept = false;
                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    should_accept = accept_packet(pkt_buf, len);
                }
                if (should_accept)
                    enqueue_readq(pkt_buf, len, false);
            }
        }
#endif

        process_receive();
        timeout_c::wait_ms(1);
    }
}

void deuna_c::worker_tx(void)
{
    worker_init_realtime_priority(rt_device);

    while (!workers_terminate) {
        if (reset_in_progress.load(std::memory_order_acquire)) {
            timeout_c::wait_ms(1);
            continue;
        }
        apply_pending_reg_writes();
        process_pending_command();

        if (init_asserted || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        process_transmit(0);
        timeout_c::wait_ms(1);
    }
}
