/*
 * DEUNA Ethernet Controller Emulation for QUniBone
 *
 * This is a clean-room implementation based on:
 *   - DEC DEUNA User's Guide (EK-DEUNA-UG)
 *   - UNIBUS specification
 *   - OpenSIMH pdp11_xu.c behavioral reference (no code copied)
 *
 * This file is part of the QUniBone project, licensed under GPLv2.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <algorithm>
#include <vector>

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

static bool mac_is_zero(const uint8_t *mac)
{
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

static bool mac_is_broadcast(const uint8_t *mac)
{
    return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
           mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff;
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
    mac_addr[0] = 0x08;
    mac_addr[1] = 0x00;
    mac_addr[2] = 0x2b;
    mac_addr[3] = 0xcc;
    mac_addr[4] = 0xdd;
    mac_addr[5] = 0xee;

    read_buffer.msg.reserve(XU_MAX_RCV_PACKET);
    write_buffer.msg.reserve(XU_MAX_RCV_PACKET);
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
            WARNING("DEUNA: ifname cannot be changed while device is installed");
            return false;
        }
    } else if (param == &mac) {
        if (mac.new_value.empty()) {
            mac_override = false;
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

void deuna_c::on_after_install(void)
{
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

    update_transceiver_bits();
    update_intr();
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
}

void deuna_c::update_transceiver_bits(void)
{
    if (pcap.is_open())
        pcsr1 &= ~PCSR1_XPWR;
    else
        pcsr1 |= PCSR1_XPWR;
}

void deuna_c::update_intr(void)
{
    bool any = (pcsr0 & PCSR0_W1C_MASK) != 0;
    if (any)
        pcsr0 |= PCSR0_INTR;
    else
        pcsr0 &= ~PCSR0_INTR;

    bool want = any && (pcsr0 & PCSR0_INTE);
    if (want && !irq) {
        qunibusadapter->INTR(intr_request, nullptr, 0);
        irq = true;
        if (trace.value)
            WARNING("DEUNA: INTR assert pcsr0=%06o vec=%03o level=%d", pcsr0, intr_vector.value, intr_level.value);
    } else if (!want && irq) {
        qunibusadapter->cancel_INTR(intr_request);
        irq = false;
        if (trace.value)
            WARNING("DEUNA: INTR deassert pcsr0=%06o", pcsr0);
    }

    update_pcsr_regs();
}

void deuna_c::reset_controller(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

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

    pending_reg_write write;
    write.reg_index = reg_index;
    write.value = device_reg->active_dato_flipflops;
    write.access = static_cast<uint8_t>(access);
    {
        std::lock_guard<std::mutex> lock(pending_reg_mutex);
        pending_reg_queue.push_back(write);
    }
}

void deuna_c::handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access)
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
            pcsr0 &= static_cast<uint16_t>(~(val & PCSR0_W1C_MASK));
            update_intr();
            return;
        }

        uint16_t data = val;
        if (access == DATO_BYTEL)
            data = static_cast<uint16_t>((pcsr0 & 0xff00) | (val & 0x00ff));

        if (access == DATO_WORD) {
            pcsr0 &= static_cast<uint16_t>(~(data & PCSR0_W1C_MASK));
        }

        if (data & PCSR0_RSET) {
            reset_controller();
            return;
        }

        if ((pcsr0 ^ data) & PCSR0_INTE) {
            pcsr0 ^= PCSR0_INTE;
            pcsr0 |= PCSR0_DNI;
        } else {
            pcsr0 &= ~PCSR0_PCMD;
            pcsr0 |= (data & PCSR0_PCMD);
            port_command(pcsr0 & PCSR0_PCMD);
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
            static_cast<DATO_ACCESS>(write.access));
    }
}

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

bool deuna_c::dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;

    if (addr + len > qunibus->addr_space_byte_count)
        return false;

    if ((addr & 1) == 0 && (len & 1) == 0)
        return dma_read_words(addr, reinterpret_cast<uint16_t*>(buffer), len / 2);

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

bool deuna_c::dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;

    if (addr + len > qunibus->addr_space_byte_count)
        return false;

    if ((addr & 1) == 0 && (len & 1) == 0)
        return dma_write_words(addr, reinterpret_cast<const uint16_t*>(buffer), len / 2);

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

    update_intr();
}

bool deuna_c::execute_command(void)
{
    if (!dma_read_words(pcbb, pcb, 4))
        return false;

    if (pcb[0] & 0177400)
        return false;

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
        if (!dma_write_bytes(pcbb + 2, mac_addr, 6))
            return false;
        break;
    case FC_RPA:
        if (!dma_write_bytes(pcbb + 2, setup.macs[0], 6))
            return false;
        break;
    case FC_WPA:
        if (!dma_read_bytes(pcbb + 2, setup.macs[0], 6))
            return false;
        setup.valid = true;
        if (setup.mac_count < 2)
            setup.mac_count = 2;
        update_pcap_filter();
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

bool deuna_c::accept_packet(const uint8_t *data, size_t len) const
{
    if (!data || len < 6)
        return false;

    if (promisc.value || setup.promiscuous)
        return true;

    const uint8_t *dst = data;
    if (mac_is_broadcast(dst))
        return true;

    if (mac_is_multicast(dst) && setup.multicast)
        return true;

    for (int i = 0; i < setup.mac_count; ++i) {
        if (mac_equal(dst, setup.macs[i]))
            return true;
    }

    return false;
}

void deuna_c::update_pcap_filter(void)
{
#ifdef HAVE_PCAP
    if (!pcap.is_open())
        return;

    if (promisc.value || setup.promiscuous) {
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

    add_mac(setup.macs[0]);
    if (setup.valid) {
        for (int i = 0; i < setup.mac_count; ++i) {
            if (!mac_is_zero(setup.macs[i]))
                add_mac(setup.macs[i]);
        }
    }

    if (filter.empty())
        filter = "ip or not ip";

    if (!pcap.set_filter(filter))
        WARNING("DEUNA: pcap filter set failed: %s", pcap.last_error().c_str());
#endif
}

bool deuna_c::process_receive(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if ((pcsr1 & PCSR1_STATE) != STATE_RUNNING)
        return false;

    if (read_queue.empty())
        return false;

    if (rrlen == 0 || relen == 0)
        return false;

    unsigned limit = rx_slots.value ? rx_slots.value : rrlen;
    unsigned processed = 0;
    queue_item *item = nullptr;

    while (!read_queue.empty() && (limit == 0 || processed < limit)) {
        uint32_t desc_addr = rdrb + (relen * 2) * rxnext;
        if (!desc_read_words(desc_addr, rxhdr, 4)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_RRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }

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
        if (!desc_write_words(desc_addr, rxhdr, 4)) {
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

bool deuna_c::process_transmit(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if ((pcsr1 & PCSR1_STATE) != STATE_RUNNING)
        return false;

    if (trlen == 0 || telen == 0)
        return false;

    unsigned limit = tx_slots.value ? tx_slots.value : trlen;
    unsigned processed = 0;

    bool giant = false;
    bool runt = false;

    while (limit == 0 || processed < limit) {
        uint32_t desc_addr = tdrb + (telen * 2) * txnext;
        if (!desc_read_words(desc_addr, txhdr, 4)) {
            stat |= STAT_ERRS | STAT_MERR | STAT_TMOT | STAT_TRNG;
            pcsr0 |= PCSR0_SERI;
            break;
        }

        if (!(txhdr[2] & TXR_OWN))
            break;

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

            if (write_buffer.len >= 12)
                memcpy(write_buffer.msg.data() + 6, setup.macs[0], sizeof(mac_addr));

            if ((mode & MODE_LOOP) && (mode & MODE_INTL)) {
                enqueue_readq(write_buffer.msg.data(), write_buffer.len, true);
            } else {
                if (!pcap.is_open() || !pcap.send(write_buffer.msg.data(), write_buffer.len)) {
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
        if (!desc_write_words(desc_addr, txhdr, 4)) {
            pcsr0 |= PCSR0_PCEI;
            stats.ftransa++;
            break;
        }

        txnext++;
        if (txnext >= trlen)
            txnext = 0;

        processed++;
    }

    update_intr();
    return true;
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
        service_timers();
        apply_pending_reg_writes();

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

void deuna_c::worker_tx(void)
{
    worker_init_realtime_priority(rt_device);

    while (!workers_terminate) {
        apply_pending_reg_writes();

        if (init_asserted) {
            timeout_c::wait_ms(1);
            continue;
        }

        process_transmit();
        timeout_c::wait_ms(1);
    }
}
