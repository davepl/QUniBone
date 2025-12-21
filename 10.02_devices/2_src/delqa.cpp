/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2025 Plummer's Software LLC
 * Contributed under the GPL2 License
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
#include "delqa.hpp"
#include "ring_lance.h"

#if !defined(QBUS)
#error "DELQA is a QBUS-only device"
#endif

// Maximum Ethernet frame size (excluding preamble/CRC added by hardware)
static const size_t DELQA_MAX_FRAME_SIZE = 1518;

static uint8_t word_low(uint16_t w)
{
    return static_cast<uint8_t>(w & 0xff);
}

static uint8_t word_high(uint16_t w)
{
    return static_cast<uint8_t>((w >> 8) & 0xff);
}

delqa_c::delqa_c() : qunibusdevice_c()
{
    set_workers_count(2);

    name.value = "delqa";
    type_name.value = "DELQA";
    log_label = "delqa";

    set_default_bus_params(DELQA_DEFAULT_ADDR, DELQA_DEFAULT_SLOT, DELQA_DEFAULT_VECTOR,
            DELQA_DEFAULT_LEVEL);

    register_count = 3;

    reg_rdp = &(this->registers[0]);
    strcpy(reg_rdp->name, "RDP");
    reg_rdp->active_on_dati = false;
    reg_rdp->active_on_dato = true;
    reg_rdp->reset_value = 0;
    reg_rdp->writable_bits = 0xffff;

    reg_rap = &(this->registers[1]);
    strcpy(reg_rap->name, "RAP");
    reg_rap->active_on_dati = false;
    reg_rap->active_on_dato = true;
    reg_rap->reset_value = 0;
    reg_rap->writable_bits = 0xffff;

    reg_rst = &(this->registers[2]);
    strcpy(reg_rst->name, "RST");
    reg_rst->active_on_dati = false;
    reg_rst->active_on_dato = true;
    reg_rst->reset_value = 0;
    reg_rst->writable_bits = 0xffff;

    ifname.value = "eth0";
    mac.value = "";
    promisc.value = true;
    rx_slots.value = 32;
    tx_slots.value = 32;
    trace.value = false;

    reset_controller();
}

delqa_c::~delqa_c()
{
#ifdef HAVE_PCAP
    pcap.close();
#endif
}

bool delqa_c::is_power_of_two(unsigned val)
{
    return val && ((val & (val - 1)) == 0);
}

bool delqa_c::parse_mac(const std::string &text, uint8_t out[6])
{
    unsigned values[6];
    if (text.empty())
        return false;
    if (sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) != 6)
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
    } else if (param == &mac) {
        if (mac.new_value.empty()) {
            mac_override = false;
            memset(mac_addr, 0, sizeof(mac_addr));
        } else if (!parse_mac(mac.new_value, mac_addr)) {
            ERROR("DELQA: invalid MAC format '%s'", mac.new_value.c_str());
            return false;
        } else {
            mac_override = true;
        }
    } else if (param == &rx_slots) {
        unsigned val = rx_slots.new_value;
        if (val != 0 && !is_power_of_two(val)) {
            ERROR("DELQA: rx_slots must be power-of-two or 0 (auto)");
            return false;
        }
    } else if (param == &tx_slots) {
        unsigned val = tx_slots.new_value;
        if (val != 0 && !is_power_of_two(val)) {
            ERROR("DELQA: tx_slots must be power-of-two or 0 (auto)");
            return false;
        }
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

    ifname.readonly = true;
    mac.readonly = true;
    promisc.readonly = true;
    rx_slots.readonly = true;
    tx_slots.readonly = true;

    return true;
#endif
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

void delqa_c::reset_controller(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    csr_sel = 0;
    csr0 = DELQA_CSR0_STOP;
    csr1 = 0;
    csr2 = 0;
    csr3 = 0;

    rx_ring.base_addr = 0;
    rx_ring.slots = 0;
    rx_ring.index = 0;
    tx_ring.base_addr = 0;
    tx_ring.slots = 0;
    tx_ring.index = 0;

    started = false;
    init_done = false;

    // Reset statistics
    rx_frames = 0;
    tx_frames = 0;
    rx_errors = 0;
    tx_errors = 0;
    stat_rx_frames.value = 0;
    stat_tx_frames.value = 0;
    stat_rx_errors.value = 0;
    stat_tx_errors.value = 0;

    intr_request.edge_detect_reset();

    if (handle) {
        reset_unibus_registers();
        update_rdp();
        update_rap();
        update_intr();
    }
}

void delqa_c::update_rdp(void)
{
    if (!handle)
        return;

    uint16_t val = 0;
    switch (csr_sel & 0x3) {
    case 0:
        val = csr0;
        break;
    case 1:
        val = csr1;
        break;
    case 2:
        val = csr2;
        break;
    case 3:
        val = csr3;
        break;
    default:
        val = 0;
        break;
    }

    set_register_dati_value(reg_rdp, val, "update_rdp");
}

void delqa_c::update_rap(void)
{
    if (!handle)
        return;
    set_register_dati_value(reg_rap, csr_sel & 0x3, "update_rap");
}

bool delqa_c::get_intr_level(void) const
{
    if (!(csr0 & DELQA_CSR0_INEA))
        return false;
    return (csr0 & (DELQA_CSR0_IDON | DELQA_CSR0_TINT | DELQA_CSR0_RINT | DELQA_CSR0_ERR));
}

void delqa_c::update_intr(void)
{
    bool level = get_intr_level();

    if (level)
        csr0 |= DELQA_CSR0_INTR;
    else
        csr0 &= ~DELQA_CSR0_INTR;

    switch (intr_request.edge_detect(level)) {
    case intr_request_c::INTERRUPT_EDGE_RAISING:
        qunibusadapter->INTR(intr_request, nullptr, 0);
        break;
    case intr_request_c::INTERRUPT_EDGE_FALLING:
        qunibusadapter->cancel_INTR(intr_request);
        break;
    default:
        break;
    }
}

void delqa_c::handle_stop(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    started = false;
    csr0 &= ~(DELQA_CSR0_STRT | DELQA_CSR0_INIT | DELQA_CSR0_TDMD | DELQA_CSR0_RXON | DELQA_CSR0_TXON);
    csr0 |= DELQA_CSR0_STOP;
    csr0 &= ~(DELQA_CSR0_IDON | DELQA_CSR0_TINT | DELQA_CSR0_RINT | DELQA_CSR0_ERR | DELQA_CSR0_INTR);

    update_intr();
    update_rdp();
}

void delqa_c::handle_start(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!init_done) {
        csr0 |= DELQA_CSR0_ERR;
        update_intr();
        update_rdp();
        return;
    }

    started = true;
    csr0 &= ~(DELQA_CSR0_STOP | DELQA_CSR0_INIT | DELQA_CSR0_TDMD);
    csr0 |= (DELQA_CSR0_STRT | DELQA_CSR0_RXON | DELQA_CSR0_TXON);

    update_intr();
    update_rdp();
}

void delqa_c::handle_init(void)
{
    uint16_t init_words[12];
    uint32_t init_addr;
    uint16_t csr1_local = 0;
    uint16_t csr2_local = 0;

    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        started = false;
        init_done = false;
        csr0 &= ~(DELQA_CSR0_STRT | DELQA_CSR0_TDMD | DELQA_CSR0_RXON | DELQA_CSR0_TXON | DELQA_CSR0_INTR);
        csr0 |= DELQA_CSR0_INIT;
        csr1_local = csr1;
        csr2_local = csr2;
    }

    init_addr = (static_cast<uint32_t>(csr2_local) << 16) | csr1_local;
    init_addr <<= 1; // word to byte address

    if (!dma_read_words(init_addr, init_words, 12)) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr0 |= DELQA_CSR0_ERR;
        update_intr();
        update_rdp();
        return;
    }

    qe_init_block_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.mode = init_words[0];
    blk.padr[0] = init_words[1];
    blk.padr[1] = init_words[2];
    blk.padr[2] = init_words[3];
    blk.ladr[0] = init_words[4];
    blk.ladr[1] = init_words[5];
    blk.ladr[2] = init_words[6];
    blk.ladr[3] = init_words[7];
    blk.rrd_lo = init_words[8];
    blk.rrd_hi = init_words[9];
    blk.trd_lo = init_words[10];
    blk.trd_hi = init_words[11];

    uint8_t init_mac[6];
    init_mac[0] = word_low(blk.padr[0]);
    init_mac[1] = word_high(blk.padr[0]);
    init_mac[2] = word_low(blk.padr[1]);
    init_mac[3] = word_high(blk.padr[1]);
    init_mac[4] = word_low(blk.padr[2]);
    init_mac[5] = word_high(blk.padr[2]);

    if (!mac_override) {
        memcpy(mac_addr, init_mac, sizeof(mac_addr));
    }

    uint16_t rlen_code = (blk.rrd_hi >> 13) & 0x7;
    uint16_t tlen_code = (blk.trd_hi >> 13) & 0x7;
    uint16_t rx_count = static_cast<uint16_t>(1u << (rlen_code + 1));
    uint16_t tx_count = static_cast<uint16_t>(1u << (tlen_code + 1));

    if (rx_slots.value != 0 && rx_slots.value != rx_count) {
        WARNING("DELQA: init RX ring size %u differs from config %u", rx_count, rx_slots.value);
        rx_count = rx_slots.value;
    }
    if (tx_slots.value != 0 && tx_slots.value != tx_count) {
        WARNING("DELQA: init TX ring size %u differs from config %u", tx_count, tx_slots.value);
        tx_count = tx_slots.value;
    }

    uint32_t rx_addr = (static_cast<uint32_t>(blk.rrd_hi & DELQA_DESC_ADDR_HI_MASK) << 16) | blk.rrd_lo;
    uint32_t tx_addr = (static_cast<uint32_t>(blk.trd_hi & DELQA_DESC_ADDR_HI_MASK) << 16) | blk.trd_lo;
    rx_addr <<= 1;
    tx_addr <<= 1;

    if ((rx_addr + static_cast<uint32_t>(rx_count) * DELQA_DESC_BYTES > qunibus->addr_space_byte_count)
            || (tx_addr + static_cast<uint32_t>(tx_count) * DELQA_DESC_BYTES
                > qunibus->addr_space_byte_count)) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr0 |= DELQA_CSR0_ERR;
        update_intr();
        update_rdp();
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);

        rx_ring.base_addr = rx_addr;
        rx_ring.slots = rx_count;
        rx_ring.index = 0;

        tx_ring.base_addr = tx_addr;
        tx_ring.slots = tx_count;
        tx_ring.index = 0;

        init_done = true;
        csr0 &= ~DELQA_CSR0_INIT;
        csr0 |= DELQA_CSR0_IDON;

        update_intr();
        update_rdp();
    }

    if (trace.value) {
        INFO("DELQA: init MAC %02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1],
             mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
        INFO("DELQA: rx ring @ %s slots=%u, tx ring @ %s slots=%u", qunibus->addr2text(rx_addr),
             rx_count, qunibus->addr2text(tx_addr), tx_count);
    }
}

void delqa_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    UNUSED(access);
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    switch (device_reg->index) {
    case 0: { // RDP
        uint16_t val = get_register_dato_value(reg_rdp);
        if ((csr_sel & 0x3) == 0) {
            if (trace.value) {
                INFO("DELQA: CSR0 write %06o", val);
            }
            if (val & DELQA_CSR0_STOP)
                handle_stop();
            if (val & DELQA_CSR0_INIT)
                handle_init();
            if (val & DELQA_CSR0_STRT)
                handle_start();

            if (val & DELQA_CSR0_INEA)
                csr0 |= DELQA_CSR0_INEA;
            else
                csr0 &= ~DELQA_CSR0_INEA;

            csr0 &= ~(val & DELQA_CSR0_CLEAR_BITS);

            update_intr();
            update_rdp();
        } else if ((csr_sel & 0x3) == 1) {
            csr1 = val;
            update_rdp();
        } else if ((csr_sel & 0x3) == 2) {
            csr2 = val;
            update_rdp();
        } else if ((csr_sel & 0x3) == 3) {
            csr3 = val;
            update_rdp();
        }
        break;
    }
    case 1: { // RAP
        uint16_t val = get_register_dato_value(reg_rap);
        csr_sel = val & 0x3;
        update_rap();
        update_rdp();
        break;
    }
    case 2: // RST
        handle_stop();
        reset_controller();
        break;
    default:
        break;
    }
}

bool delqa_c::dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;
    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
    return dma_request.success;
}

bool delqa_c::dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;
    if (addr + wordcount * 2 > qunibus->addr_space_byte_count)
        return false;

    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATO, addr,
            const_cast<uint16_t *>(buffer), wordcount);
    return dma_request.success;
}

bool delqa_c::dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;
    if (addr + len > qunibus->addr_space_byte_count)
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

bool delqa_c::dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len)
{
    if (len == 0)
        return true;
    if (addr + len > qunibus->addr_space_byte_count)
        return false;

    size_t full_words = len / 2;
    if (full_words) {
        std::vector<uint16_t> words(full_words);
        for (size_t i = 0; i < full_words; ++i) {
            words[i] = static_cast<uint16_t>(buffer[2 * i])
                    | static_cast<uint16_t>(buffer[2 * i + 1] << 8);
        }
        if (!dma_write_words(addr, words.data(), full_words))
            return false;
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

bool delqa_c::read_descriptor(uint32_t addr, uint16_t words[DELQA_DESC_WORDS])
{
    return dma_read_words(addr, words, DELQA_DESC_WORDS);
}

bool delqa_c::write_descriptor(uint32_t addr, const uint16_t words[DELQA_DESC_WORDS])
{
    return dma_write_words(addr, words, DELQA_DESC_WORDS);
}

bool delqa_c::rx_place_frame(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (!started || !init_done || rx_ring.slots == 0)
        return false;

    uint16_t slots = rx_ring.slots;
    uint16_t mask = slots - 1;

    for (uint16_t i = 0; i < slots; ++i) {
        uint16_t idx = (rx_ring.index + i) & mask;
        uint32_t desc_addr = rx_ring.base_addr + static_cast<uint32_t>(idx) * DELQA_DESC_BYTES;
        uint16_t words[DELQA_DESC_WORDS];
        if (!read_descriptor(desc_addr, words)) {
            csr0 |= DELQA_CSR0_ERR | DELQA_CSR0_RINT;
            update_intr();
            update_rdp();
            return false;
        }

        if (!(words[1] & DELQA_DESC_OWN))
            continue;

        uint32_t buf_addr = (static_cast<uint32_t>(words[1] & DELQA_DESC_ADDR_HI_MASK) << 16)
                | words[0];
        buf_addr <<= 1;
        uint16_t buf_len = static_cast<uint16_t>(-static_cast<int16_t>(words[2]));
        buf_len &= 0x0fff;

        bool error = false;
        if (buf_len == 0 || len > buf_len) {
            error = true;
        } else if (!dma_write_bytes(buf_addr, data, len)) {
            error = true;
        }

        uint16_t addr_bits = words[1] & DELQA_DESC_ADDR_HI_MASK;
        uint16_t new_w1 = addr_bits | DELQA_DESC_STP | DELQA_DESC_ENP;
        if (error)
            new_w1 |= DELQA_DESC_ERR | DELQA_DESC_BUF;
        words[1] = new_w1;
        words[3] = error ? 0 : static_cast<uint16_t>(len);

        if (!write_descriptor(desc_addr, words)) {
            csr0 |= DELQA_CSR0_ERR;
            error = true;
        }

        rx_ring.index = (idx + 1) & mask;

        csr0 |= DELQA_CSR0_RINT;
        if (error) {
            csr0 |= DELQA_CSR0_ERR;
            rx_errors++;
            stat_rx_errors.value = rx_errors;
        } else {
            rx_frames++;
            stat_rx_frames.value = rx_frames;
        }

        update_intr();
        update_rdp();

        if (trace.value) {
            INFO("DELQA: RX desc %u len=%u %s", idx, static_cast<unsigned>(len),
                 error ? "error" : "ok");
        }
        return !error;
    }

    rx_errors++;
    stat_rx_errors.value = rx_errors;
    csr0 |= DELQA_CSR0_ERR | DELQA_CSR0_RINT;
    update_intr();
    update_rdp();
    return false;
}

bool delqa_c::tx_take_frame(std::vector<uint8_t> &frame)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (!started || !init_done || tx_ring.slots == 0)
        return false;

    uint16_t slots = tx_ring.slots;
    uint16_t mask = slots - 1;

    for (uint16_t i = 0; i < slots; ++i) {
        uint16_t idx = (tx_ring.index + i) & mask;
        uint32_t desc_addr = tx_ring.base_addr + static_cast<uint32_t>(idx) * DELQA_DESC_BYTES;
        uint16_t words[DELQA_DESC_WORDS];
        if (!read_descriptor(desc_addr, words)) {
            csr0 |= DELQA_CSR0_ERR | DELQA_CSR0_TINT;
            update_intr();
            update_rdp();
            return false;
        }

        if (!(words[1] & DELQA_DESC_OWN))
            continue;

        bool error = false;
        uint32_t buf_addr = (static_cast<uint32_t>(words[1] & DELQA_DESC_ADDR_HI_MASK) << 16)
                | words[0];
        buf_addr <<= 1;

        uint16_t len = static_cast<uint16_t>(-static_cast<int16_t>(words[2]));
        len &= 0x0fff;

        if ((words[1] & (DELQA_DESC_STP | DELQA_DESC_ENP)) != (DELQA_DESC_STP | DELQA_DESC_ENP)) {
            error = true;
        } else if (len == 0 || len > DELQA_MAX_FRAME_SIZE) {
            error = true;
        } else {
            frame.resize(len);
            if (!dma_read_bytes(buf_addr, frame.data(), len)) {
                error = true;
            }
#ifdef HAVE_PCAP
            else if (!pcap.send(frame.data(), len)) {
                error = true;
            }
#endif
        }

        uint16_t addr_bits = words[1] & (DELQA_DESC_ADDR_HI_MASK | DELQA_DESC_STP | DELQA_DESC_ENP);
        uint16_t new_w1 = addr_bits;
        if (error)
            new_w1 |= DELQA_DESC_ERR;
        words[1] = new_w1;
        words[3] = 0;

        if (!write_descriptor(desc_addr, words)) {
            csr0 |= DELQA_CSR0_ERR;
            error = true;
        }

        tx_ring.index = (idx + 1) & mask;

        csr0 |= DELQA_CSR0_TINT;
        if (error) {
            csr0 |= DELQA_CSR0_ERR;
            tx_errors++;
            stat_tx_errors.value = tx_errors;
        } else {
            tx_frames++;
            stat_tx_frames.value = tx_frames;
        }

        update_intr();
        update_rdp();

        if (trace.value) {
            INFO("DELQA: TX desc %u len=%u %s", idx, static_cast<unsigned>(len),
                 error ? "error" : "ok");
        }
        return true;
    }

    return false;
}

void delqa_c::worker(unsigned instance)
{
    if (instance == 0)
        worker_rx();
    else
        worker_tx();
}

void delqa_c::worker_rx(void)
{
#ifdef HAVE_PCAP
    worker_init_realtime_priority(rt_device);

    std::vector<uint8_t> frame(2048);

    while (!workers_terminate) {
        if (!pcap.is_open()) {
            timeout_c::wait_ms(1);
            continue;
        }
        if (!started || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        size_t len = 0;
        if (!pcap.poll(frame.data(), frame.size(), &len)) {
            WARNING("DELQA: pcap poll error: %s", pcap.last_error().c_str());
            timeout_c::wait_ms(100);  // Longer wait on error
            continue;
        }

        if (len == 0) {
            timeout_c::wait_ms(1);  // Prevent busy-waiting on timeout
            continue;
        }

        // MAC filtering: accept broadcast, multicast, or frames matching our MAC
        if (len >= 6 && !promisc.value) {
            const uint8_t *dst = frame.data();
            bool broadcast = (dst[0] == 0xff && dst[1] == 0xff && dst[2] == 0xff &&
                              dst[3] == 0xff && dst[4] == 0xff && dst[5] == 0xff);
            bool multicast = (dst[0] & 0x01) != 0;  // Multicast bit set
            bool unicast_match = (memcmp(dst, mac_addr, 6) == 0);
            if (!broadcast && !multicast && !unicast_match)
                continue;
        }

        rx_place_frame(frame.data(), len);
    }
#else
    // No pcap support - worker does nothing
    while (!workers_terminate) {
        timeout_c::wait_ms(100);
    }
#endif
}

void delqa_c::worker_tx(void)
{
#ifdef HAVE_PCAP
    worker_init_realtime_priority(rt_device);

    std::vector<uint8_t> frame(2048);

    while (!workers_terminate) {
        if (!pcap.is_open()) {
            timeout_c::wait_ms(1);
            continue;
        }
        if (!started || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        if (!tx_take_frame(frame)) {
            timeout_c::wait_ms(1);
        }
    }
#else
    // No pcap support - worker does nothing
    while (!workers_terminate) {
        timeout_c::wait_ms(100);
    }
#endif
}
