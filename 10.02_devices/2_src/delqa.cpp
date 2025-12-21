/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2026 Plummer's Software LLC
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

#if !defined(QBUS)
#error "DELQA is a QBUS-only device"
#endif

// Maximum Ethernet frame size (excluding preamble/CRC added by hardware)
static const size_t DELQA_MAX_FRAME_SIZE = 1518;
static const unsigned DELQA_DEFAULT_SCAN = 32;
static const unsigned DELQA_RX_START_DELAY_MS = 1;

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

    register_count = 8;

    reg_sta_addr[0] = &(this->registers[0]);
    strcpy(reg_sta_addr[0]->name, "STA0");
    reg_sta_addr[0]->active_on_dati = false;
    reg_sta_addr[0]->active_on_dato = false;
    reg_sta_addr[0]->reset_value = 0;
    reg_sta_addr[0]->writable_bits = 0x0000;

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
    rx_slots.value = 32;
    tx_slots.value = 32;
    trace.value = false;

    mac_addr[0] = 0x08;
    mac_addr[1] = 0x00;
    mac_addr[2] = 0x2b;
    mac_addr[3] = 0xaa;
    mac_addr[4] = 0xbb;
    mac_addr[5] = 0xcc;

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
            mac_addr[0] = 0x08;
            mac_addr[1] = 0x00;
            mac_addr[2] = 0x2b;
            mac_addr[3] = 0xaa;
            mac_addr[4] = 0xbb;
            mac_addr[5] = 0xcc;
        } else if (!parse_mac(mac.new_value, mac_addr)) {
            ERROR("DELQA: invalid MAC format '%s'", mac.new_value.c_str());
            return false;
        } else {
            mac_override = true;
        }
        update_mac_checksum();
        if (handle)
            update_station_regs();
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

    update_transceiver_bits();
    update_csr_reg();

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

void delqa_c::reset_controller(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    rcvlist_lo = 0;
    rcvlist_hi = 0;
    xmtlist_lo = 0;
    xmtlist_hi = 0;
    qe_vector = (intr_vector.value & QE_VEC_IV) | QE_VEC_MS;
    qe_csr = QE_XL_INVALID | QE_RL_INVALID;

    update_transceiver_bits();

    rcvlist_addr = 0;
    xmtlist_addr = 0;
    rx_cur_addr = 0;
    tx_cur_addr = 0;

    deqna_lock = false;
    rx_delay_active = false;
    rx_enable_deadline_ns = 0;
    setup_valid = false;
    setup_promiscuous = false;
    setup_multicast = false;
    memset(setup_macs, 0, sizeof(setup_macs));

    // Reset statistics
    rx_frames = 0;
    tx_frames = 0;
    rx_errors = 0;
    tx_errors = 0;
    stat_rx_frames.value = 0;
    stat_tx_frames.value = 0;
    stat_rx_errors.value = 0;
    stat_tx_errors.value = 0;

    update_mac_checksum();

    intr_request.edge_detect_reset();
    intr_request.set_vector(qe_vector & QE_VEC_IV);

    if (handle) {
        reset_unibus_registers();
        update_station_regs();
        update_vector_reg();
        update_csr_reg();
        update_intr();
    }
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

    mac_checksum[0] = static_cast<uint8_t>(checksum);
    mac_checksum[1] = static_cast<uint8_t>(checksum >> 8);
}

void delqa_c::update_station_regs(void)
{
    if (!handle)
        return;

    for (int i = 0; i < 6; ++i) {
        uint8_t value = mac_addr[i];
        if (i < 2 && (qe_csr & QE_ELOOP))
            value = mac_checksum[i];
        uint16_t word = static_cast<uint16_t>(0xff00 | value);
        set_register_dati_value(reg_sta_addr[i], word, "update_station_regs");
    }
}

void delqa_c::update_vector_reg(void)
{
    if (!handle)
        return;
    set_register_dati_value(reg_vector, qe_vector, "update_vector_reg");
}

void delqa_c::update_csr_reg(void)
{
    if (!handle)
        return;
    set_register_dati_value(reg_csr, qe_csr, "update_csr_reg");
}

void delqa_c::update_transceiver_bits(void)
{
#ifdef HAVE_PCAP
    if (pcap.is_open())
        qe_csr |= QE_OK;
    else
        qe_csr &= ~QE_OK;
#else
    qe_csr &= ~QE_OK;
#endif

    if ((qe_csr & QE_RCV_ENABLE) && (qe_csr & QE_OK))
        qe_csr |= QE_CARRIER;
    else
        qe_csr &= ~QE_CARRIER;
}

bool delqa_c::get_intr_level(void) const
{
    if (!(qe_csr & QE_INT_ENABLE))
        return false;
    return (qe_csr & (QE_RCV_INT | QE_XMIT_INT | QE_NEX_MEM_INT)) != 0;
}

void delqa_c::update_intr(void)
{
    bool level = get_intr_level();

    switch (intr_request.edge_detect(level)) {
    case intr_request_c::INTERRUPT_EDGE_RAISING:
        if (trace.value) {
            INFO("DELQA: INTR assert, csr=%06o vec=%03o level=%d",
                 qe_csr, intr_request.get_vector(), intr_request.get_level());
        }
        qunibusadapter->INTR(intr_request, nullptr, 0);
        break;
    case intr_request_c::INTERRUPT_EDGE_FALLING:
        if (trace.value) {
            INFO("DELQA: INTR deassert, csr=%06o", qe_csr);
        }
        qunibusadapter->cancel_INTR(intr_request);
        break;
    default:
        break;
    }
}

void delqa_c::start_rx_delay(void)
{
    rx_delay_active = true;
    rx_enable_deadline_ns = timeout_c::abstime_ns() +
            static_cast<uint64_t>(DELQA_RX_START_DELAY_MS) * 1000000ull;
}

bool delqa_c::rx_ready(void)
{
    if (!rcv_enabled())
        return false;
    if (!rx_delay_active)
        return true;
    if (timeout_c::abstime_ns() >= rx_enable_deadline_ns) {
        rx_delay_active = false;
        return true;
    }
    return false;
}

bool delqa_c::loopback_enabled(void) const
{
    return (qe_csr & QE_ELOOP) || !(qe_csr & QE_ILOOP);
}

uint32_t delqa_c::make_addr(uint16_t hi, uint16_t lo) const
{
    return (static_cast<uint32_t>(hi & QE_RING_ADDR_HI_MASK) << 16) | lo;
}

uint32_t delqa_c::next_desc_addr(uint32_t addr) const
{
    return addr + QE_RING_BYTES;
}

void delqa_c::set_nxm_error(void)
{
    qe_csr |= QE_NEX_MEM_INT;
    update_csr_reg();
    update_intr();
}

bool delqa_c::rcv_enabled(void) const
{
    if (!(qe_csr & QE_RCV_ENABLE))
        return false;
    if (qe_csr & QE_RL_INVALID)
        return false;
    return (rcvlist_addr != 0);
}

bool delqa_c::xmt_enabled(void) const
{
    if (qe_csr & QE_XL_INVALID)
        return false;
    return (xmtlist_addr != 0);
}

unsigned delqa_c::rx_scan_limit(void) const
{
    return rx_slots.value ? rx_slots.value : DELQA_DEFAULT_SCAN;
}

unsigned delqa_c::tx_scan_limit(void) const
{
    return tx_slots.value ? tx_slots.value : DELQA_DEFAULT_SCAN;
}

void delqa_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    UNUSED(access);
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    uint16_t val = get_register_dato_value(device_reg);

    switch (device_reg->index) {
    case DELQA_REG_RCVLIST_LO:
        rcvlist_lo = val;
        rcvlist_addr = make_addr(rcvlist_hi, static_cast<uint16_t>(rcvlist_lo & ~1u));
        if (rcvlist_addr == 0 || rcvlist_addr >= qunibus->addr_space_byte_count) {
            qe_csr |= QE_RL_INVALID;
            rx_cur_addr = 0;
        } else {
            qe_csr &= ~QE_RL_INVALID;
            rx_cur_addr = rcvlist_addr;
        }
        update_csr_reg();
        update_intr();
        break;
    case DELQA_REG_RCVLIST_HI:
        rcvlist_hi = val;
        rcvlist_addr = make_addr(rcvlist_hi, static_cast<uint16_t>(rcvlist_lo & ~1u));
        if (rcvlist_addr == 0 || rcvlist_addr >= qunibus->addr_space_byte_count) {
            qe_csr |= QE_RL_INVALID;
            rx_cur_addr = 0;
        } else {
            qe_csr &= ~QE_RL_INVALID;
            rx_cur_addr = rcvlist_addr;
        }
        update_csr_reg();
        update_intr();
        break;
    case DELQA_REG_XMTLIST_LO:
        xmtlist_lo = val;
        xmtlist_addr = make_addr(xmtlist_hi, static_cast<uint16_t>(xmtlist_lo & ~1u));
        if (xmtlist_addr == 0 || xmtlist_addr >= qunibus->addr_space_byte_count) {
            qe_csr |= QE_XL_INVALID;
            tx_cur_addr = 0;
        } else {
            qe_csr &= ~QE_XL_INVALID;
            tx_cur_addr = xmtlist_addr;
        }
        update_csr_reg();
        update_intr();
        break;
    case DELQA_REG_XMTLIST_HI:
        xmtlist_hi = val;
        xmtlist_addr = make_addr(xmtlist_hi, static_cast<uint16_t>(xmtlist_lo & ~1u));
        if (xmtlist_addr == 0 || xmtlist_addr >= qunibus->addr_space_byte_count) {
            qe_csr |= QE_XL_INVALID;
            tx_cur_addr = 0;
        } else {
            qe_csr &= ~QE_XL_INVALID;
            tx_cur_addr = xmtlist_addr;
        }
        update_csr_reg();
        update_intr();
        break;
    case DELQA_REG_VECTOR: {
        uint16_t old_vec = qe_vector;
        uint16_t new_vec;
        if (deqna_lock)
            new_vec = (qe_vector & QE_VEC_RO) | (val & (QE_VEC_IV | QE_VEC_ID));
        else
            new_vec = (qe_vector & QE_VEC_RO) | (val & QE_VEC_RW);

        if ((old_vec ^ new_vec) & QE_VEC_MS) {
            if (!(new_vec & QE_VEC_MS)) {
                deqna_lock = true;
                new_vec &= ~(QE_VEC_OS | QE_VEC_RS | QE_VEC_ST);
            } else {
                deqna_lock = false;
            }
        }

        if (new_vec & QE_VEC_RS)
            new_vec &= ~QE_VEC_RS;

        qe_vector = new_vec;
        update_vector_reg();
        intr_request.set_vector(qe_vector & QE_VEC_IV);
        break;
    }
    case DELQA_REG_CSR: {
        uint16_t prev = qe_csr;
        if ((prev & QE_RESET) && !(val & QE_RESET)) {
            reset_controller();
            return;
        }

        uint16_t set_bits = val & QE_CSR_RW;
        uint16_t clr_bits = (~val & QE_CSR_RW) | (val & QE_CSR_W1);
        if (val & QE_XMIT_INT)
            clr_bits |= QE_NEX_MEM_INT;

        qe_csr = (qe_csr | set_bits) & ~clr_bits;

        if ((prev ^ qe_csr) & QE_RCV_ENABLE) {
            if (qe_csr & QE_RCV_ENABLE)
                start_rx_delay();
            else
                rx_delay_active = false;
        }

        if ((prev ^ qe_csr) & QE_ELOOP)
            update_station_regs();

        update_transceiver_bits();
        update_csr_reg();
        update_intr();
        break;
    }
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

bool delqa_c::read_descriptor(uint32_t addr, uint16_t words[QE_RING_WORDS])
{
    return dma_read_words(addr, words, QE_RING_WORDS);
}

bool delqa_c::write_descriptor(uint32_t addr, const uint16_t words[QE_RING_WORDS])
{
    return dma_write_words(addr, words, QE_RING_WORDS);
}

bool delqa_c::rx_place_frame(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (!rcv_enabled())
        return false;

    uint32_t desc_addr = rx_cur_addr ? rx_cur_addr : rcvlist_addr;
    if (!desc_addr)
        return false;

    size_t total_len = len < 60 ? 60 : len;
    size_t remaining = total_len;
    size_t offset = 0;
    unsigned limit = rx_scan_limit();
    bool any_written = false;
    bool error = false;

    uint16_t rbl_total = (len >= 60) ? static_cast<uint16_t>(len - 60) : 0;

    while (remaining > 0 && limit--) {
        uint16_t words[QE_RING_WORDS];
        if (!read_descriptor(desc_addr, words)) {
            set_nxm_error();
            return false;
        }

        uint16_t addr_hi = words[1];
        if (!(addr_hi & QE_RING_VALID)) {
            qe_csr |= QE_RL_INVALID;
            update_csr_reg();
            update_intr();
            return false;
        }

        if (addr_hi & QE_RING_CHAIN) {
            uint32_t next_addr = make_addr(addr_hi, words[2]);
            if (next_addr == 0 || next_addr >= qunibus->addr_space_byte_count) {
                qe_csr |= QE_RL_INVALID;
                update_csr_reg();
                update_intr();
                return false;
            }
            rx_cur_addr = next_addr;
            desc_addr = next_addr;
            continue;
        }

        if (words[4] != QE_NOTYET) {
            desc_addr = next_desc_addr(desc_addr);
            continue;
        }

        uint32_t buf_addr = make_addr(addr_hi, words[2]);
        int16_t buf_words = static_cast<int16_t>(words[3]);

        if (buf_words >= 0) {
            error = true;
        } else {
            size_t buf_bytes = static_cast<size_t>(-buf_words) * 2;
            size_t addr_offset = 0;
            if (addr_hi & QE_RING_ODD_BEGIN) {
                addr_offset = 1;
                if (buf_bytes)
                    buf_bytes--;
            }
            if (addr_hi & QE_RING_ODD_END) {
                if (buf_bytes)
                    buf_bytes--;
            }

            size_t chunk = std::min(remaining, buf_bytes);
            if (chunk == 0) {
                error = true;
            } else {
                size_t data_avail = 0;
                if (offset < len)
                    data_avail = std::min(len - offset, chunk);

                if (data_avail) {
                    if (!dma_write_bytes(buf_addr + addr_offset, data + offset, data_avail)) {
                        error = true;
                        set_nxm_error();
                    }
                }

                if (!error && chunk > data_avail) {
                    uint8_t pad[60] = {0};
                    size_t pad_len = chunk - data_avail;
                    if (!dma_write_bytes(buf_addr + addr_offset + data_avail, pad, pad_len)) {
                        error = true;
                        set_nxm_error();
                    }
                }

                remaining -= chunk;
                offset += chunk;
            }
        }

        uint16_t status1 = 0;
        uint16_t status2 = 0;
        if (error) {
            status1 = QE_RST_LASTERR;
        } else {
            status1 = QE_RST_RSVD | (rbl_total & 0x0700);
            if (remaining > 0)
                status1 |= QE_RST_LASTNOT;
        }

        status2 = static_cast<uint16_t>(rbl_total & 0x00ff);
        status2 = static_cast<uint16_t>((status2 << 8) | status2);

        words[0] = 0xffff;
        words[4] = status1;
        words[5] = status2;

        if (!write_descriptor(desc_addr, words)) {
            set_nxm_error();
            error = true;
        }

        any_written = true;
        rx_cur_addr = next_desc_addr(desc_addr);
        desc_addr = rx_cur_addr;

        if (error)
            break;
    }

    if (!any_written)
        return false;

    qe_csr |= QE_RCV_INT;
    if (error || remaining > 0) {
        rx_errors++;
        stat_rx_errors.value = rx_errors;
    } else {
        rx_frames++;
        stat_rx_frames.value = rx_frames;
    }

    update_csr_reg();
    update_intr();

    if (trace.value) {
        INFO("DELQA: RX len=%u %s", static_cast<unsigned>(len),
             (error || remaining > 0) ? "error" : "ok");
    }

    return !(error || remaining > 0);
}

bool delqa_c::tx_take_frame(std::vector<uint8_t> &frame)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    if (!xmt_enabled())
        return false;

    uint32_t desc_addr = tx_cur_addr ? tx_cur_addr : xmtlist_addr;
    if (!desc_addr)
        return false;

    frame.clear();
    unsigned limit = tx_scan_limit();
    bool error = false;
    bool eom_seen = false;
    bool any_desc = false;
    bool is_setup = false;

    while (limit--) {
        uint16_t words[QE_RING_WORDS];
        if (!read_descriptor(desc_addr, words)) {
            set_nxm_error();
            return false;
        }

        uint16_t addr_hi = words[1];
        if (!(addr_hi & QE_RING_VALID)) {
            qe_csr |= QE_XL_INVALID;
            update_csr_reg();
            update_intr();
            return false;
        }

        if (addr_hi & QE_RING_CHAIN) {
            uint32_t next_addr = make_addr(addr_hi, words[2]);
            if (next_addr == 0 || next_addr >= qunibus->addr_space_byte_count) {
                qe_csr |= QE_XL_INVALID;
                update_csr_reg();
                update_intr();
                return false;
            }
            tx_cur_addr = next_addr;
            desc_addr = next_addr;
            continue;
        }

        if (words[4] != QE_NOTYET) {
            desc_addr = next_desc_addr(desc_addr);
            continue;
        }

        any_desc = true;
        is_setup = is_setup || ((addr_hi & QE_RING_SETUP) != 0);

        uint32_t buf_addr = make_addr(addr_hi, words[2]);
        int16_t buf_words = static_cast<int16_t>(words[3]);

        if (buf_words >= 0) {
            error = true;
        } else {
            size_t buf_bytes = static_cast<size_t>(-buf_words) * 2;
            size_t addr_offset = 0;
            if (addr_hi & QE_RING_ODD_BEGIN) {
                addr_offset = 1;
                if (buf_bytes)
                    buf_bytes--;
            }
            if (addr_hi & QE_RING_ODD_END) {
                if (buf_bytes)
                    buf_bytes--;
            }

            if (buf_bytes == 0) {
                error = true;
            } else if (frame.size() + buf_bytes > DELQA_MAX_FRAME_SIZE) {
                error = true;
            } else {
                size_t base = frame.size();
                frame.resize(base + buf_bytes);
                if (!dma_read_bytes(buf_addr + addr_offset, frame.data() + base, buf_bytes)) {
                    error = true;
                    set_nxm_error();
                }
            }
        }

        if (error)
            eom_seen = true;
        else
            eom_seen = (addr_hi & QE_RING_EOMSG) != 0;

        if (!eom_seen) {
            words[0] = 0xffff;
            words[4] = QE_RST_LASTNOT;
            words[5] = 1;
            if (!write_descriptor(desc_addr, words)) {
                set_nxm_error();
                error = true;
                eom_seen = true;
            }
            tx_cur_addr = next_desc_addr(desc_addr);
            desc_addr = tx_cur_addr;
            continue;
        }

        bool loopback = is_setup || loopback_enabled();
        if (!error) {
            if (loopback) {
                if (!rx_place_frame(frame.data(), frame.size()))
                    error = true;
            }
#ifdef HAVE_PCAP
            else if (!pcap.send(frame.data(), frame.size())) {
                error = true;
            }
#else
            else {
                error = true;
            }
#endif
        }

        uint16_t status1 = 0;
        uint16_t status2 = 0;
        if (is_setup) {
            process_setup_packet(frame);
            status1 = 0x200c;
            status2 = 0x0860;
        } else if (loopback) {
            status1 = error ? 0x4000 : 0x2000;
            status2 = 1;
        } else {
            uint16_t tdr = static_cast<uint16_t>((100 + frame.size() * 8) & 0x03ff);
            status1 = error ? 0x4000 : 0x0000;
            status2 = tdr ? tdr : 1;
        }

        words[0] = 0xffff;
        words[4] = status1;
        words[5] = status2;

        if (!write_descriptor(desc_addr, words)) {
            set_nxm_error();
            error = true;
        }

        tx_cur_addr = next_desc_addr(desc_addr);

        qe_csr |= QE_XMIT_INT;
        if (error) {
            tx_errors++;
            stat_tx_errors.value = tx_errors;
        } else {
            tx_frames++;
            stat_tx_frames.value = tx_frames;
        }

        update_csr_reg();
        update_intr();

        if (trace.value) {
            INFO("DELQA: TX len=%u %s", static_cast<unsigned>(frame.size()),
                 error ? "error" : "ok");
        }
        return true;
    }

    return any_desc;
}

bool delqa_c::process_setup_packet(const std::vector<uint8_t> &frame)
{
    if (frame.size() < 128) {
        // Small setup packets disable promiscuous/multicast modes
        setup_promiscuous = false;
        setup_multicast = false;
        setup_valid = true;
        return true;
    }

    // Clear existing MAC filters
    memset(setup_macs, 0, sizeof(setup_macs));

    // Extract MAC addresses from setup packet
    // Format: bytes 1-6: MAC0, 9-14: MAC1, etc.
    for (int i = 0; i < XQ_FILTER_MAX; i++) {
        size_t offset = 1 + i * 8;
        if (offset + 6 <= frame.size()) {
            memcpy(setup_macs[i], &frame[offset], 6);
        }
    }

    // Extract control flags from packet length
    uint16_t len = static_cast<uint16_t>(frame.size());
    setup_multicast = (len & 0x0001) != 0;
    setup_promiscuous = (len & 0x0002) != 0;

    setup_valid = true;

    INFO("DELQA: Setup packet processed: len=%zu, promisc=%d multicast=%d",
         frame.size(), setup_promiscuous, setup_multicast);
    for (int i = 0; i < XQ_FILTER_MAX; i++) {
        if (setup_macs[i][0] || setup_macs[i][1] || setup_macs[i][2] ||
            setup_macs[i][3] || setup_macs[i][4] || setup_macs[i][5]) {
            INFO("DELQA: Setup MAC[%d]: %02x:%02x:%02x:%02x:%02x:%02x", i,
                 setup_macs[i][0], setup_macs[i][1], setup_macs[i][2],
                 setup_macs[i][3], setup_macs[i][4], setup_macs[i][5]);
        }
    }

    return true;
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
        if (qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }
        if (!rx_ready()) {
            timeout_c::wait_ms(1);
            continue;
        }

        size_t len = 0;
        if (!pcap.poll(frame.data(), frame.size(), &len)) {
            WARNING("DELQA: pcap poll error: %s", pcap.last_error().c_str());
            timeout_c::wait_ms(100);
            continue;
        }

        if (len == 0) {
            timeout_c::wait_ms(1);
            continue;
        }

        if (len >= 6 && !promisc.value) {
            const uint8_t *dst = frame.data();
            bool broadcast = (dst[0] == 0xff && dst[1] == 0xff && dst[2] == 0xff &&
                              dst[3] == 0xff && dst[4] == 0xff && dst[5] == 0xff);
            bool multicast = (dst[0] & 0x01) != 0;
            
            bool accept = broadcast;
            
            if (!accept && setup_valid) {
                // Use setup packet MAC addresses for filtering
                if (setup_promiscuous) {
                    accept = true;
                } else if (multicast && setup_multicast) {
                    accept = true;
                } else {
                    // Check against setup MAC addresses
                    for (int i = 0; i < XQ_FILTER_MAX; i++) {
                        if (memcmp(dst, setup_macs[i], 6) == 0) {
                            accept = true;
                            break;
                        }
                    }
                }
            } else if (!accept) {
                // Fall back to device MAC if no setup packet
                bool unicast_match = (memcmp(dst, mac_addr, 6) == 0);
                if (unicast_match) {
                    accept = true;
                }
            }
            
            if (!accept)
                continue;
        }

        rx_place_frame(frame.data(), len);
    }
#else
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
        if (qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        if (!tx_take_frame(frame)) {
            timeout_c::wait_ms(1);
        }
    }
#else
    while (!workers_terminate) {
        timeout_c::wait_ms(100);
    }
#endif
}
