/*
 * DELQA/DEQNA emulation derived from OpenSIMH pdp11_xq.c (v4.0-devel).
 *
 * Original OpenSIMH license (MIT-style):
 *
 *   Copyright (c) 2002-2008, David T. Hittner
 *
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
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *   THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Adapted for QUniBone (GPLv2 project) with the same functional behavior as
 * OpenSIMH where practical.
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

// Ethernet framing limits (excluding preamble/CRC added by hardware)
static const size_t ETH_MIN_PACKET = 60;
static const size_t ETH_MAX_PACKET = 1514;
static const size_t ETH_FRAME_SIZE = 1518;
static const size_t XQ_MAX_RCV_PACKET = 1600;
static const size_t XQ_LONG_PACKET = 0x0600; // 1536 bytes
static const unsigned XQ_QUE_MAX = 500;
static const unsigned XQ_SERVICE_INTERVAL = 100; // poll times/sec
static const unsigned XQ_SYSTEM_ID_SECS = 540;
static const unsigned XQ_HW_SANITY_SECS = 240;

static const uint16_t XQ_DSC_V = QE_RING_VALID;
static const uint16_t XQ_DSC_C = QE_RING_CHAIN;
static const uint16_t XQ_DSC_E = QE_RING_EOMSG;
static const uint16_t XQ_DSC_S = QE_RING_SETUP;
static const uint16_t XQ_DSC_L = QE_RING_ODD_END;
static const uint16_t XQ_DSC_H = QE_RING_ODD_BEGIN;

static const uint16_t XQ_CSR_RI = QE_RCV_INT;
static const uint16_t XQ_CSR_PE = QE_PARITY;
static const uint16_t XQ_CSR_CA = QE_CARRIER;
static const uint16_t XQ_CSR_OK = QE_OK;
static const uint16_t XQ_CSR_SE = QE_STIM_ENABLE;
static const uint16_t XQ_CSR_EL = QE_ELOOP;
static const uint16_t XQ_CSR_IL = QE_ILOOP;
static const uint16_t XQ_CSR_XI = QE_XMIT_INT;
static const uint16_t XQ_CSR_IE = QE_INT_ENABLE;
static const uint16_t XQ_CSR_RL = QE_RL_INVALID;
static const uint16_t XQ_CSR_XL = QE_XL_INVALID;
static const uint16_t XQ_CSR_BD = QE_LOAD_ROM;
static const uint16_t XQ_CSR_NI = QE_NEX_MEM_INT;
static const uint16_t XQ_CSR_SR = QE_RESET;
static const uint16_t XQ_CSR_RE = QE_RCV_ENABLE;

static const uint16_t XQ_CSR_RO = QE_CSR_RO;
static const uint16_t XQ_CSR_RW = QE_CSR_RW;
static const uint16_t XQ_CSR_W1 = QE_CSR_W1;
static const uint16_t XQ_CSR_BP = QE_CSR_BP;
static const uint16_t XQ_CSR_XIRI = (XQ_CSR_XI | XQ_CSR_RI);

static const uint16_t XQ_VEC_MS = QE_VEC_MS;
static const uint16_t XQ_VEC_OS = QE_VEC_OS;
static const uint16_t XQ_VEC_RS = QE_VEC_RS;
static const uint16_t XQ_VEC_ST = QE_VEC_ST;
static const uint16_t XQ_VEC_IV = QE_VEC_IV;
static const uint16_t XQ_VEC_RO = QE_VEC_RO;
static const uint16_t XQ_VEC_RW = QE_VEC_RW;

static const char *DELQA_VERSION = "v011";  // Increment on each change

static const uint16_t XQ_SETUP_MC = 0x0001;
static const uint16_t XQ_SETUP_PM = 0x0002;
static const uint16_t XQ_SETUP_LD = 0x000C;
static const uint16_t XQ_SETUP_ST = 0x0070;

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

delqa_c::delqa_c() : qunibusdevice_c()
{
    set_workers_count(2);

    name.value = "delqa";
    type_name.value = "DELQA";
    log_label = "delqa";

    set_default_bus_params(DELQA_DEFAULT_ADDR, DELQA_DEFAULT_SLOT, DELQA_DEFAULT_VECTOR, DELQA_DEFAULT_LEVEL);
    dma_request.set_priority_slot(priority_slot.value);
    intr_request.set_priority_slot(priority_slot.value);
    intr_request.set_level(intr_level.value);
    intr_request.set_vector(intr_vector.value);

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

void delqa_c::update_transceiver_bits(void)
{
    if (pcap.is_open())
        csr |= XQ_CSR_OK;
    else
        csr &= ~XQ_CSR_OK;

    csr &= ~XQ_CSR_CA;
}

void delqa_c::set_int(void)
{
    irq = true;
    WARNING("DELQA: INTR assert, csr=%06o ie=%d", csr, (csr & XQ_CSR_IE) ? 1 : 0);
    update_intr();
}

void delqa_c::clr_int(void)
{
    irq = false;
    WARNING("DELQA: INTR deassert, csr=%06o ie=%d", csr, (csr & XQ_CSR_IE) ? 1 : 0);
    update_intr();
}

void delqa_c::csr_set_clr(uint16_t set_bits, uint16_t clear_bits)
{
    uint16_t saved_csr = csr;
    csr = static_cast<uint16_t>((csr | set_bits) & ~clear_bits);

    if ((saved_csr ^ csr) & XQ_CSR_IE) {
        if ((clear_bits & XQ_CSR_IE) && irq)
            clr_int();
        if ((set_bits & XQ_CSR_IE) && (csr & XQ_CSR_XIRI) && !irq)
            set_int();
    } else {
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

    if ((saved_csr ^ csr) & (XQ_CSR_RL | XQ_CSR_XL | XQ_CSR_RI | XQ_CSR_XI)) {
        WARNING("DELQA: CSR change prev=%06o now=%06o set=%06o clr=%06o",
                saved_csr, csr, set_bits, clear_bits);
    }
}

void delqa_c::nxm_error(void)
{
    const uint16_t set_bits = XQ_CSR_NI | XQ_CSR_XI | XQ_CSR_XL | XQ_CSR_RL;
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

void delqa_c::reset_sanity_timer(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!sanity.enabled)
        return;
    sanity.timer = sanity.max;
}

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

    if (--idtmr <= 0) {
        const uint8_t mop_multicast[6] = {0xAB, 0x00, 0x00, 0x02, 0x00, 0x00};
        send_system_id(mop_multicast, 0);
        idtmr = static_cast<int>(XQ_SYSTEM_ID_SECS * XQ_SERVICE_INTERVAL);
    }
}

void delqa_c::reset_controller(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    rbdl[0] = 0;
    rbdl[1] = 0;
    xbdl[0] = 0;
    xbdl[1] = 0;

    var = static_cast<uint16_t>(XQ_VEC_MS | XQ_VEC_OS | (intr_vector.value & XQ_VEC_IV));
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

    if (!read_queue.empty()) {
        WARNING("DELQA: reset_controller clearing RX queue (size=%zu)", read_queue.size());
    }
    read_queue.clear();
    read_queue_loss = 0;
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
}

void delqa_c::sw_reset(void)
{
    const uint16_t set_bits = XQ_CSR_XL | XQ_CSR_RL;

    csr_set_clr(set_bits, static_cast<uint16_t>(~set_bits));

    if (pcap.is_open())
        csr_set_clr(XQ_CSR_OK, 0);

    clr_int();

    if (!read_queue.empty()) {
        WARNING("DELQA: sw_reset clearing RX queue (size=%zu)", read_queue.size());
    }
    read_queue.clear();
    read_queue_loss = 0;

    setup.multicast = false;
    setup.promiscuous = false;

    update_pcap_filter();
}

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

    if (setup.valid) {
        for (int i = 0; i < XQ_FILTER_MAX; ++i) {
            if (!mac_is_zero(setup.macs[i]))
                add_mac(setup.macs[i]);
        }
    } else {
        add_mac(mac_addr);
    }

    if (filter.empty())
        filter = "ip or not ip";

    if (!pcap.set_filter(filter)) {
        WARNING("DELQA: pcap filter set failed: %s", pcap.last_error().c_str());
    }
#endif
}

uint32_t delqa_c::make_addr(uint16_t hi, uint16_t lo) const
{
    return (static_cast<uint32_t>(hi & QE_RING_ADDR_HI_MASK) << 16) | lo;
}

void delqa_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    UNUSED(access);
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    uint16_t val = get_register_dato_value(device_reg);

    if (trace.value) {
        static const char *reg_names[] = {
            "STA0", "STA1", "RCLL", "RCLH", "XMTL", "XMTH", "VAR", "CSR"
        };
        const char *rname = (device_reg->index < 8) ? reg_names[device_reg->index] : "???";
        INFO("DELQA: Write %s (reg %d) = %06o", rname, device_reg->index, val);
    }

    switch (device_reg->index) {
    case DELQA_REG_RCVLIST_LO:
        rbdl[0] = val;
        break;
    case DELQA_REG_RCVLIST_HI:
        rbdl[1] = val;
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
        csr_set_clr(0, XQ_CSR_RL);
        rbdl_pending = true;
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
            WARNING("DELQA: Boot/diagnostic ROM request (BP bits set)");
            bootrom_pending = true;
        }
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
    WARNING("DELQA: DMA read_words addr=%06o words=%zu", addr, wordcount);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
    WARNING("DELQA: DMA read_words done addr=%06o ok=%d", addr, dma_request.success ? 1 : 0);
    return dma_request.success;
}

bool delqa_c::dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
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
    WARNING("DELQA: DMA write_words addr=%06o words=%zu", addr, wordcount);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATO, addr,
            const_cast<uint16_t *>(buffer), wordcount);
    WARNING("DELQA: DMA write_words done addr=%06o ok=%d", addr, dma_request.success ? 1 : 0);
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

void delqa_c::enqueue_readq(int type, const uint8_t *data, size_t len, int status)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    WARNING("DELQA: Enqueue RX type=%d len=%zu status=%06o queue=%zu",
            type, len, static_cast<uint16_t>(status), read_queue.size());

    if (read_queue.size() >= XQ_QUE_MAX) {
        read_queue_loss++;
        if (!read_queue.empty())
            read_queue.pop_front();
    }

    queue_item item;
    item.type = type;
    item.packet.msg.assign(data, data + len);
    item.packet.len = len;
    item.packet.used = 0;
    item.packet.status = status;
    read_queue.push_back(std::move(item));
}

bool delqa_c::dispatch_rbdl(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    // SimH: clear RL and recalculate rbdl_ba from base registers
    csr_set_clr(0, XQ_CSR_RL);
    rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
    if (rbdl_ba == 0)
        return false;

    WARNING("DELQA: RX list dispatch at %06o (csr=%06o queue=%zu)",
            rbdl_ba, csr, read_queue.size());
    WARNING("DELQA: RX list dispatch after RL clear at %06o (csr=%06o)",
            rbdl_ba, csr);

    // SimH: only READ the descriptor in dispatch, don't write 0xFFFF yet
    uint16_t words[4] = {0};
    for (size_t i = 0; i < 4; ++i) {
        if (!dma_read_words(rbdl_ba + static_cast<uint32_t>(i * 2), &words[i], 1)) {
            nxm_error();
            return false;
        }
    }

    WARNING("DELQA: RX dispatch read words0=%06o words1=%06o words2=%06o words3=%06o",
            words[0], words[1], words[2], words[3]);

    // Process any waiting packets in receive queue
    if (!read_queue.empty())
        return process_rbdl();

    return true;
}

bool delqa_c::process_rbdl(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    WARNING("DELQA: RX process start at %06o (queue=%zu csr=%06o)",
            rbdl_ba, read_queue.size(), csr);
    while (true) {
        uint16_t words[QE_RING_WORDS] = {0};
        uint16_t flag = 0xFFFF;

        WARNING("DELQA: RX desc fetch at %06o (pre-write)", rbdl_ba);
        if (!dma_write_words(rbdl_ba, &flag, 1)) {
            nxm_error();
            return false;
        }
        WARNING("DELQA: RX desc fetch at %06o (pre-read)", rbdl_ba);
        for (size_t i = 1; i < QE_RING_WORDS; ++i) {
            if (!dma_read_words(rbdl_ba + 2 + static_cast<uint32_t>((i - 1) * 2), &words[i], 1)) {
                nxm_error();
                return false;
            }
        }
        WARNING("DELQA: RX desc %06o words1=%06o words2=%06o words3=%06o",
                rbdl_ba, words[1], words[2], words[3]);

        if (~words[1] & XQ_DSC_V) {
            WARNING("DELQA: RX descriptor at %06o not valid (addr_hi=%06o)",
                    rbdl_ba, words[1]);
            csr_set_clr(XQ_CSR_RL, 0);
            return false;
        }

        if (words[1] & XQ_DSC_C) {
            rbdl_ba = make_addr(words[1], words[2]);
            continue;
        }

        if (read_queue.empty()) {
            WARNING("DELQA: RX list idle at %06o (queue empty, csr=%06o)",
                    rbdl_ba, csr);
            break;
        }

        if (!dma_read_words(rbdl_ba + 8, &words[4], 2)) {
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

        queue_item &item = read_queue.front();
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

        if (rbl > b_length)
            rbl = b_length;
        item.packet.used += rbl;

        if (!dma_write_bytes(address, rbuf, rbl)) {
            nxm_error();
            return false;
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

        // SimH: XQ_RST_LASTNOT if packet has more data to deliver
        if (item.packet.used < item.packet.len)
            words[4] |= QE_RST_LASTNOT;  // 0xC000 = not last segment
        words[5] = static_cast<uint16_t>(((rbl & 0x00FF) << 8) | (rbl & 0x00FF));

        if (read_queue_loss) {
            words[4] |= 0x0001;
            read_queue_loss = 0;
        }

        if (!dma_write_words(rbdl_ba + 8, &words[4], 2)) {
            nxm_error();
            return false;
        }

        WARNING("DELQA: RX desc %06o writeback status1=%06o status2=%06o bytes=%u",
                rbdl_ba, words[4], words[5], static_cast<unsigned>(rbl));

        if (item.packet.used >= item.packet.len)
            read_queue.pop_front();

        csr_set_clr(XQ_CSR_RI, 0);

        rbdl_ba += QE_RING_BYTES;
    }

    return true;
}

void delqa_c::touch_rbdl_if_idle(void)
{
    // SimH doesn't have this function - descriptors are only touched when processing packets
    // Just log for debugging, no DMA operations
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!read_queue.empty())
        return;
    WARNING("DELQA: RX idle at %06o (queue empty)", rbdl_ba);
}

bool delqa_c::dispatch_xbdl(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    csr_set_clr(0, XQ_CSR_XL);

    // SimH: Always recalculate xbdl_ba from base registers when dispatching
    xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
    if (xbdl_ba == 0)
        return false;

    WARNING("DELQA: TX list dispatch at %06o (csr=%06o)", xbdl_ba, csr);

    write_buffer.len = 0;
    write_buffer.used = 0;

    return process_xbdl();
}

void delqa_c::write_callback(int status)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint16_t TDR = static_cast<uint16_t>(100 + write_buffer.len * 8);
    uint16_t write_success[2] = {0, static_cast<uint16_t>(TDR & 0x03FF)};
    uint16_t write_failure[2] = {XQ_DSC_C, static_cast<uint16_t>(TDR & 0x03FF)};

    stats.xmit++;
    stat_tx_frames.value = stats.xmit;

    if (!dma_write_words(xbdl_ba + 8, (status == 0) ? write_success : write_failure, 2)) {
        nxm_error();
        return;
    }

    if (status != 0) {
        stats.fail++;
        stat_tx_errors.value = stats.fail;
    }

    csr_set_clr(XQ_CSR_XI, 0);
    reset_sanity_timer();

    write_buffer.len = 0;
    write_buffer.used = 0;

    xbdl_ba += QE_RING_BYTES;

    process_xbdl();
}

bool delqa_c::process_xbdl(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint16_t implicit_chain_status[2] = {static_cast<uint16_t>(XQ_DSC_V | XQ_DSC_C), 1};

    while (true) {
        uint16_t words[QE_RING_WORDS] = {0};
        if (!dma_read_words(xbdl_ba, words, QE_RING_WORDS)) {
            nxm_error();
            return false;
        }

        uint16_t flag = 0xFFFF;
        if (!dma_write_words(xbdl_ba, &flag, 1)) {
            nxm_error();
            return false;
        }

        if (~words[1] & XQ_DSC_V) {
            WARNING("DELQA: TX descriptor at %06o not valid (addr_hi=%06o)",
                    xbdl_ba, words[1]);
            csr_set_clr(XQ_CSR_XL, 0);
            return false;
        }

        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        if (words[1] & XQ_DSC_H)
            b_length -= 1;
        if (words[1] & XQ_DSC_L)
            b_length -= 1;

        if (words[1] & XQ_DSC_C) {
            xbdl_ba = address;
            continue;
        }

        if ((write_buffer.len + b_length) > write_buffer.msg.size())
            b_length = static_cast<uint16_t>(write_buffer.msg.size() - write_buffer.len);

        if (!dma_read_bytes(address, &write_buffer.msg[write_buffer.len], b_length)) {
            nxm_error();
            return false;
        }
        write_buffer.len += b_length;

        if (words[1] & XQ_DSC_E) {
            // SimH: loopback if IL=0 (internal) OR EL=1 (external), independent of RE
            bool il_clear = !(csr & XQ_CSR_IL);
            bool el_set = (csr & XQ_CSR_EL) != 0;
            bool loopback = il_clear || el_set;
            bool setup_packet = (words[1] & XQ_DSC_S) != 0;

            WARNING("DELQA: TX EOMSG len=%u setup=%d loopback=%d (IL_clear=%d EL_set=%d) csr=%06o",
                    write_buffer.len, setup_packet ? 1 : 0, loopback ? 1 : 0,
                    il_clear ? 1 : 0, el_set ? 1 : 0, csr);

            if (loopback || setup_packet) {
                if (setup_packet) {
                    process_setup();
                    enqueue_readq(0, write_buffer.msg.data(), write_buffer.len, 0);
                } else {
                    enqueue_readq(1, write_buffer.msg.data(), write_buffer.len, 0);
                }

                uint16_t write_success[2] = {0, 1};
                if (!dma_write_words(xbdl_ba + 8, write_success, 2)) {
                    nxm_error();
                    return false;
                }

                write_buffer.len = 0;
                write_buffer.used = 0;

                reset_sanity_timer();
                csr_set_clr(XQ_CSR_XI, 0);

                if (!(csr & XQ_CSR_RL))
                    process_rbdl();

            } else {
                if (!pcap.send(write_buffer.msg.data(), write_buffer.len))
                    write_callback(1);
                else
                    write_callback(0);
                return true;
            }
        } else {
            if (!dma_write_words(xbdl_ba + 8, implicit_chain_status, 2)) {
                nxm_error();
                return false;
            }
        }

        xbdl_ba += QE_RING_BYTES;
    }
}

void delqa_c::process_setup(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint8_t *msg = write_buffer.msg.data();
    size_t len = write_buffer.len;

    memset(setup.macs, 0, sizeof(setup.macs));
    for (int i = 0; i < 7; i++)
        for (int j = 0; j < 6; j++) {
            setup.macs[i][j] = msg[(i + 1) + (j * 8)];
            if (len > 112)
                setup.macs[i + 7][j] = msg[(i + 0x41) + (j * 8)];
        }

    setup.promiscuous = false;
    if (len > 128) {
        uint16_t l = static_cast<uint16_t>(len);
        uint16_t led = static_cast<uint16_t>((l & XQ_SETUP_LD) >> 2);
        uint16_t san = static_cast<uint16_t>((l & XQ_SETUP_ST) >> 4);
        float secs = 0.25f;

        setup.multicast = (0 != (l & XQ_SETUP_MC));
        setup.promiscuous = (0 != (l & XQ_SETUP_PM));
        if (led) {
            switch (led) {
            case 1: setup.l1 = false; break;
            case 2: setup.l2 = false; break;
            case 3: setup.l3 = false; break;
            }
        }

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

    sanity.timer = sanity.max;
    if (sanity.enabled != 2) {
        if (csr & XQ_CSR_SE)
            sanity.enabled = 1;
        else
            sanity.enabled = 0;
    }

    update_pcap_filter();
    setup.valid = true;

    WARNING("DELQA: Setup packet processed: len=%zu, promisc=%d multicast=%d",
            len, setup.promiscuous ? 1 : 0, setup.multicast ? 1 : 0);
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

bool delqa_c::process_bootrom(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!ensure_bootrom_image())
        return false;

    uint16_t words[QE_RING_WORDS] = {0};
    uint16_t flag = 0xFFFF;

    for (int part = 0; part < 2; ++part) {
    WARNING("DELQA: RX list dispatch pre-write flag at %06o", rbdl_ba);
    if (!dma_write_words(rbdl_ba, &flag, 1)) {
        WARNING("DELQA: RX list dispatch flag write failed at %06o", rbdl_ba);
        nxm_error();
        return false;
    }
    WARNING("DELQA: RX list dispatch pre-read desc at %06o", rbdl_ba);
    for (size_t i = 1; i < QE_RING_WORDS; ++i) {
        if (!dma_read_words(rbdl_ba + 2 + static_cast<uint32_t>((i - 1) * 2), &words[i], 1)) {
            WARNING("DELQA: RX list dispatch desc read failed at %06o", rbdl_ba);
            nxm_error();
            return false;
        }
    }
    WARNING("DELQA: RX dispatch read words0=%06o words1=%06o words2=%06o words3=%06o",
            flag, words[1], words[2], words[3]);

        if (~words[1] & XQ_DSC_V) {
            WARNING("DELQA: Bootrom RX descriptor at %06o not valid (addr_hi=%06o)",
                    rbdl_ba, words[1]);
            csr_set_clr(XQ_CSR_RL, 0);
            return false;
        }

        if (!dma_read_words(rbdl_ba + 8, &words[4], 2)) {
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
                    rbdl_ba, b_length);
            csr_set_clr(XQ_CSR_RL, 0);
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
        if (!dma_write_words(rbdl_ba + 8, &words[4], 2)) {
            nxm_error();
            return false;
        }

        {
            uint32_t remaining = (sizeof(delqa_bootrom) / 2) * (1 - part);
            WARNING("DELQA: Bootrom desc_addr=%06o status1=%06o status2=%06o remaining=%u",
                    rbdl_ba, words[4], words[5], remaining);
        }

        rbdl_ba += QE_RING_BYTES;
    }

    csr_set_clr(XQ_CSR_RI, 0);
    reset_sanity_timer();
    return true;
}

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

void delqa_c::worker(unsigned instance)
{
    WARNING("DELQA: %s worker(%u) start", DELQA_VERSION, instance);
    if (instance == 0)
        worker_rx();
    else
        worker_tx();
}

void delqa_c::worker_rx(void)
{
    worker_init_realtime_priority(rt_device);
    bool rx_blocked_logged = false;

    while (!workers_terminate) {
        service_timers();

        if (qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (bootrom_pending) {
                process_bootrom();
                bootrom_pending = false;
                continue;
            }

            if (rbdl_pending) {
                WARNING("DELQA: RX list pending set (csr=%06o)", csr);
                rbdl_pending = false;
                dispatch_rbdl();
            }
        }

        if (!rx_ready()) {
            if (!read_queue.empty() && !rx_blocked_logged) {
                WARNING("DELQA: RX blocked (RE=0) with queued packets=%zu", read_queue.size());
                rx_blocked_logged = true;
            }
            timeout_c::wait_ms(1);
            continue;
        }
        rx_blocked_logged = false;

#ifdef HAVE_PCAP
        if (pcap.is_open()) {
            if (!read_queue.empty() && !(csr & XQ_CSR_RL))
                process_rbdl();

            while (true) {
                size_t len = 0;
                if (!pcap.poll(read_buffer.msg.data(), read_buffer.msg.size(), &len)) {
                    WARNING("DELQA: pcap poll error: %s", pcap.last_error().c_str());
                    break;
                }
                if (len == 0)
                    break;

                stats.recv++;
                stat_rx_frames.value = stats.recv;

                read_buffer.len = len;
                read_buffer.used = 0;

                bool consumed = process_local(read_buffer.msg.data(), read_buffer.len);
                if (!consumed)
                    enqueue_readq(2, read_buffer.msg.data(), read_buffer.len, 0);
            }

            if (!read_queue.empty() && !(csr & XQ_CSR_RL))
                process_rbdl();
        }
#endif

        timeout_c::wait_ms(10);
    }
}

void delqa_c::worker_tx(void)
{
    worker_init_realtime_priority(rt_device);

    while (!workers_terminate) {
        if (qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (xbdl_pending) {
                xbdl_pending = false;
                dispatch_xbdl();
            }
        }

        timeout_c::wait_ms(1);
    }
}
