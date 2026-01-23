/*
 * DEQNA Ethernet Controller Emulation for QUniBone
 * (c) Dave Plummer, davepl@davepl.com, Plummer's Software LLC, 2026
 * Contributed under the BSD License
 *
 * This implementation is derived from DEC DEQNA documentation and the
 * OpenSIMH PDP-11 xq (DEQNA) emulator. OpenSIMH attribution:
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
 */

#include <string.h>
#include <stdio.h>
#include <climits>
#include <algorithm>
#include <vector>

#include "logger.hpp"
#include "timeout.hpp"
#include "qunibus.h"
#include "qunibusadapter.hpp"
#include "ddrmem.h"
#include "deqna.hpp"

#if !defined(QBUS)
#error "DEQNA is a QBUS-only device"
#endif

static const size_t ETH_MIN_PACKET = 60;    // Minimum Ethernet frame (no CRC)
static const size_t ETH_MAX_PACKET = 1514;  // Maximum Ethernet frame (no CRC)
static const size_t ETH_FRAME_SIZE = 1518;  // Frame + CRC space

static const unsigned QNA_QUE_MAX = 64;
static const unsigned QNA_SERVICE_INTERVAL = 100; // Timer service rate (Hz)
static const unsigned QNA_HW_SANITY_SECS = 240;

static const uint16_t QNA_DSC_V = QE_RING_VALID;
static const uint16_t QNA_DSC_C = QE_RING_CHAIN;
static const uint16_t QNA_DSC_E = QE_RING_EOMSG;
static const uint16_t QNA_DSC_S = QE_RING_SETUP;
static const uint16_t QNA_DSC_L = QE_RING_ODD_END;
static const uint16_t QNA_DSC_H = QE_RING_ODD_BEGIN;

static const uint16_t QNA_CSR_RI = QE_RCV_INT;
static const uint16_t QNA_CSR_PE = QE_PARITY;
static const uint16_t QNA_CSR_CA = QE_CARRIER;
static const uint16_t QNA_CSR_OK = QE_OK;
static const uint16_t QNA_CSR_SE = QE_STIM_ENABLE;
static const uint16_t QNA_CSR_EL = QE_ELOOP;
static const uint16_t QNA_CSR_IL = QE_ILOOP;
static const uint16_t QNA_CSR_XI = QE_XMIT_INT;
static const uint16_t QNA_CSR_IE = QE_INT_ENABLE;
static const uint16_t QNA_CSR_RL = QE_RL_INVALID;
static const uint16_t QNA_CSR_XL = QE_XL_INVALID;
static const uint16_t QNA_CSR_NI = QE_NEX_MEM_INT;
static const uint16_t QNA_CSR_SR = QE_RESET;
static const uint16_t QNA_CSR_RE = QE_RCV_ENABLE;

static const uint16_t QNA_CSR_RO = QE_CSR_RO;
static const uint16_t QNA_CSR_RW = QE_CSR_RW;
static const uint16_t QNA_CSR_W1 = QE_CSR_W1;
static const uint16_t QNA_CSR_BP = QE_CSR_BP;
static const uint16_t QNA_CSR_XIRI = (QNA_CSR_XI | QNA_CSR_RI);

static const uint16_t QNA_VEC_MS = QE_VEC_MS;
static const uint16_t QNA_VEC_OS = QE_VEC_OS;
static const uint16_t QNA_VEC_RS = QE_VEC_RS;
static const uint16_t QNA_VEC_ST = QE_VEC_ST;
static const uint16_t QNA_VEC_IV = QE_VEC_IV;
static const uint16_t QNA_VEC_ID = QE_VEC_ID;
static const uint16_t QNA_VEC_RO = QE_VEC_RO;
static const uint16_t QNA_VEC_RW = QE_VEC_RW;

static const char *DEQNA_VERSION = "v090";  // Simplified refactor, OpenSIMH-aligned

static const uint16_t QNA_SETUP_MC = 0x0001;  // Accept all multicast
static const uint16_t QNA_SETUP_PM = 0x0002;  // Promiscuous mode
static const uint16_t QNA_SETUP_LD = 0x000C;  // LED control bits
static const uint16_t QNA_SETUP_ST = 0x0070;  // Sanity timer setting

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

static uint8_t word_low(uint16_t w)
{
    return static_cast<uint8_t>(w & 0xff);
}

static uint8_t word_high(uint16_t w)
{
    return static_cast<uint8_t>((w >> 8) & 0xff);
}

deqna_c::deqna_c() : dec_ether_base_c()
{
    set_workers_count(1);

    name.value = "deqna";
    type_name.value = "DEQNA";
    log_label = "deqna";

    set_default_bus_params(DEQNA_DEFAULT_ADDR, DEQNA_DEFAULT_SLOT, DEQNA_DEFAULT_VECTOR, DEQNA_DEFAULT_LEVEL);
    dma_request.set_priority_slot(priority_slot.value);
    dma_desc_request.set_priority_slot(priority_slot.value);
    intr_request.set_priority_slot(priority_slot.value);
    intr_request.set_level(intr_level.value);
    intr_request.set_vector(intr_vector.value & QNA_VEC_IV);

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
    version.value = DEQNA_VERSION;

    mac_addr[0] = 0x08;
    mac_addr[1] = 0x00;
    mac_addr[2] = 0x2B;
    mac_addr[3] = 0xAA;
    mac_addr[4] = 0xBB;
    mac_addr[5] = 0xCC;

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
        intr_request.set_vector(intr_vector.new_value & QNA_VEC_IV);
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

void deqna_c::on_before_uninstall(void)
{
    workers_terminate = true;

    timeout_c timeout;
    const uint64_t start_ns = timeout_c::abstime_ns();
    const uint64_t wait_ns = 200000000ull; // 200ms
    while (timeout_c::abstime_ns() - start_ns < wait_ns) {
        bool any_running = false;
        for (const auto &worker : workers) {
            if (worker.running) {
                any_running = true;
                break;
            }
        }
        if (!any_running)
            return;
        timeout.wait_ms(1);
    }

    WARNING("DEQNA: on_before_uninstall: worker still running after 200ms, "
            "continuing shutdown");
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

    // Update all 6 station address registers (readable via registers 0-5)
    // set_register_dati_value sets the READ value, which is independent of
    // what the driver WRITES to these registers (DATO value for list pointers)
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

void deqna_c::update_transceiver_bits(void)
{
    if (pcap.is_open())
        csr |= QNA_CSR_OK;
    else
        csr &= ~QNA_CSR_OK;

    csr &= ~QNA_CSR_CA;
}

void deqna_c::set_int(void)
{
    irq = true;
    update_intr();
}

void deqna_c::clr_int(void)
{
    irq = false;
    note_intr_deasserted();
    update_intr();
}

void deqna_c::update_intr(void)
{
    bool level = irq && (dma_in_progress.load(std::memory_order_relaxed) == 0);

    if (intr_holdoff_active) {
        uint64_t now = timeout_c::abstime_ns();
        if (now >= intr_holdoff_until_ns) {
            intr_holdoff_active = false;
        } else if (level) {
            irq = false;
            return;
        }
    }

    switch (intr_request.edge_detect(level)) {
    case intr_request_c::INTERRUPT_EDGE_RAISING:
        note_intr_asserted();
        {
            const uint16_t current_vec = intr_request.get_vector();
            const uint16_t masked_vec = static_cast<uint16_t>(current_vec & QNA_VEC_IV);
            if (masked_vec != current_vec)
                intr_request.set_vector(masked_vec);
        }
        qunibusadapter->INTR(intr_request, nullptr, 0);
        break;
    case intr_request_c::INTERRUPT_EDGE_FALLING:
        qunibusadapter->cancel_INTR(intr_request);
        break;
    default:
        break;
    }
}

void deqna_c::on_dma_quiet(void)
{
    // DMA just went idle; re-evaluate interrupt level.
    update_intr();
}

void deqna_c::process_deferred_interrupts(void)
{
    bool do_clr = intr_deferred_clr.exchange(false, std::memory_order_acq_rel);
    bool do_set = intr_deferred_set.exchange(false, std::memory_order_acq_rel);

    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (do_clr) {
        clr_int();
    } else if (do_set) {
        if ((csr & QNA_CSR_IE) && (csr & QNA_CSR_XIRI) && !irq)
            set_int();
    } else if (!irq && (csr & QNA_CSR_IE) && (csr & QNA_CSR_XIRI)) {
        set_int();
    }
}

void deqna_c::csr_set_clr(uint16_t set_bits, uint16_t clear_bits)
{
    uint16_t saved_csr = csr;
    csr = static_cast<uint16_t>((csr | set_bits) & ~clear_bits);

    bool should_assert = (csr & QNA_CSR_IE) && (csr & QNA_CSR_XIRI) && !irq;
    bool ie_cleared = (saved_csr & QNA_CSR_IE) && !(csr & QNA_CSR_IE);
    bool should_deassert = irq && ie_cleared;

    if (in_bus_callback.load(std::memory_order_acquire)) {
        if (should_deassert)
            intr_deferred_clr.store(true, std::memory_order_release);
        else if (should_assert)
            intr_deferred_set.store(true, std::memory_order_release);
    } else {
        if (should_deassert)
            clr_int();
        else if (should_assert)
            set_int();
    }

    update_transceiver_bits();
    update_csr_reg();
}

void deqna_c::note_xl_set(const char *reason, uint32_t desc_ba, const uint16_t *desc_words,
        size_t desc_word_count)
{
    UNUSED(reason);
    UNUSED(desc_ba);
    UNUSED(desc_words);
    UNUSED(desc_word_count);
}

void deqna_c::service_intr_complete(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!intr_request.complete)
        return;
    intr_request.complete = false;
    clr_int();
}

bool deqna_c::wait_for_interrupt_ack(void)
{
    return false;
}

void deqna_c::nxm_error(void)
{
    const uint16_t set_bits = QNA_CSR_XI | QNA_CSR_XL | QNA_CSR_RL | QNA_CSR_NI;
    csr_set_clr(set_bits, 0);
    stats.fail++;
    stat_tx_errors.value = stats.fail;
}

bool deqna_c::rx_ready(void)
{
    if (!(csr & QNA_CSR_RE))
        return false;
    if (csr & QNA_CSR_RL)
        return false;
    return true;
}

void deqna_c::start_rx_delay(void)
{
    rx_delay_active = false;
}

void deqna_c::reset_sanity_timer(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    if (!sanity.enabled)
        return;
    sanity.timer = sanity.max;
}

void deqna_c::service_timers(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint64_t now_ns = timeout_c::abstime_ns();
    if (timers_last_service_ns == 0)
        timers_last_service_ns = now_ns;

    const uint64_t tick_ns = 1000000000ull / QNA_SERVICE_INTERVAL;
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
            reset_controller();
            return;
        }
    }
}

void deqna_c::reset_controller(void)
{
    reset_in_progress.store(true, std::memory_order_release);
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    rbdl[0] = 0;
    rbdl[1] = 0;
    xbdl[0] = 0;
    xbdl[1] = 0;

    var = static_cast<uint16_t>(intr_vector.value & QNA_VEC_IV);
    csr = static_cast<uint16_t>(QNA_CSR_RL | QNA_CSR_XL);

    // Cancel any pending interrupt request in the PRU before resetting state.
    // This prevents stale interrupt requests from blocking DMA arbitration.
    // Always call cancel_INTR - it's safe even if no request is pending.
    qunibusadapter->cancel_INTR(intr_request);
    irq = false;
    intr_request.edge_detect_reset();
    intr_request.set_vector(var & QNA_VEC_IV);

    intr_holdoff_active = true;
    intr_holdoff_until_ns = timeout_c::abstime_ns() + 2000000ull;

    update_mac_checksum();
    update_transceiver_bits();
    update_station_regs();
    update_vector_reg();
    update_csr_reg();

    rbdl_ba = 0;
    xbdl_ba = 0;

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        read_queue.clear();
        read_queue_loss = 0;
    }
    write_buffer.len = 0;
    write_buffer.used = 0;

    setup.valid = false;
    setup.promiscuous = false;
    setup.multicast = false;
    memset(setup.macs, 0, sizeof(setup.macs));

    rbdl_pending = false;
    rbdl_hi_written = false;
    rbdl_lo_written = false;
    tx_state = tx_state_enum::idle;
    tx_kick = false;
    xbdl_hi_written = false;
    xbdl_lo_written = false;
    tx_wait_ba = 0;
    tx_wait_until_ns = 0;

    intr_deferred_set.store(false, std::memory_order_release);
    intr_deferred_clr.store(false, std::memory_order_release);

    sanity.enabled = 0;
    sanity.quarter_secs = QNA_HW_SANITY_SECS * 4;
    sanity.max = static_cast<int>(QNA_HW_SANITY_SECS * QNA_SERVICE_INTERVAL);
    sanity.timer = sanity.max;
    timers_last_service_ns = timeout_c::abstime_ns();

    update_csr_reg();
    update_pcap_filter();
    reset_in_progress.store(false, std::memory_order_release);
}

void deqna_c::sw_reset(void)
{
    reset_in_progress.store(true, std::memory_order_release);
    std::lock_guard<std::recursive_mutex> lock(state_mutex);

    size_t queue_depth = 0;
    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        queue_depth = read_queue.size();
    }
    WARNING("DEQNA: sw_reset: csr=%06o var=%06o rbdl=%06o/%06o xbdl=%06o/%06o rbdl_ba=%06o xbdl_ba=%06o "
            "tx_state=%d tx_kick=%d rbdl_pending=%d irq=%d holdoff=%d deferred_set=%d deferred_clr=%d "
            "queue=%zu",
            csr, var, rbdl[1], rbdl[0], xbdl[1], xbdl[0], rbdl_ba, xbdl_ba,
            static_cast<int>(tx_state), tx_kick ? 1 : 0, rbdl_pending ? 1 : 0, irq ? 1 : 0,
            intr_holdoff_active ? 1 : 0,
            intr_deferred_set.load(std::memory_order_relaxed) ? 1 : 0,
            intr_deferred_clr.load(std::memory_order_relaxed) ? 1 : 0,
            queue_depth);

    rbdl_pending = false;
    rbdl_hi_written = false;
    rbdl_lo_written = false;
    tx_state = tx_state_enum::idle;
    tx_kick = false;
    xbdl_hi_written = false;
    xbdl_lo_written = false;
    tx_wait_ba = 0;
    tx_wait_until_ns = 0;
    rbdl_ba = 0;
    xbdl_ba = 0;
    write_buffer.len = 0;
    write_buffer.used = 0;

    csr = static_cast<uint16_t>(QNA_CSR_XL | QNA_CSR_RL);

    // Cancel any pending interrupt request in the PRU before resetting state.
    // This prevents stale interrupt requests from blocking DMA arbitration.
    // Always call cancel_INTR - it's safe even if no request is pending.
    qunibusadapter->cancel_INTR(intr_request);
    irq = false;
    intr_request.edge_detect_reset();
    intr_request.set_vector(var & QNA_VEC_IV);

    intr_holdoff_active = true;
    intr_holdoff_until_ns = timeout_c::abstime_ns() + 2000000ull;

    intr_deferred_set.store(false, std::memory_order_release);
    intr_deferred_clr.store(false, std::memory_order_release);

    update_mac_checksum();
    update_transceiver_bits();
    update_station_regs();
    update_vector_reg();
    update_csr_reg();

    dma_in_progress.store(0, std::memory_order_release);

    {
        std::lock_guard<std::mutex> queue_lock(queue_mutex);
        read_queue.clear();
        read_queue_loss = 0;
    }

    setup.multicast = false;
    setup.promiscuous = false;
    sanity.timer = sanity.max;
    timers_last_service_ns = timeout_c::abstime_ns();

    update_pcap_filter();

    reset_in_progress.store(false, std::memory_order_release);
}

void deqna_c::update_pcap_filter(void)
{
#ifdef HAVE_PCAP
    if (!pcap.is_open())
        return;

    if (promisc.value || setup.promiscuous) {
        (void)pcap.set_filter("ip or not ip");
        return;
    }

    std::string filter = "ether broadcast";
    if (setup.multicast)
        filter += " or ether multicast";

    auto add_mac = [&](const uint8_t *mac_bytes) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ether dst %02x:%02x:%02x:%02x:%02x:%02x",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        filter += " or ";
        filter += buf;
    };

    add_mac(mac_addr);
    if (setup.valid) {
        for (int i = 0; i < QNA_FILTER_MAX; ++i) {
            if (!mac_is_zero(setup.macs[i]))
                add_mac(setup.macs[i]);
        }
    }

    (void)pcap.set_filter(filter);
#endif
}

bool deqna_c::accept_packet(const uint8_t *data, size_t len) const
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

    for (int i = 0; i < QNA_FILTER_MAX; ++i) {
        if (!mac_is_zero(setup.macs[i]) && mac_equal(dst, setup.macs[i]))
            return true;
    }

    return false;
}

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

void deqna_c::on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
        DATO_ACCESS access)
{
    if (qunibus_control != QUNIBUS_CYCLE_DATO)
        return;

    in_bus_callback.store(true, std::memory_order_release);

    uint16_t val = get_register_dato_value(device_reg);
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        handle_register_write(static_cast<uint8_t>(device_reg->index), val, access);
    }

    in_bus_callback.store(false, std::memory_order_release);
}

void deqna_c::handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access)
{
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
        if (access == DATO_WORD) {
            rbdl_pending = true;
            rbdl_hi_written = false;
            rbdl_lo_written = false;
        } else if (access == DATO_BYTEH) {
            rbdl_hi_written = true;
            if (rbdl_lo_written) {
                rbdl_pending = true;
                rbdl_hi_written = false;
                rbdl_lo_written = false;
            }
        } else { // DATO_BYTEL
            rbdl_lo_written = true;
            if (rbdl_hi_written) {
                rbdl_pending = true;
                rbdl_hi_written = false;
                rbdl_lo_written = false;
            }
        }
        break;
    case DEQNA_REG_XMTLIST_LO:
        xbdl[0] = static_cast<uint16_t>((xbdl[0] & ~byte_mask) | (val & byte_mask));
        break;
    case DEQNA_REG_XMTLIST_HI:
        xbdl[1] = static_cast<uint16_t>((xbdl[1] & ~byte_mask) | (val & byte_mask));
        if (access == DATO_WORD) {
            tx_kick = true;
            xbdl_hi_written = false;
            xbdl_lo_written = false;
        } else if (access == DATO_BYTEH) {
            xbdl_hi_written = true;
            if (xbdl_lo_written) {
                tx_kick = true;
                xbdl_hi_written = false;
                xbdl_lo_written = false;
            }
        } else { // DATO_BYTEL
            xbdl_lo_written = true;
            if (xbdl_hi_written) {
                tx_kick = true;
                xbdl_hi_written = false;
                xbdl_lo_written = false;
            }
        }
        break;
    case DEQNA_REG_VECTOR: {
        uint16_t merged = var;
        if (access == DATO_WORD)
            merged = val;
        else if (access == DATO_BYTEH)
            merged = static_cast<uint16_t>((var & 0x00ff) | (val & 0xff00));
        else
            merged = static_cast<uint16_t>((var & 0xff00) | (val & 0x00ff));

        uint16_t writable = static_cast<uint16_t>(QNA_VEC_RW | QNA_VEC_IV);
        uint16_t new_var = static_cast<uint16_t>((var & ~writable) | (merged & writable));
        new_var &= ~QNA_VEC_MS;
        new_var &= ~(QNA_VEC_OS | QNA_VEC_RS | QNA_VEC_ST | QNA_VEC_ID);

        var = new_var;
        update_vector_reg();
        intr_request.set_vector(var & QNA_VEC_IV);

        if (intr_holdoff_active)
            intr_holdoff_active = false;
        break;
    }
    case DEQNA_REG_CSR: {
        uint16_t prev = csr;
        const uint16_t data_masked = static_cast<uint16_t>(val & byte_mask);
        const uint16_t rw_in_access = static_cast<uint16_t>(QNA_CSR_RW & byte_mask);
        const uint16_t w1_in_access = static_cast<uint16_t>(QNA_CSR_W1 & byte_mask);
        const uint16_t w1_in_data = static_cast<uint16_t>(data_masked & w1_in_access);
        const bool w1c_only = (w1_in_data != 0) && ((data_masked & rw_in_access) == 0);

        uint16_t set_bits = static_cast<uint16_t>(w1c_only ? 0 : (data_masked & rw_in_access));
        uint16_t clr_bits = 0;
        if (w1c_only) {
            clr_bits = static_cast<uint16_t>(w1_in_data |
                                             ((w1_in_data & QNA_CSR_XI) ? QNA_CSR_NI : 0));
        } else {
            clr_bits = static_cast<uint16_t>(((data_masked ^ rw_in_access) & rw_in_access) |
                                             w1_in_data |
                                             ((data_masked & QNA_CSR_XI) ? QNA_CSR_NI : 0));
        }

        if ((byte_mask & QNA_CSR_SR) && (prev & QNA_CSR_SR) && !(data_masked & QNA_CSR_SR)) {
            sw_reset();
            return;
        }

        csr_set_clr(set_bits, clr_bits);

        if ((prev ^ csr) & QNA_CSR_EL)
            update_station_regs();

        if (intr_holdoff_active && ((prev ^ csr) & QNA_CSR_IE) && (csr & QNA_CSR_IE))
            intr_holdoff_active = false;

        if ((csr & QNA_CSR_BP) == QNA_CSR_BP)
            csr_set_clr(0, QNA_CSR_BP);

        if (!in_bus_callback.load(std::memory_order_acquire))
            process_deferred_interrupts();
        break;
    }
    default:
        break;
    }
}

void deqna_c::apply_pending_reg_writes(void)
{
}

void deqna_c::enqueue_readq(int type, const uint8_t *data, size_t len, int status)
{
    std::lock_guard<std::mutex> lock(queue_mutex);

    if (read_queue.size() >= QNA_QUE_MAX) {
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

bool deqna_c::dispatch_rbdl(void)
{
    uint32_t cur_ba = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, QNA_CSR_RL);
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
        cur_ba = rbdl_ba;
    }
    if (cur_ba == 0)
        return false;

    return process_rbdl();
}

bool deqna_c::process_rbdl(void)
{
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        if (csr & QNA_CSR_RL)
            return false;
    }

    bool ri_pending = false;
    bool xi_pending = false;
    unsigned desc_count = 0;
    unsigned processed = 0;
    // Limit RX processing per call to prevent TX starvation during floods.
    // If rx_slots is configured, use that; otherwise default to 8 packets max.
    const unsigned limit = rx_slots.value ? static_cast<unsigned>(rx_slots.value) : 8;
    uint32_t start_rbdl_ba = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        start_rbdl_ba = rbdl_ba;
    }

    while (true) {
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;

        {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            if (read_queue.empty())
                break;
        }

        uint32_t cur_ba = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = rbdl_ba;
        }

        if (desc_count > 0 && cur_ba == start_rbdl_ba)
            break;
        if (++desc_count > 256) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(static_cast<uint16_t>(QNA_CSR_RL | QNA_CSR_RI), 0);
            process_deferred_interrupts();
            return false;
        }

        uint16_t words[QE_RING_WORDS] = {0};
        if (!desc_read_words(cur_ba, words, 4)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            process_deferred_interrupts();
            return false;
        }

        const uint16_t flag_word = 0xFFFF;
        if (!desc_write_words(cur_ba, &flag_word, 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            process_deferred_interrupts();
            return false;
        }

        if (~words[1] & QNA_DSC_V) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(QNA_CSR_RL, 0);
            process_deferred_interrupts();
            return true;
        }

        if (words[1] & QNA_DSC_C) {
            uint32_t next_ba = make_addr(words[1], words[2]) & ~1u;
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
        if (item.packet.used) {
            rbl -= item.packet.used;
        } else {
            if (rbl < ETH_MIN_PACKET) {
                if (item.packet.msg.size() < ETH_MIN_PACKET)
                    item.packet.msg.resize(ETH_MIN_PACKET, 0);
                else
                    memset(&item.packet.msg[rbl], 0, ETH_MIN_PACKET - rbl);
                rbl = ETH_MIN_PACKET;
                item.packet.len = rbl;
            }
            if (rbl > ETH_MAX_PACKET) {
                item.packet.len = ETH_MAX_PACKET;
                rbl = ETH_MAX_PACKET;
            }
        }

        uint8_t *rbuf = item.packet.msg.data() + item.packet.used;
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
        if (rbl && !dma_write_bytes(address, rbuf, rbl)) {
            dma_failed = true;
            rbl = 0;
            item.packet.used = item.packet.len;
        }

        uint16_t status1 = 0;
        uint16_t report_rbl = static_cast<uint16_t>(item.packet.len & 0xFFFF);
        switch (item.type) {
        case 0:
            stats.setup++;
            status1 = static_cast<uint16_t>(QE_ESETUP | 0x0700);
            break;
        case 1:
            stats.loop++;
            status1 = QE_RST_LASTNOERR;
            status1 |= static_cast<uint16_t>(report_rbl & 0x0700);
            if (csr & QNA_CSR_EL)
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
            status1 |= QE_RST_LASTERR | QE_DISCARD;
        } else if (overflow) {
            status1 |= QE_RST_LASTERR | QE_OVF | QE_DISCARD;
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

        if (!desc_write_words(cur_ba + 8, &words[4], 2)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            process_deferred_interrupts();
            return false;
        }

        if (item.packet.used < item.packet.len) {
            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            read_queue.push_front(std::move(item));
        } else {
            ri_pending = true;
            if (item.type < 2)
                xi_pending = true;
        }

        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = cur_ba + QE_RING_BYTES;
        }

        // Throttle RX processing to prevent TX starvation during floods
        if (++processed >= limit)
            break;
    }

    if (ri_pending) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        uint16_t set_bits = QNA_CSR_RI;
        if (xi_pending)
            set_bits |= QNA_CSR_XI;
        csr_set_clr(set_bits, 0);
    }

    process_deferred_interrupts();
    return true;
}

void deqna_c::touch_rbdl_if_idle(void)
{
}

bool deqna_c::dispatch_xbdl(void)
{
    uint32_t cur_ba = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, QNA_CSR_XL);
        xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
        tx_state = tx_state_enum::active;
        cur_ba = xbdl_ba;
        write_buffer.len = 0;
        write_buffer.used = 0;
    }
    if (cur_ba == 0)
        return false;

    return process_xbdl();
}

void deqna_c::write_callback(int status)
{
    UNUSED(status);
}

bool deqna_c::process_xbdl(void)
{
    const uint16_t implicit_chain_status[2] = {static_cast<uint16_t>(QNA_DSC_V | QNA_DSC_C), 1};

    uint32_t start_xbdl_ba = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        start_xbdl_ba = xbdl_ba;
    }

    bool waiting_for_valid = false;
    unsigned desc_count = 0;

    while (true) {
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;

        uint32_t cur_ba = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = xbdl_ba;
        }

        if (desc_count > 0 && cur_ba == start_xbdl_ba)
            break;
        if (++desc_count > 256) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(static_cast<uint16_t>(QNA_CSR_XL | QNA_CSR_XI), 0);
            tx_state = tx_state_enum::idle;
            write_buffer.len = 0;
            write_buffer.used = 0;
            process_deferred_interrupts();
            return false;
        }

        uint16_t words[QE_RING_WORDS] = {0};
        if (!desc_read_words(cur_ba, words, QE_RING_WORDS)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            tx_state = tx_state_enum::idle;
            process_deferred_interrupts();
            return false;
        }

        if (words[1] & QNA_DSC_C) {
            const uint16_t flag_word = 0xFFFF;
            if (!desc_write_words(cur_ba, &flag_word, 1)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                tx_state = tx_state_enum::idle;
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

        if (~words[1] & QNA_DSC_V) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            tx_state = tx_state_enum::wait_valid;
            tx_wait_ba = cur_ba;
            write_buffer.len = 0;
            write_buffer.used = 0;
            process_deferred_interrupts();
            return true;
        }

        // Clear XL now that we have a valid descriptor
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (csr & QNA_CSR_XL)
                csr_set_clr(0, QNA_CSR_XL);
        }

        const uint16_t flag_word = 0xFFFF;
        if (!desc_write_words(cur_ba, &flag_word, 1)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            nxm_error();
            tx_state = tx_state_enum::idle;
            process_deferred_interrupts();
            return false;
        }

        const bool setup_packet = (words[1] & QNA_DSC_S) != 0;
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
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                il_clear = (csr & QNA_CSR_IL) == 0;
                el_set = (csr & QNA_CSR_EL) != 0;
                if (write_buffer.len < ETH_MIN_PACKET) {
                    size_t pad = ETH_MIN_PACKET - write_buffer.len;
                    memset(write_buffer.msg.data() + write_buffer.len, 0, pad);
                    write_buffer.len = ETH_MIN_PACKET;
                }
                len_snapshot = write_buffer.len;
            }
            bool loopback = el_set || il_clear;

            if (loopback || setup_packet) {
                uint16_t write_success[2] = {0x0000, 0x0001};
                if (setup_packet) {
                    process_setup();
                    enqueue_readq(0, write_buffer.msg.data(), write_buffer.len, 0);
                    write_success[0] = 0x200C;
                    write_success[1] = 0x0860;
                } else {
                    enqueue_readq(1, write_buffer.msg.data(), write_buffer.len, 0);
                    write_success[0] = 0x2100;
                }
                if (!desc_write_words(cur_ba + 8, write_success, 2)) {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    nxm_error();
                    tx_state = tx_state_enum::idle;
                    process_deferred_interrupts();
                    return false;
                }

                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    write_buffer.len = 0;
                    write_buffer.used = 0;
                    reset_sanity_timer();
                    xbdl_ba = cur_ba + QE_RING_BYTES;
                }

                process_deferred_interrupts();
            } else {
                const uint16_t TDR = static_cast<uint16_t>(100 + len_snapshot * 8);
                uint16_t write_success[2] = {0x2000, static_cast<uint16_t>(TDR & 0x03FF)};
                uint16_t write_failure[2] = {QNA_DSC_C, static_cast<uint16_t>(TDR & 0x03FF)};

                bool ok = true;
#ifdef HAVE_PCAP
                ok = pcap.send(write_buffer.msg.data(), write_buffer.len);
#endif
                if (!desc_write_words(cur_ba + 8, ok ? write_success : write_failure, 2)) {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    nxm_error();
                    tx_state = tx_state_enum::idle;
                    process_deferred_interrupts();
                    return false;
                }

                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    if (!ok) {
                        stats.fail++;
                        stat_tx_errors.value = stats.fail;
                    }
                    stats.xmit++;
                    stat_tx_frames.value = stats.xmit;
                    write_buffer.len = 0;
                    write_buffer.used = 0;
                    xbdl_ba = cur_ba + QE_RING_BYTES;
                }

                reset_sanity_timer();
                csr_set_clr(QNA_CSR_XI, 0);
                process_deferred_interrupts();
            }
        } else {
            if (!desc_write_words(cur_ba + 8, implicit_chain_status, 2)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                nxm_error();
                tx_state = tx_state_enum::idle;
                process_deferred_interrupts();
                return false;
            }
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            xbdl_ba = cur_ba + QE_RING_BYTES;
        }
    }

    if (!waiting_for_valid) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        if (tx_state != tx_state_enum::wait_valid)
            tx_state = tx_state_enum::idle;
    }

    process_deferred_interrupts();
    return true;
}

void deqna_c::process_setup(void)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint8_t *msg = write_buffer.msg.data();
    size_t len = write_buffer.len;

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

    setup.promiscuous = false;
    setup.multicast = false;

    if (len > 128) {
        const uint16_t len16 = static_cast<uint16_t>(len & 0xffff);
        setup.multicast = (0 != (len16 & QNA_SETUP_MC));
        setup.promiscuous = (0 != (len16 & QNA_SETUP_PM));

        uint16_t san = static_cast<uint16_t>((len16 & QNA_SETUP_ST) >> 4);
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
    }

    sanity.timer = sanity.max;
    sanity.enabled = (csr & QNA_CSR_SE) ? 1 : 0;

    setup.valid = true;
    update_pcap_filter();
}

void deqna_c::dump_descriptor_rings(const char *reason)
{
    UNUSED(reason);
}

bool deqna_c::process_local(const uint8_t *data, size_t len)
{
    UNUSED(data);
    UNUSED(len);
    return false;
}

bool deqna_c::process_loopback(const uint8_t *data, size_t len)
{
    UNUSED(data);
    UNUSED(len);
    return false;
}

bool deqna_c::process_remote_console(const uint8_t *data, size_t len)
{
    UNUSED(data);
    UNUSED(len);
    return false;
}

bool deqna_c::send_system_id(const uint8_t *dest, uint16_t receipt_id)
{
    UNUSED(dest);
    UNUSED(receipt_id);
    return false;
}

void deqna_c::worker(unsigned instance)
{
    UNUSED(instance);
    worker_init_realtime_priority(rt_device);

    uint8_t pkt_buf[2048];
    while (!workers_terminate) {
        if (reset_in_progress.load(std::memory_order_acquire)) {
            timeout_c::wait_ms(1);
            continue;
        }

        service_timers();
        service_intr_complete();
        process_deferred_interrupts();

        if (init_asserted || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }

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
                do_process = true;
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

        bool do_rbdl = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (rbdl_pending) {
                rbdl_pending = false;
                do_rbdl = true;
            }
        }
        if (do_rbdl)
            dispatch_rbdl();

#ifdef HAVE_PCAP
        bool capture_enabled = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (csr & QNA_CSR_RE)
                capture_enabled = true;
        }
        if (pcap.is_open() && capture_enabled) {
            size_t len = 0;
            if (!pcap.poll(pkt_buf, sizeof(pkt_buf), &len)) {
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
                    enqueue_readq(2, pkt_buf, len, 0);
            }
        }
#endif

        process_rbdl();
        process_deferred_interrupts();

        timeout_c::wait_ms(1);
    }
}
