/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2026 Plummer's Software LLC
 * Contributed under the GPL2 License
 */
#ifndef _DELQA_HPP_
#define _DELQA_HPP_

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <mutex>

#include "qunibusdevice.hpp"
#include "priorityrequest.hpp"
#include "parameter.hpp"
#include "pcap_bridge.hpp"
#include "delqa_regs.h"

// Default DELQA parameters (offset within IOPAGE)
#define DELQA_DEFAULT_ADDR 014440
#define DELQA_DEFAULT_SLOT 18
#define DELQA_DEFAULT_VECTOR 0154
#define DELQA_DEFAULT_LEVEL 5

class delqa_c : public qunibusdevice_c {
public:
    delqa_c();
    ~delqa_c() override;

    parameter_string_c ifname = parameter_string_c(this, "ifname", "if", false,
            "Host interface for libpcap, e.g. \"eth0\"");
    parameter_string_c mac = parameter_string_c(this, "mac", "mac", false,
            "MAC address override (aa:bb:cc:dd:ee:ff), empty = device default");
    parameter_bool_c promisc = parameter_bool_c(this, "promisc", "pr", false,
            "Enable libpcap promiscuous capture");
    parameter_unsigned_c rx_slots = parameter_unsigned_c(this, "rx_slots", "rx", false, "",
            "%d", "RX ring scan limit (0 = default)", 16, 10);
    parameter_unsigned_c tx_slots = parameter_unsigned_c(this, "tx_slots", "tx", false, "",
            "%d", "TX ring scan limit (0 = default)", 16, 10);
    parameter_bool_c trace = parameter_bool_c(this, "trace", "tr", false,
            "Trace CSR/ring events to log");

    // Read-only statistics (updated during operation)
    parameter_unsigned64_c stat_rx_frames = parameter_unsigned64_c(this, "rx_frames", "rxf", true, "",
            "%llu", "Received frames count", 64, 10);
    parameter_unsigned64_c stat_tx_frames = parameter_unsigned64_c(this, "tx_frames", "txf", true, "",
            "%llu", "Transmitted frames count", 64, 10);
    parameter_unsigned64_c stat_rx_errors = parameter_unsigned64_c(this, "rx_errors", "rxe", true, "",
            "%llu", "Receive error count", 64, 10);
    parameter_unsigned64_c stat_tx_errors = parameter_unsigned64_c(this, "tx_errors", "txe", true, "",
            "%llu", "Transmit error count", 64, 10);

    bool on_param_changed(parameter_c *param) override;
    bool on_before_install(void) override;
    void on_after_install(void) override;
    void on_after_uninstall(void) override;

    void on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge) override;
    void on_init_changed(void) override;

    void on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
            DATO_ACCESS access) override;

    void worker(unsigned instance) override;

private:
    qunibusdevice_register_t *reg_sta_addr[6] = {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
    qunibusdevice_register_t *reg_rcvlist_lo = nullptr;
    qunibusdevice_register_t *reg_rcvlist_hi = nullptr;
    qunibusdevice_register_t *reg_xmtlist_lo = nullptr;
    qunibusdevice_register_t *reg_xmtlist_hi = nullptr;
    qunibusdevice_register_t *reg_vector = nullptr;
    qunibusdevice_register_t *reg_csr = nullptr;

    intr_request_c intr_request = intr_request_c(this);
    dma_request_c dma_request = dma_request_c(this);

    PcapBridge pcap;

    std::recursive_mutex state_mutex;
    std::recursive_mutex dma_mutex;

    uint16_t rcvlist_lo = 0;
    uint16_t rcvlist_hi = 0;
    uint16_t xmtlist_lo = 0;
    uint16_t xmtlist_hi = 0;
    uint16_t qe_vector = 0;
    uint16_t qe_csr = 0;

    uint32_t rcvlist_addr = 0;
    uint32_t xmtlist_addr = 0;
    uint32_t rx_cur_addr = 0;
    uint32_t tx_cur_addr = 0;

    bool mac_override = false;
    uint8_t mac_addr[6] = {0};
    uint8_t mac_checksum[2] = {0};

    // Setup packet state
    bool setup_valid = false;
    bool setup_promiscuous = false;
    bool setup_multicast = false;
    uint8_t setup_macs[XQ_FILTER_MAX][6] = {{0}};

    bool deqna_lock = false;
    bool rx_delay_active = false;
    uint64_t rx_enable_deadline_ns = 0;

    // Statistics counters
    uint64_t rx_frames = 0;
    uint64_t tx_frames = 0;
    uint64_t rx_errors = 0;
    uint64_t tx_errors = 0;

    void reset_controller(void);

    void update_mac_checksum(void);
    void update_station_regs(void);
    void update_vector_reg(void);
    void update_csr_reg(void);
    void update_transceiver_bits(void);
    void update_intr(void);
    bool get_intr_level(void) const;

    void start_rx_delay(void);
    bool rx_ready(void);
    bool loopback_enabled(void) const;

    void worker_rx(void);
    void worker_tx(void);

    bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    bool dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len);

    bool read_descriptor(uint32_t addr, uint16_t words[QE_RING_WORDS]);
    bool write_descriptor(uint32_t addr, const uint16_t words[QE_RING_WORDS]);

    bool rx_place_frame(const uint8_t *data, size_t len);
    bool tx_take_frame(std::vector<uint8_t> &frame);
    bool process_setup_packet(const std::vector<uint8_t> &frame);

    uint32_t make_addr(uint16_t hi, uint16_t lo) const;
    uint32_t next_desc_addr(uint32_t addr) const;
    void set_nxm_error(void);

    bool rcv_enabled(void) const;
    bool xmt_enabled(void) const;
    unsigned rx_scan_limit(void) const;
    unsigned tx_scan_limit(void) const;

    static bool parse_mac(const std::string &text, uint8_t out[6]);
};

#endif
