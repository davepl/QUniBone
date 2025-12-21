/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2025 Plummer's Software LLC
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
#ifdef HAVE_PCAP
#include "pcap_bridge.hpp"
#endif
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
            "MAC address override (aa:bb:cc:dd:ee:ff), empty = use init block");
    parameter_bool_c promisc = parameter_bool_c(this, "promisc", "pr", false,
            "Enable libpcap promiscuous capture");
    parameter_unsigned_c rx_slots = parameter_unsigned_c(this, "rx_slots", "rx", false, "",
            "%d", "RX ring slots (power of two)", 16, 10);
    parameter_unsigned_c tx_slots = parameter_unsigned_c(this, "tx_slots", "tx", false, "",
            "%d", "TX ring slots (power of two)", 16, 10);
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
    void on_after_uninstall(void) override;

    void on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge) override;
    void on_init_changed(void) override;

    void on_after_register_access(qunibusdevice_register_t *device_reg, uint8_t qunibus_control,
            DATO_ACCESS access) override;

    void worker(unsigned instance) override;

private:
    struct ring_state_t {
        uint32_t base_addr;
        uint16_t slots;
        uint16_t index;
    };

    qunibusdevice_register_t *reg_rdp = nullptr;
    qunibusdevice_register_t *reg_rap = nullptr;
    qunibusdevice_register_t *reg_rst = nullptr;

    intr_request_c intr_request = intr_request_c(this);
    dma_request_c dma_request = dma_request_c(this);

#ifdef HAVE_PCAP
    PcapBridge pcap;
#endif

    std::recursive_mutex state_mutex;
    std::recursive_mutex dma_mutex;

    uint16_t csr_sel = 0;
    uint16_t csr0 = 0;
    uint16_t csr1 = 0;
    uint16_t csr2 = 0;
    uint16_t csr3 = 0;

    ring_state_t rx_ring = {0, 0, 0};
    ring_state_t tx_ring = {0, 0, 0};

    bool started = false;
    bool init_done = false;

    bool mac_override = false;
    uint8_t mac_addr[6] = {0};

    // Statistics counters
    uint64_t rx_frames = 0;
    uint64_t tx_frames = 0;
    uint64_t rx_errors = 0;
    uint64_t tx_errors = 0;

    void reset_controller(void);

    void update_rdp(void);
    void update_rap(void);
    void update_intr(void);
    bool get_intr_level(void) const;

    void handle_init(void);
    void handle_start(void);
    void handle_stop(void);

    void worker_rx(void);
    void worker_tx(void);

    bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    bool dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len);

    bool read_descriptor(uint32_t addr, uint16_t words[DELQA_DESC_WORDS]);
    bool write_descriptor(uint32_t addr, const uint16_t words[DELQA_DESC_WORDS]);

    bool rx_place_frame(const uint8_t *data, size_t len);
    bool tx_take_frame(std::vector<uint8_t> &frame);

    static bool parse_mac(const std::string &text, uint8_t out[6]);
    static bool is_power_of_two(unsigned val);
};

#endif
