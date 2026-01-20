/* deqna.hpp - Simplified DEQNA Ethernet Controller Emulation
 *
 * Minimal DEQNA (M7504) implementation for QUniBone:
 * - TX/RX packet handling via descriptor rings
 * - Internal/external loopback
 * - Setup packet processing
 * - STA ON deferred interrupt (400µs delay after SR clear)
 *
 * Copyright (c) 2024-2026 QUniBone project
 */

#ifndef _DEQNA_HPP_
#define _DEQNA_HPP_

#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <algorithm>

#include "logger.hpp"
#include "timeout.hpp"
#include "qunibus.h"
#include "qunibusadapter.hpp"
#include "ddrmem.h"
#include "qunibusdevice.hpp"
#include "priorityrequest.hpp"
#include "pcap_bridge.hpp"
#include "deqna_regs.h"

// Constants not in deqna_regs.h
#define ETH_MIN_PACKET  60      // Minimum Ethernet packet size
#define ETH_MAX_PACKET  1514    // Maximum Ethernet packet size
#define QNA_FILTER_MAX  14      // Max MAC addresses in filter

class deqna_c : public qunibusdevice_c {
public:
    deqna_c();
    virtual ~deqna_c();

    bool on_param_changed(parameter_c *param) override;
    bool on_before_install(void) override;
    void on_after_install(void) override;
    void on_after_uninstall(void) override;
    void on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge) override;
    void on_init_changed(void) override;
    void worker(unsigned instance) override;

private:
    // Packet buffer structure
    struct packet_t {
        std::vector<uint8_t> msg;
        size_t len = 0;
        size_t used = 0;
        int type = 2;  // 0=setup, 1=loopback, 2=normal
        packet_t() : msg(ETH_MAX_PACKET + 64) {}
    };

    // Setup configuration
    struct setup_t {
        uint8_t macs[QNA_FILTER_MAX][6] = {};
        bool valid = false;
        bool promiscuous = false;
        bool multicast = false;
    };

    // Parameters
    parameter_string_c version = parameter_string_c(this, "version", "ver", /*readonly*/true,
            "DEQNA driver version");
    parameter_string_c ifname = parameter_string_c(this, "ifname", "if", false,
            "Host interface for libpcap, e.g. \"eth0\"");
    parameter_string_c mac = parameter_string_c(this, "mac", "mac", false,
            "MAC address (aa:bb:cc:dd:ee:ff)");
    parameter_bool_c trace = parameter_bool_c(this, "trace", "tr", false,
            "Trace events to log");

    // Bus requests
    intr_request_c intr_request;
    dma_request_c dma_request;

    // Network bridge
    PcapBridge pcap;

    // State protected by state_mutex
    std::recursive_mutex state_mutex;
    std::recursive_mutex dma_mutex;     // Serialize DMA operations
    uint16_t csr = 0;                   // Control/Status Register
    uint16_t var = 0;                   // Vector Address Register
    uint16_t rbdl[2] = {0, 0};          // Receive base address registers
    uint16_t xbdl[2] = {0, 0};          // Transmit base address registers
    uint32_t rbdl_ba = 0;               // Current RX descriptor address
    uint32_t xbdl_ba = 0;               // Current TX descriptor address
    uint8_t mac_addr[6] = {};           // MAC address
    setup_t setup;                      // Setup packet configuration
    packet_t write_buffer;              // TX packet assembly buffer
    std::atomic<bool> irq{false};       // Interrupt request pending (atomic for cross-thread visibility)
    bool var_written = false;           // VAR has been written - interrupts allowed
    bool tx_kick = false;               // TX dispatch requested
    bool rx_kick = false;               // RX dispatch requested
    
    // STA ON deferred interrupt timing
    uint64_t sta_on_deadline_ns = 0;    // When to assert OK bit after SR clear
    static constexpr uint64_t STA_ON_DELAY_NS = 400000; // 400µs delay

    // Setup/loopback RX delivery timing (400µs delay like real hardware)
    uint64_t setup_rx_deadline_ns = 0;  // When setup/loopback RX can be delivered
    static constexpr uint64_t SETUP_RX_DELAY_NS = 400000; // 400µs delay
    
    // Interrupt cooldown - don't do DMA immediately after interrupt is cleared
    // PRU may still be completing IACK cycle
    uint64_t intr_cooldown_ns = 0;      // Time when DMA can resume after interrupt clear
    static constexpr uint64_t INTR_COOLDOWN_NS = 100000; // 100µs cooldown after interrupt clear

    // RX queue protected by queue_mutex
    std::mutex queue_mutex;
    std::deque<packet_t> read_queue;

    // Atomic flags
    std::atomic<bool> reset_in_progress{false};

    // Core functions
    void reset_controller();
    void sw_reset();
    
    // Register access
    void on_after_register_access(qunibusdevice_register_t *device_reg,
                                   uint8_t unibus_control, DATO_ACCESS access) override;
    void handle_register_write(uint8_t reg_idx, uint16_t value, DATO_ACCESS access);
    void update_all_registers();  // Pre-populate all register DATI values
    void csr_set_clr(uint16_t set_bits, uint16_t clr_bits);
    void update_csr_reg();
    void update_intr();

    // DMA helpers
    bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    uint32_t make_addr(uint16_t hi, uint16_t lo);

    // TX processing
    bool dispatch_xbdl();
    bool process_xbdl();
    void process_setup();

    // RX processing  
    bool dispatch_rbdl();
    bool process_rbdl();
    void enqueue_rx(int type, const uint8_t *data, size_t len);
    
    // Packet filtering
    bool accept_packet(const uint8_t *data, size_t len);
    bool mac_match(const uint8_t *a, const uint8_t *b);
    bool mac_is_zero(const uint8_t *a);
    bool mac_is_broadcast(const uint8_t *a);
    bool mac_is_multicast(const uint8_t *a);
};

#endif // _DEQNA_HPP_
