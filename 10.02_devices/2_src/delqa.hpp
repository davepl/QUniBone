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
#include <deque>
#include <mutex>

#include "qunibusdevice.hpp"
#include "priorityrequest.hpp"
#include "parameter.hpp"
#include "pcap_bridge.hpp"
#include "delqa_regs.h"

// Default DELQA parameters (offset within IOPAGE)
#define DELQA_DEFAULT_ADDR 014440
#define DELQA_DEFAULT_SLOT 18
#define DELQA_DEFAULT_VECTOR 0  // Vector is software-programmable via VAR register
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
            "%d", "RX ring scan limit (0 = no limit)", 16, 10);
    parameter_unsigned_c tx_slots = parameter_unsigned_c(this, "tx_slots", "tx", false, "",
            "%d", "TX ring scan limit (0 = no limit)", 16, 10);
    parameter_unsigned_c rx_start_delay_ms = parameter_unsigned_c(this, "rx_start_delay_ms", "rxd", false, "",
            "%d", "Receiver start delay in ms", 16, 10);
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

    struct setup_state {
        bool valid = false;
        bool promiscuous = false;
        bool multicast = false;
        bool l1 = true;
        bool l2 = true;
        bool l3 = true;
        int sanity_timer = 0;
        uint8_t macs[XQ_FILTER_MAX][6] = {{0}};
    } setup;

    struct sanity_state {
        int enabled = 0; // 2=HW, 1=SW, 0=off
        int quarter_secs = 0;
        int max = 0;
        int timer = 0;
    } sanity;

    struct stats_state {
        uint64_t recv = 0;
        uint64_t filter = 0;
        uint64_t xmit = 0;
        uint64_t fail = 0;
        uint64_t runt = 0;
        uint64_t giant = 0;
        uint64_t setup = 0;
        uint64_t loop = 0;
    } stats;

    struct packet_buffer {
        std::vector<uint8_t> msg;
        size_t len = 0;
        size_t used = 0;
        int status = 0;
    } read_buffer, write_buffer;

    struct queue_item {
        int type = 0; // 0=setup, 1=loopback, 2=normal
        packet_buffer packet;
    };

    std::deque<queue_item> read_queue;
    unsigned read_queue_loss = 0;

    uint16_t rbdl[2] = {0, 0};
    uint16_t xbdl[2] = {0, 0};
    uint16_t var = 0;
    uint16_t csr = 0;
    bool irq = false;

    uint32_t rbdl_ba = 0;
    uint32_t xbdl_ba = 0;

    bool mac_override = false;
    uint8_t mac_addr[6] = {0};
    uint8_t mac_checksum[2] = {0};

    bool deqna_lock = false;
    bool rx_delay_active = false;
    uint64_t rx_enable_deadline_ns = 0;
    bool bootrom_pending = false;
    bool rbdl_pending = false;
    bool xbdl_pending = false;

    int idtmr = 0;

    std::vector<uint8_t> bootrom_image;
    bool bootrom_ready = false;

    void reset_controller(void);
    void sw_reset(void);

    void update_mac_checksum(void);
    void update_station_regs(void);
    void update_vector_reg(void);
    void update_csr_reg(void);
    void update_transceiver_bits(void);
    void update_intr(void);

    void set_int(void);
    void clr_int(void);
    void csr_set_clr(uint16_t set_bits, uint16_t clear_bits);
    void nxm_error(void);

    void start_rx_delay(void);
    bool rx_ready(void);

    void update_pcap_filter(void);

    void worker_rx(void);
    void worker_tx(void);

    bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    bool dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len);

    uint32_t make_addr(uint16_t hi, uint16_t lo) const;

    void enqueue_readq(int type, const uint8_t *data, size_t len, int status);
    bool process_rbdl(void);
    bool dispatch_rbdl(void);

    bool process_xbdl(void);
    bool dispatch_xbdl(void);
    void write_callback(int status);

    void process_setup(void);
    bool process_bootrom(void);
    bool ensure_bootrom_image(void);
    void touch_rbdl_if_idle(void);

    bool process_local(const uint8_t *data, size_t len);
    bool process_loopback(const uint8_t *data, size_t len);
    bool process_remote_console(const uint8_t *data, size_t len);
    bool send_system_id(const uint8_t *dest, uint16_t receipt_id);

    void reset_sanity_timer(void);
    void service_timers(void);

    static bool parse_mac(const std::string &text, uint8_t out[6]);
};

#endif
