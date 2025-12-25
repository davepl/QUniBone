/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2026 Plummer's Software LLC
 * Contributed under the GPL2 License
 *
 * DEUNA Ethernet Controller Emulation for QUniBone
 * ================================================
 *
 * This module emulates the DEC DEUNA (UNIBUS Ethernet controller).
 * It provides a port-command interface (PCSR0-3) with descriptor
 * rings in host memory, and bridges Ethernet frames to a host
 * interface using libpcap.
 */
#ifndef _DEUNA_HPP_
#define _DEUNA_HPP_

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "qunibusdevice.hpp"
#include "priorityrequest.hpp"
#include "parameter.hpp"
#include "pcap_bridge.hpp"

/*
 * Default DEUNA I/O page parameters
 * Base address is a typical DEUNA CSR location (octal)
 */
#define DEUNA_DEFAULT_ADDR 0174510
#define DEUNA_DEFAULT_SLOT 18
#define DEUNA_DEFAULT_VECTOR 0120
#define DEUNA_DEFAULT_LEVEL 5

#define DEUNA_FILTER_MAX 12
#define DEUNA_UDB_WORDS 200

#define DEUNA_REG_PCSR0 0
#define DEUNA_REG_PCSR1 1
#define DEUNA_REG_PCSR2 2
#define DEUNA_REG_PCSR3 3

class deuna_c : public qunibusdevice_c {
public:
    deuna_c();
    ~deuna_c() override;

    /*
     * User-configurable parameters (set via menu system before install)
     */
    parameter_string_c ifname = parameter_string_c(this, "ifname", "if", false,
            "Host interface for libpcap, e.g. \"eth0\"");
    parameter_string_c mac = parameter_string_c(this, "mac", "mac", false,
            "MAC address override (aa:bb:cc:dd:ee:ff), empty = device default");
    parameter_bool_c promisc = parameter_bool_c(this, "promisc", "pr", false,
            "Enable libpcap promiscuous capture");
    parameter_unsigned_c rx_slots = parameter_unsigned_c(this, "rx_slots", "rx", false, "",
            "%d", "RX ring scan limit (0 = no limit)", 0, 10);
    parameter_unsigned_c tx_slots = parameter_unsigned_c(this, "tx_slots", "tx", false, "",
            "%d", "TX ring scan limit (0 = no limit)", 0, 10);
    parameter_bool_c trace = parameter_bool_c(this, "trace", "tr", false,
            "Trace CSR/ring events to log");

    /*
     * Read-only statistics (updated during operation, visible in menu)
     */
    parameter_unsigned64_c stat_rx_frames = parameter_unsigned64_c(this, "rx_frames", "rxf", true, "",
            "%llu", "Received frames count", 64, 10);
    parameter_unsigned64_c stat_tx_frames = parameter_unsigned64_c(this, "tx_frames", "txf", true, "",
            "%llu", "Transmitted frames count", 64, 10);
    parameter_unsigned64_c stat_rx_errors = parameter_unsigned64_c(this, "rx_errors", "rxe", true, "",
            "%llu", "Receive error count", 64, 10);
    parameter_unsigned64_c stat_tx_errors = parameter_unsigned64_c(this, "tx_errors", "txe", true, "",
            "%llu", "Transmit error count", 64, 10);

    /*
     * QUniBone device framework callbacks
     */
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
    /*
     * Device Registers
     */
    qunibusdevice_register_t *reg_pcsr0 = nullptr;
    qunibusdevice_register_t *reg_pcsr1 = nullptr;
    qunibusdevice_register_t *reg_pcsr2 = nullptr;
    qunibusdevice_register_t *reg_pcsr3 = nullptr;

    /*
     * Bus requests for interrupts and DMA
     */
    intr_request_c intr_request = intr_request_c(this);
    dma_request_c dma_request = dma_request_c(this);
    dma_request_c dma_desc_request = dma_request_c(this);

    /*
     * Network bridge to host interface via libpcap
     */
    PcapBridge pcap;

    /*
     * Thread synchronization
     */
    std::recursive_mutex state_mutex;
    std::recursive_mutex dma_mutex;
    std::mutex queue_mutex;  // New: Serialize queue access from PCAP callbacks
    std::atomic<bool> reset_in_progress{false};  // New: Flag to abort worker operations during reset

    /*
     * Pending register writes from PDP-11 (preserve write order)
     */
    struct pending_reg_write {
        uint8_t reg_index = 0;
        uint16_t value = 0;
        uint8_t access = 0;
        uint16_t w1c_snapshot = 0;
    };
    std::mutex pending_reg_mutex;
    std::deque<pending_reg_write> pending_reg_queue;

    /*
     * Pending port command for worker thread (DMA required)
     */
    std::mutex pending_cmd_mutex;
    std::condition_variable pending_cmd_cv;
    uint16_t pending_cmd = 0;  // 0 = no command pending

    /*
     * Setup packet state (MAC filtering)
     */
    struct setup_state {
        bool valid = false;
        bool promiscuous = false;
        bool multicast = false;
        int mac_count = 0;
        uint8_t macs[DEUNA_FILTER_MAX][6] = {{0}};
    } setup;

    /*
     * Network statistics
     */
    struct stats_state {
        uint32_t secs = 0;
        uint32_t frecv = 0;
        uint32_t mfrecv = 0;
        uint16_t rxerf = 0;
        uint16_t frecve = 0;
        uint32_t rbytes = 0;
        uint32_t mrbytes = 0;
        uint16_t rlossi = 0;
        uint16_t rlossl = 0;
        uint32_t ftrans = 0;
        uint32_t mftrans = 0;
        uint32_t ftrans3 = 0;
        uint32_t ftrans2 = 0;
        uint32_t ftransd = 0;
        uint32_t tbytes = 0;
        uint32_t mtbytes = 0;
        uint16_t txerf = 0;
        uint16_t ftransa = 0;
        uint16_t txccf = 0;
        uint16_t porterr = 0;
        uint16_t bablcnt = 0;
        uint64_t last_update_ns = 0;
    } stats;

    /*
     * Packet buffer for RX/TX operations
     */
    struct packet_buffer {
        std::vector<uint8_t> msg;
        size_t len = 0;
        size_t used = 0;
        size_t crc_len = 0;
        int status = 0;
    } read_buffer, write_buffer;

    /*
     * Queue item for received packets waiting to be delivered
     */
    struct queue_item {
        bool loopback = false;
        packet_buffer packet;
    };

    std::deque<queue_item> read_queue;
    unsigned read_queue_loss = 0;

    /*
     * Port command and ring state
     */
    uint16_t pcsr0 = 0;
    uint16_t pcsr1 = 0;
    uint16_t pcsr2 = 0;
    uint16_t pcsr3 = 0;
    uint32_t mode = 0;
    uint16_t stat = 0;
    bool irq = false;

    uint32_t pcbb = 0;
    uint32_t tdrb = 0;
    uint32_t telen = 0;
    uint32_t trlen = 0;
    uint32_t txnext = 0;
    uint32_t rdrb = 0;
    uint32_t relen = 0;
    uint32_t rrlen = 0;
    uint32_t rxnext = 0;

    uint16_t pcb[4] = {0};
    uint16_t udb[DEUNA_UDB_WORDS] = {0};
    uint16_t rxhdr[4] = {0};
    uint16_t txhdr[4] = {0};

    uint8_t load_server[6] = {0};

    /*
     * MAC address state
     */
    bool mac_override = false;
    uint8_t mac_addr[6] = {0};

    /*
     * Controller reset/initialization
     */
    void reset_controller(void);

    /*
     * Register value update functions
     */
    void update_pcsr_regs(void);
    void update_transceiver_bits(void);
    void update_intr(void);

    /*
     * Register write handling
     */
    void handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access,
            uint16_t w1c_snapshot);
    void apply_pending_reg_writes(void);
    void process_pending_command(void);

    /*
     * DMA operations
     */
    bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool desc_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool desc_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    bool dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len);
    bool cpu_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool cpu_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    void log_pcbb_snapshot(const char *tag, uint32_t addr);

    uint32_t make_addr(uint16_t hi, uint16_t lo) const;

    /*
     * Port command processing
     */
    void port_command(uint16_t cmd);
    bool execute_command(void);

    /*
     * Receive/transmit ring processing
     */
    void enqueue_readq(const uint8_t *data, size_t len, bool loopback);
    bool process_receive(void);
    bool process_transmit(void);
    void dump_tx_ring(unsigned max_entries);

    /*
     * Packet filtering
     */
    bool accept_packet(const uint8_t *data, size_t len) const;
    void update_pcap_filter(void);

    /*
     * Timer services
     */
    void service_timers(void);

    /*
     * Worker thread entry points
     */
    void worker_rx(void);
    void worker_tx(void);

    /*
     * Utility
     */
    static bool parse_mac(const std::string &text, uint8_t out[6]);
};

#endif
