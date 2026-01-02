/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2026 Plummer's Software LLC
 * Contributed under the GPL2 License
 *
 * DEQNA Ethernet Controller Emulation for QUniBone
 * ================================================
 *
 * This module emulates the DEC DEQNA (M7504) Q-bus Ethernet controller.
 *
 * HARDWARE OVERVIEW:
 * ------------------
 * The DEQNA occupies 16 bytes of I/O space and provides:
 *   - Six station address registers (SA0-SA5): Read MAC or checksum
 *   - RCV list address (RCLL/RCLH): 22-bit pointer to RX descriptor ring
 *   - XMT list address (XMTL/XMTH): 22-bit pointer to TX descriptor ring
 *   - Vector Address Register (VAR): Interrupt vector and mode control
 *   - Control/Status Register (CSR): Device control and status
 *
 * DMA DESCRIPTOR RING ARCHITECTURE:
 * ---------------------------------
 * Both TX and RX use linked descriptor rings in host memory. Each descriptor
 * is 12 bytes (6 words):
 *   Word 0: Flag word (0xFFFF when in-use by device)
 *   Word 1: Address high bits + control flags (V=valid, C=chain, E=end, S=setup, L/H=length adjust)
 *   Word 2: Buffer address low 16 bits
 *   Word 3: Buffer length (one's complement)
 *   Word 4: Status word 1 (written by device after completion)
 *   Word 5: Status word 2 (written by device after completion)
 *
 * THREADING MODEL:
 * ----------------
 * Two worker threads handle RX and TX independently:
 *   - Instance 0 (worker_rx): Polls pcap for incoming packets, processes RX ring
 *   - Instance 1 (worker_tx): Processes TX ring when software writes XMTH
 *
 * Register writes from the PDP-11 are captured atomically and processed by
 * the appropriate worker thread to avoid DMA deadlocks (the PRU can grant
 * the bus to DMA while holding a register access pending).
 *
 * LOOPBACK MODE:
 * --------------
 * Loopback is controlled by CSR bits IL (internal) and EL (external):
 *   - IL=0 (internal loopback) OR EL=1 (external loopback) → packets loop back
 *   - This behavior is derived from hardware testing, independent of RE
 *
 * NETWORK BRIDGING:
 * -----------------
 * libpcap bridges the emulated Ethernet to a real host interface. The pcap
 * filter is dynamically updated based on setup packet contents and promisc
 * mode to minimize unnecessary packet processing.
 *
 * REFERENCE:
 * ----------
 * This implementation derives behavior from reference behavior where the
 * hardware documentation is ambiguous. Key compatibility behaviors:
 *   - Descriptor base address is recalculated from registers on each dispatch
 *   - Loopback is IL=0 OR EL=1 (not AND, not dependent on RE)
 *   - Boot ROM handling is not applicable for DEQNA
 * 
 * Ring Buffer Architecture
 * ------------------------
 * 
 *  ┌────────────────────────────────────────────────────────────────┐
 *  │                      BeagleBone (Linux)                        │
 *  │  ┌──────────────┐    ┌──────────────────────────────────────┐  │
 *  │  │ Host Network │───▶│ read_queue (up to 500 packets)       │  │
 *  │  │   (pcap)     │    │ std::deque in Linux memory           │  │
 *  │  └──────────────┘    └───────────────┬──────────────────────┘  │
 *  │                                      │ DMA                     │
 *  └──────────────────────────────────────│─────────────────────────┘
 *                                         ▼
 *  ┌────────────────────────────────────────────────────────────────┐
 *  │                    PDP-11 System Memory                        │
 *  │  ┌─────────────────────────────────────────────────────────┐   │
 *  │  │ RX Descriptor Ring (driver-allocated, 4-16 descriptors) │   │
 *  │  │ rbdl_ba → [desc0] → [desc1] → [desc2] → ... (C=0 ends)  │   │
 *  │  └─────────────────────────────────────────────────────────┘   │
 *  │  ┌─────────────────────────────────────────────────────────┐   │
 *  │  │ TX Descriptor Ring (driver-allocated, 4-16 descriptors) │   │
 *  │  │ xbdl_ba → [desc0] → [desc1] → [desc2] → ... (C=0 ends)  │   │
 *  │  └─────────────────────────────────────────────────────────┘   │
 *  └────────────────────────────────────────────────────────────────┘
 * 
 *  The read_qyeye is a staging buffer that allows packets to come in
 *  faster than the PDP-11 can process them. The RX worker thread
 *  dequeues packets from read_queue and DMA's them into the RX descriptor
 *  ring in PDP-11 memory.
 * 
 *  The TX worker thread processes the TX descriptor ring and sends
 *  packets out via pcap.
 * 
 */

#ifndef _DEQNA_HPP_
#define _DEQNA_HPP_

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>

#include "dec_ether_base.hpp"
#include "parameter.hpp"
#include "deqna_regs.h"

/*
 * Default DEQNA I/O page parameters
 * Base address 017774440 = IOPAGE + 014440 (octal)
 * Slot 18 is typical for network devices
 * Vector is software-programmable via VAR register (usually 0120 or similar)
 * Level 5 is standard for network devices (BR5)
 */
#define DEQNA_DEFAULT_ADDR 014440
#define DEQNA_DEFAULT_SLOT 18
#define DEQNA_DEFAULT_VECTOR 0  // Vector is software-programmable via VAR register
#define DEQNA_DEFAULT_LEVEL 5

/*
 * DEQNA Device Class
 * ==================
 * Inherits from qunibusdevice_c to participate in the QUniBone device framework.
 * Provides all register handling, DMA operations, and network bridging for
 * DEQNA Ethernet controller emulation.
 */
class deqna_c : public dec_ether_base_c {
public:
    deqna_c();
    ~deqna_c() override;

    /*
     * User-configurable parameters (set via menu system before install)
     * -----------------------------------------------------------------
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
    parameter_unsigned_c rx_start_delay_ms = parameter_unsigned_c(this, "rx_start_delay_ms", "rxd", false, "",
            "%d", "Receiver start delay in ms", 16, 10);
    parameter_unsigned_c intr_dma_holdoff_us = parameter_unsigned_c(this, "intr_dma_holdoff_us", "idh", false, "",
            "%d", "DMA holdoff after INTR assert in us (0 = disable)", 16, 10);
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
     * -----------------------------------
     * on_param_changed: Handle runtime parameter changes (MAC, promisc, etc.)
     * on_before_install: Open pcap interface, validate configuration
     * on_after_install: Reset controller to initial state
     * on_after_uninstall: Close pcap, release resources
     * on_power_changed: Handle DCLO (power fail) - reset on power restore
     * on_init_changed: Handle BINIT signal - reset controller
     * on_after_register_access: Process PDP-11 register writes
     * worker: Entry point for worker threads (instance 0=RX, 1=TX)
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
     * Device Registers (directly accessed by PDP-11 via DATO/DATI)
     * -------------------------------------------------------------
     * reg_sta_addr[0-5]: Station Address registers (SA0-SA5)
     *                    Read returns MAC address bytes (or checksum if EL set)
     *                    Write has no effect
     * reg_rcvlist_lo/hi: Receive descriptor list base address (22-bit)
     *                    Writing RCLH triggers RX ring processing
     * reg_xmtlist_lo/hi: Transmit descriptor list base address (22-bit)
     *                    Writing XMTH triggers TX ring processing
     * reg_vector:        Vector Address Register (VAR) - interrupt vector + mode
     * reg_csr:           Control/Status Register - main device control
     */
    qunibusdevice_register_t *reg_sta_addr[6] = {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
    qunibusdevice_register_t *reg_rcvlist_lo = nullptr;
    qunibusdevice_register_t *reg_rcvlist_hi = nullptr;
    qunibusdevice_register_t *reg_xmtlist_lo = nullptr;
    qunibusdevice_register_t *reg_xmtlist_hi = nullptr;
    qunibusdevice_register_t *reg_vector = nullptr;
    qunibusdevice_register_t *reg_csr = nullptr;

    /*
     * Thread synchronization
     * ----------------------
     * state_mutex: Protects device state (csr, rbdl_ba, ring state, setup, etc.)
     * dma_mutex: Serializes DMA operations (only one DMA at a time)
     * queue_mutex: Serializes queue access from PCAP callbacks
     * descriptor_process_mutex: Serializes process_rbdl() and process_xbdl() to
     *                           prevent concurrent DMA from RX and TX threads.
     *                           This ensures deferred interrupts only fire when
     *                           ALL descriptor processing is complete.
     */
    std::recursive_mutex state_mutex;
    std::mutex queue_mutex;  // Serialize queue access from PCAP callbacks
    std::mutex descriptor_process_mutex;  // Serialize ALL descriptor processing (RX + TX)
    std::atomic<bool> reset_in_progress{false};  // Flag to abort worker operations during reset

    /*
     * Pending register writes from PDP-11
     * -----------------------------------
     * Register writes are captured atomically by on_after_register_access()
     * and processed by worker threads. This avoids DMA deadlocks where the
     * PRU waits for bus grant while the CPU polls CSR waiting for completion.
     *
     * pending_reg_mask: Bitmask of registers with pending writes (bit N = reg N)
     * pending_reg_value[]: Written values for each register
     */
    std::atomic<uint16_t> pending_reg_mask{0};
    std::atomic<uint16_t> pending_reg_value[8];

    /*
     * Setup packet state (from last processed setup frame)
     * -----------------------------------------------------
     * The setup packet configures the device's receive filter. It's sent
     * as a transmit with the S (setup) bit set in the descriptor. Contains:
     *   - Up to 14 multicast/unicast MAC addresses to accept
     *   - Promiscuous mode flag
     *   - Multicast all flag
     *   - Sanity timer configuration
     *   - LED control bits (l1/l2/l3)
     */
    struct setup_state {
        bool valid = false;         // true after first setup packet processed
        bool promiscuous = false;   // accept all packets
        bool multicast = false;     // accept all multicast
        bool l1 = true;             // LED 1 state (active low in hardware)
        bool l2 = true;             // LED 2 state
        bool l3 = true;             // LED 3 state
        int sanity_timer = 0;       // unused legacy field
        uint8_t macs[QNA_FILTER_MAX][6] = {{0}};  // up to 14 filter MACs
    } setup;

    /*
     * Sanity timer state (watchdog timer)
     * ------------------------------------
     * If enabled, the sanity timer resets the controller if no TX completes
     * within the configured timeout. This prevents hung driver situations.
     * The timer is reset on each successful transmit.
     *
     * enabled: 0=off, 1=software sanity (from setup), 2=hardware sanity
     * quarter_secs: timeout in 0.25-second units (from setup packet)
     * max: timeout in service_timers() call units
     * timer: countdown, reset on TX completion
     */
    struct sanity_state {
        int enabled = 0; // 2=HW, 1=SW, 0=off
        int quarter_secs = 0;
        int max = 0;
        int timer = 0;
    } sanity;

    /*
     * Packet statistics
     */
    struct stats_state {
        uint64_t recv = 0;    // packets received from network
        uint64_t filter = 0;  // packets filtered out (unused currently)
        uint64_t xmit = 0;    // packets transmitted
        uint64_t fail = 0;    // transmit failures (NXM, etc.)
        uint64_t runt = 0;    // received packets < 64 bytes (padded)
        uint64_t giant = 0;   // received packets > 1518 bytes (truncated)
        uint64_t setup = 0;   // setup packets processed
        uint64_t loop = 0;    // loopback packets processed
    } stats;

    /*
     * Packet buffer for RX/TX operations
     * -----------------------------------
     * msg: Packet data (up to ETH_FRAME_SIZE bytes)
     * len: Total packet length
     * used: Bytes already transferred (for multi-segment packets)
     * status: Status code for completed packet
     */
    struct packet_buffer {
        std::vector<uint8_t> msg;
        size_t len = 0;
        size_t used = 0;
        int status = 0;
    } read_buffer, write_buffer;

    /*
     * Queue item for received packets waiting to be delivered
     * --------------------------------------------------------
     * type: Packet type for status word generation
     *       0 = setup (ESETUP + length)
     *       1 = loopback (status 0x2000 + length)
     *       2 = normal receive (length only in status)
     * enqueue_time: Timestamp when packet was enqueued (for loopback delay)
     */
    struct queue_item {
        int type = 0; // 0=setup, 1=loopback, 2=normal
        packet_buffer packet;
        std::chrono::steady_clock::time_point enqueue_time;
    };

    /*
     * Receive queue: packets waiting for RX descriptors
     * --------------------------------------------------
     * Packets are queued when received from pcap or loopback, then
     * delivered to host memory when RX descriptors are available.
     * If queue is full, oldest packets are dropped (read_queue_loss counts).
     */
    std::deque<queue_item> read_queue;
    unsigned read_queue_loss = 0;

    /*
     * Descriptor ring state
     * ----------------------
     * rbdl[0]/rbdl[1]: Last written values to RCLL/RCLH registers
     * xbdl[0]/xbdl[1]: Last written values to XMTL/XMTH registers
     * var: Vector Address Register value (vector + mode bits)
     * csr: Control/Status Register value
     * irq: Current interrupt request state (true = asserting)
     *
     * rbdl_ba/xbdl_ba: Calculated 22-bit base addresses for current
     *                  descriptor being processed. Recalculated from
     *                  rbdl[]/xbdl[] on each dispatch.
     */
    uint16_t rbdl[2] = {0, 0};
    uint16_t xbdl[2] = {0, 0};
    uint16_t var = 0;
    uint16_t csr = 0;
    bool irq = false;

    uint32_t rbdl_ba = 0;
    uint32_t xbdl_ba = 0;
    // Remember the last RX ring start we saw when packets remained queued.
    // Used to avoid lapping a circular ring across process_rbdl() calls.
    uint32_t last_rbdl_start = 0;
    bool rbdl_wrap_guard = false;

    /*
     * MAC address state
     * ------------------
     * mac_override: true if user specified custom MAC via parameter
     * mac_addr[6]: Current MAC address (device default or user-specified)
     * mac_checksum[2]: Checksum of MAC for EL mode station register reads
     */
    bool mac_override = false;
    uint8_t mac_addr[6] = {0};
    uint8_t mac_checksum[2] = {0};

    /*
     * Device operational flags
     * -------------------------
     * deqna_lock: DEQNA compatibility mode locked (MS bit cleared)
     * rx_delay_active: Artificial RX delay in effect (for timing compat)
     * rx_enable_deadline_ns: Absolute time when RX delay expires
     * rbdl_pending: RX list needs dispatching (RCLH written)
     * xbdl_pending: TX list needs dispatching (XMTH written)
     * xbdl_active: TX ring is active; keep scanning even without XMTH writes
     * idtmr: System ID timer countdown (sends MOP system ID periodically)
     */
    bool deqna_lock = false;
    bool rx_delay_active = false;
    uint64_t rx_enable_deadline_ns = 0;
    bool rbdl_pending = false;
    bool xbdl_pending = false;
    bool xbdl_active = false;
    uint64_t timers_last_service_ns = 0; // service_timers() tick baseline

    /*
     * Deferred interrupt signaling
     * -----------------------------
     * QuNiBone's PRU can deadlock if we assert a bus interrupt while DMA is
     * underway. csr_set_clr() therefore sets deferred flags instead of
     * calling set_int/clr_int directly; process_deferred_interrupts() is
     * called after DMA-heavy operations complete.
     */
    std::atomic<bool> deferred_set_int{false};
    std::atomic<bool> deferred_clr_int{false};

    int idtmr = 0;

    /*
     * Controller reset/initialization
     * --------------------------------
     * reset_controller: Full hardware reset (power-on, BINIT, sanity timeout)
     * sw_reset: Software reset via SR bit in CSR (preserves some state)
     */
    void reset_controller(void);
    void sw_reset(void);

    /*
     * Register value update functions
     * ---------------------------------
     * These update the DATI (read) values of device registers to reflect
     * current internal state. Called after state changes.
     *
     * update_mac_checksum: Recompute MAC checksum for EL mode reads
     * update_station_regs: Update SA0-SA5 with MAC or checksum values
     * update_vector_reg: Update VAR register read value
     * update_csr_reg: Update CSR register read value
     * update_transceiver_bits: Update OK/CA bits based on pcap state
     * update_intr: Update interrupt signal based on IE and pending conditions
     */
    void update_mac_checksum(void);
    void update_station_regs(void);
    void update_vector_reg(void);
    void update_csr_reg(void);
    void update_transceiver_bits(void);
    void update_intr(void) override;
    void service_intr_complete(void);
    uint64_t intr_dma_holdoff_us_value(void) const override
    {
        return static_cast<uint64_t>(intr_dma_holdoff_us.value);
    }
    void service_intr_complete_for_dma_holdoff(void) override
    {
        service_intr_complete();
    }

    /*
     * Interrupt control
     * ------------------
     * set_int: Assert interrupt request (sets RI or XI in CSR)
     * clr_int: Deassert interrupt request
     * csr_set_clr: Atomic set/clear of CSR bits with interrupt side effects
     * nxm_error: Handle NXM (non-existent memory) DMA error
     */
    void set_int(void);
    void clr_int(void);
    void process_deferred_interrupts(void);
    void csr_set_clr(uint16_t set_bits, uint16_t clear_bits);
    void nxm_error(void);

    /*
     * Receiver startup delay (for OS compatibility)
     */
    void start_rx_delay(void);
    bool rx_ready(void);

    /*
     * Update libpcap BPF filter based on current setup/promisc state
     */
    void update_pcap_filter(void);

    /*
     * Worker thread entry points
     * ---------------------------
     * worker_rx: Instance 0 - polls pcap, processes RX ring
     * worker_tx: Instance 1 - processes TX ring
     */
    void worker_rx(void);
    void worker_tx(void);

    /*
     * Register write handling
     * ------------------------
     * handle_register_write: Process a single register write
     * apply_pending_reg_writes: Process all pending writes from atomic queue
     */
    void handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access);
    void apply_pending_reg_writes(void);

    // DMA operations are inherited from dec_ether_base_c.

    /*
     * Address calculation
     * --------------------
     * Constructs 22-bit physical address from high/low register values,
     * masking based on current bus address width (16/18/22 bit).
     */
    uint32_t make_addr(uint16_t hi, uint16_t lo) const;

    /*
     * Receive queue management
     * -------------------------
     * enqueue_readq: Add a received packet to the queue
     * process_rbdl: Process RX descriptors, deliver queued packets to host
     * dispatch_rbdl: Entry point for RX ring processing (clears RL, recalc base)
     */
    void enqueue_readq(int type, const uint8_t *data, size_t len, int status);
    bool process_rbdl(void);
    bool dispatch_rbdl(void);

    /*
     * Transmit ring processing
     * -------------------------
     * process_xbdl: Process TX descriptors, send packets via pcap or loopback
     * dispatch_xbdl: Entry point for TX ring processing (clears XL, recalc base)
     * write_callback: Called after pcap send completes, updates descriptor status
     */
    bool process_xbdl(void);
    bool dispatch_xbdl(void);
    void write_callback(int status);

    /*
     * Packet filtering
     * -----------------
     * accept_packet: Determine if packet should be delivered to emulated NIC
     */
    bool accept_packet(const uint8_t *data, size_t len) const;

    /*
     * Setup packet processing
     * ------------------------
     * Parses the 128-byte setup frame to configure receive filters,
     * promiscuous mode, sanity timer, etc.
     */
    void process_setup(void);

    /* Debug helper: Dump RX/TX descriptor rings and CSR for diagnosis */
    void dump_descriptor_rings(const char *reason);

    /*
     * Idle RX ring touch (debugging only, no DMA)
     */
    void touch_rbdl_if_idle(void);

    /*
     * Local packet processing (MOP protocols)
     * ----------------------------------------
     * process_local: Dispatch received MOP protocol packets
     * process_loopback: Handle MOP loopback assistant protocol (90-00)
     * process_remote_console: Handle MOP remote console protocol (02-60)
     * send_system_id: Transmit MOP system ID message
     */
    bool process_local(const uint8_t *data, size_t len);
    bool process_loopback(const uint8_t *data, size_t len);
    bool process_remote_console(const uint8_t *data, size_t len);
    bool send_system_id(const uint8_t *dest, uint16_t receipt_id);

    /*
     * Timer services
     * ---------------
     * reset_sanity_timer: Reset watchdog after successful TX
     * service_timers: Called periodically to check sanity/ID timers
     */
    void reset_sanity_timer(void);
    void service_timers(void);

    /*
     * Utility
     */
    static bool parse_mac(const std::string &text, uint8_t out[6]);
};

#endif
