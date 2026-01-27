// Author: Dave Plummer (davepl@davepl.com)
// (c) 2026 Plummer's Software LLC
// Contributed under the BSD License
//
// DEUNA Ethernet Controller Emulation for QUniBone
// ================================================
//
// This module emulates the DEC DEUNA (UNIBUS Ethernet controller).
// It provides a port-command interface (PCSR0-3) with descriptor
// rings in host memory, and bridges Ethernet frames to a host
// interface using libpcap.
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
#include <cstring>

#include "qunibusdevice.hpp"
#include "priorityrequest.hpp"
#include "pcap_bridge.hpp"
#include "parameter.hpp"

// Safe string copy with guaranteed NUL termination for static arrays.
// Array size is automatically deduced at compile time.
// Returns length of src (like strlcpy).
template <size_t N>
static inline size_t static_strcpy(char (&dst)[N], const char *src)
{
    size_t len = std::strlen(src);
    if (N > 0) {
        size_t copy_len = (len < N - 1) ? len : N - 1;
        std::memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }
    return len;
}

// Array size helper - deduces static array length at compile time.
template <typename T, size_t N>
static constexpr size_t arraysize(const T (&)[N]) noexcept
{
    return N;
}

// Default DEUNA I/O page parameters
// Base address is a typical DEUNA CSR location (octal)
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

// Ethernet frame size constants
static constexpr size_t ETH_MIN_PACKET      = 60;       // Minimum Ethernet frame (no CRC)
static constexpr size_t ETH_MAX_PACKET      = 1514;     // Maximum Ethernet frame (no CRC)
static constexpr size_t ETH_FRAME_SIZE      = 1518;     // Frame + CRC space
static constexpr size_t UNA_MAX_RCV_PACKET  = 1600;     // Maximum receive packet size

// Queue and timer constants
static constexpr unsigned UNA_QUE_MAX       = 500;      // Maximum packet queue depth

// Internal memory sizes (word counts)
static constexpr size_t DEUNA_WCS_WORDS     = 8192;     // Writable control store words
static constexpr size_t DEUNA_LINK_WORDS    = 1024;     // Link memory words

// Default DEUNA hardware address (DEC OUI)
static constexpr uint8_t DEUNA_DEFAULT_MAC[6] = {0x08, 0x00, 0x2b, 0xcc, 0xdd, 0xee};

// PCSR0 register definitions (Status/Control Register)
static constexpr uint16_t PCSR0_SERI       = 0100000;   // Status Error Interrupt (error occurred)
static constexpr uint16_t PCSR0_PCEI       = 0040000;   // Port Command Error Interrupt (invalid command)
static constexpr uint16_t PCSR0_RXI        = 0020000;   // Receive Interrupt (packet available)
static constexpr uint16_t PCSR0_TXI        = 0010000;   // Transmit Interrupt (transmission complete)
static constexpr uint16_t PCSR0_DNI        = 0004000;   // Done Interrupt (port command done)
static constexpr uint16_t PCSR0_RCBI       = 0002000;   // Receive Buffer Unavailable (out of buffers)
static constexpr uint16_t PCSR0_FATL       = 0001000;   // Fatal Internal Error (self-test failure)
static constexpr uint16_t PCSR0_USCI       = 0000400;   // Unsolicited State Change Interrupt
static constexpr uint16_t PCSR0_INTR       = 0000200;   // Interrupt Summary (any interrupt active)
static constexpr uint16_t PCSR0_INTE       = 0000100;   // Interrupt Enable (allow interrupts)
static constexpr uint16_t PCSR0_RSET       = 0000040;   // Reset (perform soft reset)
static constexpr uint16_t PCSR0_PCMD       = 0000017;   // Port Command field (command opcode)
static constexpr uint16_t PCSR0_W1C_MASK   = 0177400;   // Write-1-to-clear bits (interrupt flags)

// PCSR0 Port Commands
static constexpr uint16_t CMD_NOOP         = 000;       // No operation
static constexpr uint16_t CMD_GETPCBB      = 001;       // Fetch PCB from memory
static constexpr uint16_t CMD_GETCMD       = 002;       // Get port command from PCB
static constexpr uint16_t CMD_SELFTEST     = 003;       // Execute self-test
static constexpr uint16_t CMD_START        = 004;       // Start device operation
static constexpr uint16_t CMD_BOOT         = 005;       // Bootstrap load (firmware)
static constexpr uint16_t CMD_PDMD         = 010;       // Pseudoduplicate mode
static constexpr uint16_t CMD_HALT         = 016;       // Halt current operation
static constexpr uint16_t CMD_STOP         = 017;       // Stop device immediately

// PCSR1 register definitions (Status Register 1)
static constexpr uint16_t PCSR1_XPWR       = 0100000;   // Transceiver power failure status
static constexpr uint16_t PCSR1_ICAB       = 0040000;   // Interface/cable fault indicator
static constexpr uint16_t PCSR1_ECOD       = 0037400;   // Self-test error code (diagnostic)
static constexpr uint16_t PCSR1_PCTO       = 0000200;   // Port Command Timeout error
static constexpr uint16_t PCSR1_TYPE       = 0000160;   // Controller type (DEUNA vs DELUA)
static constexpr uint16_t PCSR1_STATE      = 0000017;   // Current controller state

static constexpr uint16_t TYPE_DEUNA       = (0 << 4);  // DEUNA controller type
static constexpr uint16_t TYPE_DELUA       = (1 << 4);  // DELUA controller type (newer)

static constexpr uint16_t STATE_RESET      = 000;       // Reset/uninitialized
static constexpr uint16_t STATE_PLOAD      = 001;       // Program load (loading firmware)
static constexpr uint16_t STATE_READY      = 002;       // Ready for operation
static constexpr uint16_t STATE_RUNNING    = 003;       // Currently operating
static constexpr uint16_t STATE_UHALT      = 005;       // Unrecovered halt
static constexpr uint16_t STATE_NHALT      = 006;       // Normal halt
static constexpr uint16_t STATE_NUHALT     = 007;       // Nonrecovered unrecovered halt
static constexpr uint16_t STATE_HALT       = 010;       // General halt state
static constexpr uint16_t STATE_SLOAD      = 017;       // System load microcode

// Status register definitions (receive/transmit diagnostics)
static constexpr uint16_t STAT_ERRS        = 0100000;   // Error bits summary
static constexpr uint16_t STAT_MERR        = 0040000;   // Memory error
static constexpr uint16_t STAT_BABL        = 0020000;   // Babble (frame too long)
static constexpr uint16_t STAT_CERR        = 0010000;   // Collision error
static constexpr uint16_t STAT_TMOT        = 0004000;   // Timeout
static constexpr uint16_t STAT_RRNG        = 0001000;   // Receive ring counter
static constexpr uint16_t STAT_TRNG        = 0000400;   // Transmit ring counter
static constexpr uint16_t STAT_PTCH        = 0000200;   // Patch/revision indicator
static constexpr uint16_t STAT_RRAM        = 0000100;   // RAM failure
static constexpr uint16_t STAT_RREV        = 0000077;   // ROM revision field

// Mode register definitions
static constexpr uint16_t MODE_PROM        = 0100000;   // Promiscuous mode
static constexpr uint16_t MODE_ENAL        = 0040000;   // Enable all multicast
static constexpr uint16_t MODE_DRDC        = 0020000;   // Disable data chaining
static constexpr uint16_t MODE_TPAD        = 0010000;   // Transmit pad enable
static constexpr uint16_t MODE_ECT         = 0004000;   // Enable collision test
static constexpr uint16_t MODE_DMNT        = 0001000;   // Disable maintenance message
static constexpr uint16_t MODE_INTL        = 0000200;   // Internal loopback enable
static constexpr uint16_t MODE_DTCR        = 0000010;   // Disable transmit CRC
static constexpr uint16_t MODE_LOOP        = 0000004;   // Internal loopback mode
static constexpr uint16_t MODE_HDPX        = 0000001;   // Half duplex

// Function Code definitions (port command operations)
static constexpr uint16_t FC_NOOP          = 0000000;   // No operation
static constexpr uint16_t FC_LSM           = 0000001;   // Load station microcode
static constexpr uint16_t FC_RDPA          = 0000002;   // Read physical address (MAC)
static constexpr uint16_t FC_RPA           = 0000004;   // Read protocol address
static constexpr uint16_t FC_WPA           = 0000005;   // Write protocol address
static constexpr uint16_t FC_RMAL          = 0000006;   // Read multicast address list
static constexpr uint16_t FC_WMAL          = 0000007;   // Write multicast address list
static constexpr uint16_t FC_RRF           = 0000010;   // Read ring filters
static constexpr uint16_t FC_WRF           = 0000011;   // Write ring filters
static constexpr uint16_t FC_RDCTR         = 0000012;   // Read counters
static constexpr uint16_t FC_RDCLCTR       = 0000013;   // Read and clear counters
static constexpr uint16_t FC_RMODE         = 0000014;   // Read mode register
static constexpr uint16_t FC_WMODE         = 0000015;   // Write mode register
static constexpr uint16_t FC_RSTAT         = 0000016;   // Read status register
static constexpr uint16_t FC_RCSTAT        = 0000017;   // Read and clear status
static constexpr uint16_t FC_DIM           = 0000020;   // Disable internal maintenance
static constexpr uint16_t FC_LIM           = 0000021;   // Load internal memory
static constexpr uint16_t FC_RSID          = 0000022;   // Read subsystem ID
static constexpr uint16_t FC_WSID          = 0000023;   // Write subsystem ID
static constexpr uint16_t FC_RLSA          = 0000024;   // Read load server address
static constexpr uint16_t FC_WLSA          = 0000025;   // Write load server address

// Transmitter Ring definitions (descriptor ownership and status)
static constexpr uint16_t TXR_OWN          = 0100000;   // Ownership bit (1=controller, 0=host)
static constexpr uint16_t TXR_ERRS         = 0040000;   // Error occurred on transmission
static constexpr uint16_t TXR_MTCH         = 0020000;   // More than one transmission attempt
static constexpr uint16_t TXR_MORE         = 0010000;   // More data segments in chain
static constexpr uint16_t TXR_ONE          = 0004000;   // One collision during transmission
static constexpr uint16_t TXR_DEF          = 0002000;   // Transmission deferred
static constexpr uint16_t TXR_STF          = 0001000;   // Start of frame indicator
static constexpr uint16_t TXR_ENF          = 0000400;   // End of frame indicator

static constexpr uint16_t TXR_BUFL         = 0100000;   // Buffer loss error
static constexpr uint16_t TXR_UBTO         = 0040000;   // UNIBUS timeout
static constexpr uint16_t TXR_UFLO         = 0020000;   // UNIBUS underflow error
static constexpr uint16_t TXR_LCOL         = 0010000;   // Late collision
static constexpr uint16_t TXR_LCAR         = 0004000;   // Loss of carrier
static constexpr uint16_t TXR_RTRY         = 0002000;   // Excessive retries
static constexpr uint16_t TXR_TDR          = 0001777;   // Time domain reflectometry (cable length)

// Receiver Ring definitions (descriptor ownership and status)
static constexpr uint16_t RXR_OWN          = 0100000;   // Ownership bit (1=controller, 0=host)
static constexpr uint16_t RXR_ERRS         = 0040000;   // Error occurred during reception
static constexpr uint16_t RXR_FRAM         = 0020000;   // Frame alignment error
static constexpr uint16_t RXR_OFLO         = 0010000;   // Overflow (frame too long)
static constexpr uint16_t RXR_CRC          = 0004000;   // CRC error detected
static constexpr uint16_t RXR_STF          = 0001000;   // Start of frame indicator
static constexpr uint16_t RXR_ENF          = 0000400;   // End of frame indicator

static constexpr uint16_t RXR_BUFL         = 0100000;   // Buffer loss error
static constexpr uint16_t RXR_UBTO         = 0040000;   // UNIBUS timeout

class deuna_c : public qunibusdevice_c {
public:
    deuna_c();
    ~deuna_c() override;

    // User-configurable parameters (set via menu system before install)
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
    parameter_unsigned_c intr_dma_holdoff_us = parameter_unsigned_c(this, "intr_dma_holdoff_us", "idh", false, "",
            "%d", "DMA holdoff after INTR assert in us (0 = disable)", 16, 10);
    parameter_bool_c trace = parameter_bool_c(this, "trace", "tr", false,
            "Trace CSR/ring events to log");

    // Read-only statistics (updated during operation, visible in menu)
    parameter_unsigned64_c stat_rx_frames = parameter_unsigned64_c(this, "rx_frames", "rxf", true, "",
            "%llu", "Received frames count", 64, 10);
    parameter_unsigned64_c stat_tx_frames = parameter_unsigned64_c(this, "tx_frames", "txf", true, "",
            "%llu", "Transmitted frames count", 64, 10);
    parameter_unsigned64_c stat_rx_errors = parameter_unsigned64_c(this, "rx_errors", "rxe", true, "",
            "%llu", "Receive error count", 64, 10);
    parameter_unsigned64_c stat_tx_errors = parameter_unsigned64_c(this, "tx_errors", "txe", true, "",
            "%llu", "Transmit error count", 64, 10);

    // QUniBone device framework callbacks
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
    // Bus requests for interrupts and DMA
    intr_request_c intr_request{this};
    dma_request_c dma_request{this};
    dma_request_c dma_desc_request{this};

    // Network bridge
    PcapBridge pcap;

    // DMA synchronization
    std::recursive_mutex dma_mutex;

    // Device Registers
    qunibusdevice_register_t *reg_pcsr0 = nullptr;
    qunibusdevice_register_t *reg_pcsr1 = nullptr;
    qunibusdevice_register_t *reg_pcsr2 = nullptr;
    qunibusdevice_register_t *reg_pcsr3 = nullptr;

    // Thread synchronization
    std::recursive_mutex state_mutex;
    std::mutex queue_mutex;  // New: Serialize queue access from PCAP callbacks
    std::atomic<bool> reset_in_progress{false};  // New: Flag to abort worker operations during reset

    // Pending register writes from PDP-11 (preserve write order)
    struct pending_reg_write {
        uint8_t reg_index = 0;
        uint16_t value = 0;
        uint8_t access = 0;
        uint16_t w1c_snapshot = 0;
    };
    std::mutex pending_reg_mutex;
    std::deque<pending_reg_write> pending_reg_queue;

    // Pending port command for worker thread (DMA required)
    std::mutex pending_cmd_mutex;
    std::condition_variable pending_cmd_cv;
    uint16_t pending_cmd = 0;  // 0 = no command pending

    // Setup packet state (MAC filtering)
    struct setup_state {
        bool valid = false;
        bool promiscuous = false;
        bool multicast = false;
        int mac_count = 0;
        uint8_t macs[DEUNA_FILTER_MAX][6] = {{0}};
    } setup;

    // Network statistics
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

    // Packet buffer for RX/TX operations
    struct packet_buffer {
        std::vector<uint8_t> msg;
        size_t len = 0;
        size_t used = 0;
        size_t crc_len = 0;
        int status = 0;
    } read_buffer, write_buffer;

    // Queue item for received packets waiting to be delivered
    struct queue_item {
        bool loopback = false;
        packet_buffer packet;
    };

    std::deque<queue_item> read_queue;
    unsigned read_queue_loss = 0;

    // Port command and ring state
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

    std::vector<uint16_t> wcs_mem;
    std::vector<uint16_t> link_mem;

    uint16_t pcb[4] = {0};
    uint16_t udb[DEUNA_UDB_WORDS] = {0};
    uint16_t rxhdr[4] = {0};
    uint16_t txhdr[4] = {0};

    uint8_t load_server[6] = {0};

    // MAC address state
    bool mac_override = false;
    uint8_t mac_addr[6] = {0};

    // Controller reset/initialization
    void reset_controller(void);
    void init_internal_memory(void);

    // Register value update functions
    void update_pcsr_regs(void);
    void update_transceiver_bits(void);
    void update_intr(void);

    // Register write handling
    void handle_register_write(uint8_t reg_index, uint16_t val, DATO_ACCESS access,
            uint16_t w1c_snapshot);
    void apply_pending_reg_writes(void);
    void process_pending_command(void);

    // DMA operations
    bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool desc_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool desc_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount);
    bool dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    bool dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len);
    bool cpu_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount);
    bool cpu_read_bytes(uint32_t addr, uint8_t *buffer, size_t len);
    bool process_bootrom(uint32_t dst_addr);
    bool load_system_microcode(uint32_t udbb);
    bool transfer_internal_memory(uint32_t udbb, bool to_internal);
    void log_pcbb_snapshot(const char *tag, uint32_t addr);

    uint32_t make_addr(uint16_t hi, uint16_t lo) const;

    // Port command processing
    void port_command(uint16_t cmd); 
    bool execute_command(void); 

    // Receive/transmit ring processing
    void enqueue_readq(const uint8_t *data, size_t len, bool loopback);
    bool process_receive(void); 
    bool process_transmit(unsigned max_descriptors = 0); 
    void dump_tx_ring(unsigned max_entries);

    // Packet filtering
    bool accept_packet(const uint8_t *data, size_t len) const;
    void update_pcap_filter(void);

    // Timer services
    void service_timers(void);

    // Worker thread entry points
    void worker_rx(void);
    void worker_tx(void);

    // Utility
    static bool parse_mac(const std::string &text, uint8_t out[6]);
};

#endif
