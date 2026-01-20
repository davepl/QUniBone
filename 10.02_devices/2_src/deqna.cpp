/* deqna.cpp - Simplified DEQNA Ethernet Controller Emulation
 *
 * Minimal DEQNA (M7504) implementation for QUniBone:
 * - TX/RX via pcap
 * - Internal/external loopback
 * - Setup packets
 * - STA ON deferred interrupt (400µs delay after SR clear)
 *
 * Copyright (c) 2024-2026 QUniBone project
 */

#include "deqna.hpp"
#include "timeout.hpp"
#include "utils.hpp"
#include <cstring>

// Alias the QE_* names from deqna_regs.h to QNA_* for readability
static const uint16_t QNA_DSC_V = QE_RING_VALID;     // Descriptor is valid
static const uint16_t QNA_DSC_C = QE_RING_CHAIN;     // Chain to address in words 1,2
static const uint16_t QNA_DSC_E = QE_RING_EOMSG;     // End of message (last segment)
static const uint16_t QNA_DSC_S = QE_RING_SETUP;     // Setup packet (TX only)
static const uint16_t QNA_DSC_L = QE_RING_ODD_END;   // Odd byte at end
static const uint16_t QNA_DSC_H = QE_RING_ODD_BEGIN; // Odd byte at start

static const uint16_t QNA_CSR_RI = QE_RCV_INT;       // Receive interrupt pending
static const uint16_t QNA_CSR_OK = QE_OK;            // Transceiver OK
static const uint16_t QNA_CSR_SE = QE_STIM_ENABLE;   // Sanity timer enable
static const uint16_t QNA_CSR_EL = QE_ELOOP;         // External loopback
static const uint16_t QNA_CSR_IL = QE_ILOOP;         // Internal loopback
static const uint16_t QNA_CSR_XI = QE_XMIT_INT;      // Transmit interrupt pending
static const uint16_t QNA_CSR_IE = QE_INT_ENABLE;    // Interrupt enable
static const uint16_t QNA_CSR_RL = QE_RL_INVALID;    // Receive list invalid
static const uint16_t QNA_CSR_XL = QE_XL_INVALID;    // Transmit list invalid
static const uint16_t QNA_CSR_BD = QE_LOAD_ROM;      // Boot/diagnostic ROM
static const uint16_t QNA_CSR_NI = QE_NEX_MEM_INT;   // Non-existent memory interrupt
static const uint16_t QNA_CSR_SR = QE_RESET;         // Software reset
static const uint16_t QNA_CSR_RE = QE_RCV_ENABLE;    // Receive enable
static const uint16_t QNA_VEC_IV = QE_VEC_IV;        // Interrupt vector bits
static const uint16_t QNA_VEC_MS = QE_VEC_MS;        // Mode select (forced 0)
static const uint16_t QNA_VEC_OS = QE_VEC_OS;        // Option status (forced 0)
static const uint16_t QNA_VEC_RS = QE_VEC_RS;        // ROM status (forced 0)
static const uint16_t QNA_VEC_ST = QE_VEC_ST;        // Self-test status (forced 0)
static const uint16_t QNA_VEC_ID = QE_VEC_ID;        // ID (forced 0)

//------------------------------------------------------------------------------
// Construction / Destruction
//------------------------------------------------------------------------------

deqna_c::deqna_c() :
    qunibusdevice_c(),
    intr_request(this),
    dma_request(this)
{
    name.value = "deqna";
    type_name.value = "DEQNA";
    log_label = "DEQNA";
    
    // Version string for identification
    version.value = "1.0.26-20260119-nocooldown";
    
    // Set default bus parameters: base_addr, priority_slot, vector, level
    // DEQNA typically uses slot 18, vector 0120, level 4
    set_default_bus_params(0774440, 18, 0120, 4);
    
    // Single worker thread for RX/TX processing
    set_workers_count(1);
    
    // Set default values for parameters
    ifname.value = "eth0";
    mac.value = "08:00:2b:00:00:01";

    // Create 8 device registers (16 bytes I/O space)
    register_count = 8;
    
    // Configure each register
    // Note: active_on_dati=false means PRU serves reads directly from shared memory
    //       active_on_dato=true means we get callback on writes to process them
    //
    // DEQNA register layout:
    //   Reg 0-5: Read returns MAC address bytes (0xFF in high byte, MAC byte in low)
    //            Write to reg 2-5 sets RCVLIST/XMTLIST addresses
    //   Reg 6: VAR (Vector Address Register)
    //   Reg 7: CSR (Control/Status Register)
    
    // STA0 - Station Address byte 0 (read-only)
    strcpy(registers[0].name, "STA0");
    registers[0].active_on_dati = false;  // PRU serves reads directly
    registers[0].active_on_dato = false;  // Writes ignored (read-only)
    registers[0].writable_bits = 0x0000;  // Read-only
    registers[0].reset_value = 0;
    
    // STA1 - Station Address byte 1 (read-only)
    strcpy(registers[1].name, "STA1");
    registers[1].active_on_dati = false;
    registers[1].active_on_dato = false;
    registers[1].writable_bits = 0x0000;
    registers[1].reset_value = 0;
    
    // STA2/RCLL - Read returns MAC[2], Write sets RCVLIST low
    strcpy(registers[2].name, "STA2/RCLL");
    registers[2].active_on_dati = false;
    registers[2].active_on_dato = true;
    registers[2].writable_bits = 0xFFFF;
    registers[2].reset_value = 0;
    
    // STA3/RCLH - Read returns MAC[3], Write sets RCVLIST high (triggers RX dispatch)
    strcpy(registers[3].name, "STA3/RCLH");
    registers[3].active_on_dati = false;
    registers[3].active_on_dato = true;
    registers[3].writable_bits = 0xFFFF;
    registers[3].reset_value = 0;
    
    // STA4/XMTL - Read returns MAC[4], Write sets XMTLIST low
    strcpy(registers[4].name, "STA4/XMTL");
    registers[4].active_on_dati = false;
    registers[4].active_on_dato = true;
    registers[4].writable_bits = 0xFFFF;
    registers[4].reset_value = 0;
    
    // STA5/XMTH - Read returns MAC[5], Write sets XMTLIST high (triggers TX dispatch)
    strcpy(registers[5].name, "STA5/XMTH");
    registers[5].active_on_dati = false;
    registers[5].active_on_dato = true;
    registers[5].writable_bits = 0xFFFF;
    registers[5].reset_value = 0;
    
    // VAR - Vector Address Register
    strcpy(registers[6].name, "VAR");
    registers[6].active_on_dati = false;  // PRU serves reads directly
    registers[6].active_on_dato = true;   // Callback on writes
    registers[6].writable_bits = 0xFFFF;
    registers[6].reset_value = 0;
    
    // CSR - Control/Status Register
    strcpy(registers[7].name, "CSR");
    registers[7].active_on_dati = false;  // PRU serves reads directly
    registers[7].active_on_dato = true;   // Callback on writes
    registers[7].writable_bits = 0xFFFF;
    registers[7].reset_value = 0;
    
    // Set up interrupt/DMA priorities using the values set by set_default_bus_params
    intr_request.set_priority_slot(priority_slot.value);
    intr_request.set_level(intr_level.value);
    intr_request.set_vector(intr_vector.value);
    dma_request.set_priority_slot(priority_slot.value);
    
    // Parse MAC address
    unsigned m[6];
    if (sscanf(mac.value.c_str(), "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i = 0; i < 6; i++)
            mac_addr[i] = static_cast<uint8_t>(m[i]);
    }
}

deqna_c::~deqna_c()
{
    workers_terminate = true;
    pcap.close();
}

//------------------------------------------------------------------------------
// Parameter and install handling
//------------------------------------------------------------------------------

bool deqna_c::on_param_changed(parameter_c *param)
{
    if (param == &priority_slot) {
        dma_request.set_priority_slot(priority_slot.new_value);
        intr_request.set_priority_slot(priority_slot.new_value);
    } else if (param == &intr_level) {
        intr_request.set_level(intr_level.new_value);
    } else if (param == &intr_vector) {
        intr_request.set_vector(intr_vector.new_value);
    } else if (param == &mac) {
        unsigned m[6];
        if (sscanf(mac.new_value.c_str(), "%x:%x:%x:%x:%x:%x",
                   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
            for (int i = 0; i < 6; i++)
                mac_addr[i] = static_cast<uint8_t>(m[i]);
        }
    }
    return qunibusdevice_c::on_param_changed(param);
}

bool deqna_c::on_before_install(void)
{
    if (ifname.value.empty()) {
        ERROR("DEQNA: ifname must be set");
        return false;
    }

    if (!pcap.open(ifname.value, true)) {  // promisc=true
        ERROR("DEQNA: Failed to open %s: %s", ifname.value.c_str(), pcap.last_error().c_str());
        return false;
    }

    return qunibusdevice_c::on_before_install();
}

void deqna_c::on_after_install(void)
{
    WARNING("DEQNA: on_after_install called");
    reset_controller();
    
    // Don't set OK here - it will be set via STA ON mechanism after software reset
    // The driver must do a software reset (SR 1->0) to get OK set after 400µs delay
    
    qunibusdevice_c::on_after_install();
}

void deqna_c::on_after_uninstall(void)
{
    pcap.close();
    qunibusdevice_c::on_after_uninstall();
}

void deqna_c::on_power_changed(signal_edge_enum aclo_edge, signal_edge_enum dclo_edge)
{
    UNUSED(aclo_edge);
    if (dclo_edge == SIGNAL_EDGE_RAISING) {
        reset_controller();
    }
}

void deqna_c::on_init_changed(void)
{
    if (init_asserted)
        reset_controller();
}

//------------------------------------------------------------------------------
// DMA helpers
//------------------------------------------------------------------------------

bool deqna_c::dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    DEBUG("DEQNA: DMA read addr=%06o words=%zu", addr, wordcount);

    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;

    // Try DDR memory first if available
    if (ddrmem && ddrmem->enabled &&
        addr64 >= ddrmem->qunibus_startaddr &&
        (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->exam(addr + static_cast<uint32_t>(i * 2), &buffer[i]))
                return false;
        }
        return true;
    }

    // Fall back to bus DMA - serialize with dma_mutex
    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
    return dma_request.success;
}

bool deqna_c::dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
{
    if (wordcount == 0)
        return true;

    DEBUG("DEQNA: DMA write addr=%06o words=%zu", addr, wordcount);

    uint64_t addr64 = addr;
    uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;

    // Try DDR memory first if available
    if (ddrmem && ddrmem->enabled &&
        addr64 >= ddrmem->qunibus_startaddr &&
        (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
        for (size_t i = 0; i < wordcount; ++i) {
            if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                return false;
        }
        return true;
    }

    // Fall back to bus DMA - serialize with dma_mutex
    std::lock_guard<std::recursive_mutex> lock(dma_mutex);
    qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATO, addr,
            const_cast<uint16_t *>(buffer), wordcount);
    return dma_request.success;
}

//------------------------------------------------------------------------------
// Register access helpers
//------------------------------------------------------------------------------

uint32_t deqna_c::make_addr(uint16_t hi, uint16_t lo)
{
    return (static_cast<uint32_t>(hi & 0x3F) << 16) | lo;
}

void deqna_c::csr_set_clr(uint16_t set_bits, uint16_t clr_bits)
{
    uint16_t old_csr = csr;
    csr = (csr | set_bits) & ~clr_bits;
    
    // STA ON: When OK transitions 0->1, this is significant for driver init
    if (!(old_csr & QNA_CSR_OK) && (csr & QNA_CSR_OK)) {
        DEBUG("DEQNA: STA ON - OK bit set");
    }
    
    // CRITICAL: Update the PRU register file so driver reads see new value
    update_csr_reg();
    update_intr();
}

void deqna_c::update_intr()
{
    bool want_irq = false;
    // Only allow interrupts if VAR has been written (interrupt holdoff)
    if ((csr & QNA_CSR_IE) && var_written) {
        if (csr & (QNA_CSR_RI | QNA_CSR_XI | QNA_CSR_NI))
            want_irq = true;
    }
    
    // Check if interrupt state changed
    bool was_active = irq.load(std::memory_order_acquire);
    if (want_irq && !was_active) {
        irq.store(true, std::memory_order_release);
        WARNING("DEQNA: Firing interrupt vec=%03o csr=%06o (RI=%d XI=%d NI=%d)",
                var, csr,
                (csr & QNA_CSR_RI) ? 1 : 0,
                (csr & QNA_CSR_XI) ? 1 : 0,
                (csr & QNA_CSR_NI) ? 1 : 0);
        intr_request.set_vector(var);
        qunibusadapter->INTR(intr_request, NULL, 0);
    } else if (!want_irq && was_active) {
        irq.store(false, std::memory_order_release);
        WARNING("DEQNA: Interrupt cleared, csr=%06o (RI=%d XI=%d NI=%d IE=%d)",
                csr,
                (csr & QNA_CSR_RI) ? 1 : 0,
                (csr & QNA_CSR_XI) ? 1 : 0,
                (csr & QNA_CSR_NI) ? 1 : 0,
                (csr & QNA_CSR_IE) ? 1 : 0);
        // Cancel any pending interrupt request
        qunibusadapter->cancel_INTR(intr_request);
    }
}

void deqna_c::update_csr_reg()
{
    set_register_dati_value(&registers[DEQNA_REG_CSR], csr, "csr");
}

//------------------------------------------------------------------------------
// Reset functions
//------------------------------------------------------------------------------

void deqna_c::reset_controller()
{
    WARNING("DEQNA: reset_controller called.  Flags: csr=%06o", csr);

    reset_in_progress.store(true, std::memory_order_release);
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        std::lock_guard<std::mutex> qlock(queue_mutex);
        
        csr = QNA_CSR_XL | QNA_CSR_RL | QNA_CSR_IL;  // Lists invalid, IL=1 (no internal loopback)
        var = 0;
        rbdl[0] = rbdl[1] = 0;
        xbdl[0] = xbdl[1] = 0;
        rbdl_ba = xbdl_ba = 0;
        irq.store(false, std::memory_order_release);
        var_written = false;  // Interrupt holdoff until VAR is written
        tx_kick = false;
        rx_kick = false;
        sta_on_deadline_ns = 0;
        setup_rx_deadline_ns = 0;
        
        // Full power-on reset clears entire setup structure (like OpenSIMH)
        memset(&setup, 0, sizeof(setup));
        
        write_buffer.len = 0;
        read_queue.clear();
        
        // Pre-populate all register values for PRU to serve
        update_all_registers();
    }
    reset_in_progress.store(false, std::memory_order_release);
}

void deqna_c::sw_reset()
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    std::lock_guard<std::mutex> qlock(queue_mutex);
    
    DEBUG("DEQNA: sw_reset() csr=%06o", csr);
    
    // Set XL and RL, clear most other bits including OK
    // OK will be set after 400µs delay via sta_on_deadline_ns
    csr = QNA_CSR_XL | QNA_CSR_RL;
    // Note: Do NOT set OK here - the STA ON holdoff mechanism handles that
    
    rbdl_ba = xbdl_ba = 0;
    irq.store(false, std::memory_order_release);
    // Note: var_written is PRESERVED across soft reset (VAR itself is preserved)
    tx_kick = false;
    rx_kick = false;
    setup_rx_deadline_ns = 0;  // Clear setup RX deadline
    intr_cooldown_ns = 0;      // Clear interrupt cooldown
    write_buffer.len = 0;
    read_queue.clear();
    
    // OpenSIMH-compatible: sw_reset preserves setup.valid and setup.macs[].
    // Only clear the mode flags, not the MAC address setup.
    setup.promiscuous = false;
    setup.multicast = false;
    // setup.valid and setup.macs[] are PRESERVED across soft reset!
    
    // Pre-populate all register values for PRU to serve
    update_all_registers();
}

//------------------------------------------------------------------------------
// Register access from QBUS
//------------------------------------------------------------------------------

void deqna_c::on_after_register_access(qunibusdevice_register_t *device_reg,
                                        uint8_t unibus_control, DATO_ACCESS access)
{
    // We only handle writes here. Reads are served by PRU from pre-populated values.
    if (unibus_control != QUNIBUS_CYCLE_DATO)
        return;
    
    uint8_t reg_idx = static_cast<uint8_t>(device_reg->index);
    uint16_t value = device_reg->active_dato_flipflops;
    handle_register_write(reg_idx, value, access);
}

// Pre-populate all register DATI values for PRU to serve reads
void deqna_c::update_all_registers()
{
    // DEQNA register read values:
    // STA0-STA5: Each returns 0xFF in high byte, MAC address byte in low byte
    // VAR: Vector Address Register value
    // CSR: Control/Status Register value
    
    WARNING("DEQNA: update_all_registers MAC=%02x:%02x:%02x:%02x:%02x:%02x csr=%06o var=%06o",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
            csr, var);
    
    // Station Address registers (all return 0xFF:MAC[n])
    set_register_dati_value(&registers[DEQNA_REG_STA0], 
                           static_cast<uint16_t>(0xFF00 | mac_addr[0]), "sta0");
    set_register_dati_value(&registers[DEQNA_REG_STA1], 
                           static_cast<uint16_t>(0xFF00 | mac_addr[1]), "sta1");
    set_register_dati_value(&registers[DEQNA_REG_STA2], 
                           static_cast<uint16_t>(0xFF00 | mac_addr[2]), "sta2");
    set_register_dati_value(&registers[DEQNA_REG_STA3], 
                           static_cast<uint16_t>(0xFF00 | mac_addr[3]), "sta3");
    set_register_dati_value(&registers[DEQNA_REG_STA4], 
                           static_cast<uint16_t>(0xFF00 | mac_addr[4]), "sta4");
    set_register_dati_value(&registers[DEQNA_REG_STA5], 
                           static_cast<uint16_t>(0xFF00 | mac_addr[5]), "sta5");
    
    // VAR - Vector Address Register
    set_register_dati_value(&registers[DEQNA_REG_VECTOR], var, "var");
    // CSR - Control/Status Register
    set_register_dati_value(&registers[DEQNA_REG_CSR], csr, "csr");
}

void deqna_c::handle_register_write(uint8_t reg_idx, uint16_t value, DATO_ACCESS access)
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    
    static const char *reg_names[] = {
        "STA0", "STA1", "STA2/RCLL", "STA3/RCLH", "STA4/XMTL", "STA5/XMTH", "VAR", "CSR"
    };
    const char *rname = (reg_idx < 8) ? reg_names[reg_idx] : "???";
    WARNING("DEQNA: Write %s (reg %d) = %06o access=%d", rname, reg_idx, value, access);
    
    const uint16_t byte_mask =
        (access == DATO_WORD) ? 0xffff :
        (access == DATO_BYTEH) ? 0xff00 :
        0x00ff;
    
    switch (reg_idx) {
    case DEQNA_REG_STA0:  // Read-only
    case DEQNA_REG_STA1:
        break;
        
    case DEQNA_REG_RCVLIST_LO:  // Same as DEQNA_REG_STA2
        rbdl[0] = static_cast<uint16_t>((rbdl[0] & ~byte_mask) | (value & byte_mask));
        // Note: Don't update read value - reads still return MAC address
        break;
        
    case DEQNA_REG_RCVLIST_HI:  // Same as DEQNA_REG_STA3
        rbdl[1] = static_cast<uint16_t>((rbdl[1] & ~byte_mask) | (value & byte_mask));
        // Note: Don't update read value - reads still return MAC address
        csr_set_clr(0, QNA_CSR_RL);  // Clear RL - list now valid
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
        rx_kick = true;
        DEBUG("DEQNA: RX list set rbdl_ba=%06o RL=%d csr=%06o", rbdl_ba, (csr & QNA_CSR_RL) ? 1 : 0, csr);
        break;
        
    case DEQNA_REG_XMTLIST_LO:  // Same as DEQNA_REG_STA4
        xbdl[0] = static_cast<uint16_t>((xbdl[0] & ~byte_mask) | (value & byte_mask));
        // Note: Don't update read value - reads still return MAC address
        break;
        
    case DEQNA_REG_XMTLIST_HI:  // Same as DEQNA_REG_STA5
        xbdl[1] = static_cast<uint16_t>((xbdl[1] & ~byte_mask) | (value & byte_mask));
        // Note: Don't update read value - reads still return MAC address
        csr_set_clr(0, QNA_CSR_XL);  // Clear XL - list now valid
        xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
        tx_kick = true;
        WARNING("DEQNA: TX dispatch xbdl_ba=%06o", xbdl_ba);
        break;
        
    case DEQNA_REG_VECTOR:
        {
        uint16_t merged = var;
        if (access == DATO_WORD)
            merged = value;
        else if (access == DATO_BYTEH)
            merged = static_cast<uint16_t>((var & 0x00ff) | (value & 0xff00));
        else
            merged = static_cast<uint16_t>((var & 0xff00) | (value & 0x00ff));
        
        uint16_t new_var = static_cast<uint16_t>(merged & QNA_VEC_IV);
        new_var &= static_cast<uint16_t>(~(QNA_VEC_MS | QNA_VEC_OS | QNA_VEC_RS | QNA_VEC_ST | QNA_VEC_ID));
        var = new_var;
        var_written = true;   // Allow interrupts now that vector is set
        intr_request.set_vector(var & QNA_VEC_IV);
        set_register_dati_value(&registers[DEQNA_REG_VECTOR], var, "var");
        WARNING("DEQNA: VAR set to %06o (vec=%03o), interrupts now enabled", var, var);
        // Check if we should interrupt now that holdoff is released
        update_intr();
        }
        break;
        
    case DEQNA_REG_CSR: {
        uint16_t old_csr = csr;
        uint16_t data_masked = static_cast<uint16_t>(value & byte_mask);
        
        // OpenSIMH-compatible: reset controller when SR transitions to cleared (1->0)
        // Only applies if the SR bit is actually being written (low byte or full word).
        if ((byte_mask & QNA_CSR_SR) && (old_csr & QNA_CSR_SR) && !(data_masked & QNA_CSR_SR)) {
            WARNING("DEQNA: Software reset triggered (SR falling edge 1->0)");
            sw_reset();
            // After SR, schedule STA ON (OK bit) after 400µs delay
            sta_on_deadline_ns = timeout_c::abstime_ns() + STA_ON_DELAY_NS;
            update_csr_reg();
            WARNING("DEQNA: CSR now %06o (IE=%d RE=%d OK=%d) - post-reset", csr, 
                  (csr & QNA_CSR_IE) ? 1 : 0,
                  (csr & QNA_CSR_RE) ? 1 : 0,
                  (csr & QNA_CSR_OK) ? 1 : 0);
            break;
        }
        
        // Handle write-1-to-clear bits: XI (bit 7) and RI (bit 15)
        // Also: clearing XI clears NI (per OpenSIMH)
        uint16_t w1c_mask = 0;
        if (data_masked & QNA_CSR_XI) {
            w1c_mask |= QNA_CSR_XI | QNA_CSR_NI;
            WARNING("DEQNA: Write-1-to-clear XI (and NI) - value=%06o", value);
        }
        if (data_masked & QNA_CSR_RI) {
            w1c_mask |= QNA_CSR_RI;
            WARNING("DEQNA: Write-1-to-clear RI - value=%06o", value);
        }
        
        // Writable bits: RE, SR, BD, IE, IL, EL, SE
        uint16_t wmask = QNA_CSR_RE | QNA_CSR_SR | QNA_CSR_BD | QNA_CSR_IE |
                         QNA_CSR_IL | QNA_CSR_EL | QNA_CSR_SE;
        uint16_t writable_mask = static_cast<uint16_t>(wmask & byte_mask);
        csr = static_cast<uint16_t>((csr & ~writable_mask) | (data_masked & writable_mask));
        csr = static_cast<uint16_t>(csr & ~w1c_mask);
        if (w1c_mask && (old_csr != csr)) {
            WARNING("DEQNA: CSR changed %06o -> %06o by w1c", old_csr, csr);
        }
        update_intr();
        update_csr_reg();
        WARNING("DEQNA: CSR now %06o (IE=%d RE=%d OK=%d)", csr, 
              (csr & QNA_CSR_IE) ? 1 : 0,
              (csr & QNA_CSR_RE) ? 1 : 0,
              (csr & QNA_CSR_OK) ? 1 : 0);
        break;
    }
    default:
        break;
    }
}

//------------------------------------------------------------------------------
// TX Processing
//------------------------------------------------------------------------------

bool deqna_c::dispatch_xbdl()
{
    // Don't hold lock during DMA - just set up the address
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, QNA_CSR_XL);
        xbdl_ba = make_addr(xbdl[1], static_cast<uint16_t>(xbdl[0] & ~1u));
        write_buffer.len = 0;
    }
    return process_xbdl();
}

bool deqna_c::process_xbdl()
{
    DEBUG("DEQNA: process_xbdl() starting");
    unsigned desc_count = 0;
    const unsigned max_descs = 256;
    
    while (desc_count++ < max_descs) {
        if (reset_in_progress.load())
            return false;
        
        uint32_t cur_ba;
        uint16_t csr_snap;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = xbdl_ba;
            csr_snap = csr;
        }
        
        if (cur_ba == 0)
            break;
        
        // Read descriptor
        uint16_t words[QE_RING_WORDS] = {0};
        if (!dma_read_words(cur_ba, words, QE_RING_WORDS)) {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(QNA_CSR_NI | QNA_CSR_XI | QNA_CSR_XL, 0);
            return false;
        }
        
        // Handle chain descriptor first (before checking V)
        if (words[1] & QNA_DSC_C) {
            const uint16_t flag = 0xFFFF;
            dma_write_words(cur_ba, &flag, 1);
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            xbdl_ba = make_addr(words[1], words[2]) & ~1u;
            continue;
        }
        
        // Check valid
        if (~words[1] & QNA_DSC_V) {
            // Not valid - list ends
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(QNA_CSR_XL, 0);
            return true;
        }
        
        // Mark as processed
        const uint16_t flag = 0xFFFF;
        dma_write_words(cur_ba, &flag, 1);
        
        // Calculate buffer address and length
        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        
        if (words[1] & QNA_DSC_H) { address++; if (b_length) b_length--; }
        if (words[1] & QNA_DSC_L) { if (b_length) b_length--; }
        
        // Read packet data
        size_t offset = write_buffer.len;
        if (offset + b_length > write_buffer.msg.size())
            b_length = static_cast<uint16_t>(write_buffer.msg.size() - offset);
        
        if (b_length > 0) {
            if (!dma_read_words(address, reinterpret_cast<uint16_t*>(&write_buffer.msg[offset]), 
                               (b_length + 1) / 2)) {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                csr_set_clr(QNA_CSR_NI | QNA_CSR_XI, 0);
                return false;
            }
        }
        write_buffer.len += b_length;
        
        // End of message?
        if (words[1] & QNA_DSC_E) {
            // Pad to minimum size
            if (write_buffer.len < ETH_MIN_PACKET) {
                memset(&write_buffer.msg[write_buffer.len], 0, 
                       ETH_MIN_PACKET - write_buffer.len);
                write_buffer.len = ETH_MIN_PACKET;
            }
            
            bool is_setup = (words[1] & QNA_DSC_S) != 0;
            bool loopback = (csr_snap & QNA_CSR_EL) || !(csr_snap & QNA_CSR_IL);
            
            uint16_t status[2] = {0x0000, 0x0001};
            
            if (is_setup) {
                process_setup();
                enqueue_rx(0, write_buffer.msg.data(), write_buffer.len);
                status[0] = 0x200C;
                status[1] = 0x0860;
                // Set deadline for setup RX delivery (400µs like real hardware)
                // NOTE: Don't set XI here - defer until RX response is delivered
                // This prevents DMA deadlock with pending interrupt
                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    setup_rx_deadline_ns = timeout_c::abstime_ns() + SETUP_RX_DELAY_NS;
                }
                WARNING("DEQNA: TX setup packet, len=%zu", write_buffer.len);
            } else if (loopback) {
                enqueue_rx(1, write_buffer.msg.data(), write_buffer.len);
                status[0] = 0x2100;
                // Set deadline for loopback RX delivery (400µs like real hardware)
                // NOTE: Don't set XI here - defer until RX response is delivered
                {
                    std::lock_guard<std::recursive_mutex> lock(state_mutex);
                    setup_rx_deadline_ns = timeout_c::abstime_ns() + SETUP_RX_DELAY_NS;
                }
                WARNING("DEQNA: TX loopback packet, len=%zu", write_buffer.len);
            } else {
                // Normal TX - send via pcap
                if (pcap.is_open()) {
                    pcap.send(write_buffer.msg.data(), write_buffer.len);
                    WARNING("DEQNA: TX packet sent, len=%zu dst=%02x:%02x:%02x:%02x:%02x:%02x",
                            write_buffer.len,
                            write_buffer.msg[0], write_buffer.msg[1], write_buffer.msg[2],
                            write_buffer.msg[3], write_buffer.msg[4], write_buffer.msg[5]);
                }
            }
            
            dma_write_words(cur_ba + 8, status, 2);
            
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                write_buffer.len = 0;
                // Only set XI for normal TX packets - setup/loopback defer XI until RX delivery
                if (!is_setup && !loopback) {
                    csr_set_clr(QNA_CSR_XI, 0);  // TX interrupt for normal packets
                }
                xbdl_ba = cur_ba + QE_RING_BYTES;
            }
            
            update_csr_reg();
            return true;  // One packet at a time
        } else {
            // Multi-segment packet - continue gathering
            uint16_t chain_status[2] = {static_cast<uint16_t>(QNA_DSC_V | QNA_DSC_C), 1};
            dma_write_words(cur_ba + 8, chain_status, 2);
        }
        
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            xbdl_ba = cur_ba + QE_RING_BYTES;
        }
    }
    
    return true;
}

void deqna_c::process_setup()
{
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    const uint8_t *msg = write_buffer.msg.data();
    size_t len = write_buffer.len;
    
    // Extract MAC addresses (DEQNA's unusual interleaved format)
    memset(setup.macs, 0, sizeof(setup.macs));
    for (int i = 0; i < 7; i++) {
        for (int j = 0; j < 6; j++) {
            size_t idx1 = static_cast<size_t>((i + 1) + (j * 8));
            if (idx1 < len) setup.macs[i][j] = msg[idx1];
            size_t idx2 = static_cast<size_t>((i + 0x41) + (j * 8));
            if (idx2 < len) setup.macs[i + 7][j] = msg[idx2];
        }
    }
    
    // Setup options from length encoding
    setup.promiscuous = false;
    setup.multicast = false;
    if (len > 128) {
        uint16_t flags = static_cast<uint16_t>(len & 0xffff);
        setup.multicast = (flags & 0x01) != 0;
        setup.promiscuous = (flags & 0x02) != 0;
    }
    
    setup.valid = true;
    
    DEBUG("DEQNA: Setup complete: promisc=%d multicast=%d mac=%02x:%02x:%02x:%02x:%02x:%02x",
          setup.promiscuous, setup.multicast,
          setup.macs[0][0], setup.macs[0][1], setup.macs[0][2],
          setup.macs[0][3], setup.macs[0][4], setup.macs[0][5]);
}

//------------------------------------------------------------------------------
// RX Processing
//------------------------------------------------------------------------------

void deqna_c::enqueue_rx(int type, const uint8_t *data, size_t len)
{
    std::lock_guard<std::mutex> lock(queue_mutex);
    
    if (read_queue.size() >= 64) {
        read_queue.pop_front();  // Drop oldest
    }
    
    packet_t pkt;
    pkt.type = type;
    pkt.len = len;
    pkt.used = 0;
    memcpy(pkt.msg.data(), data, len);
    read_queue.push_back(std::move(pkt));
}

bool deqna_c::dispatch_rbdl()
{
    // Don't hold lock during DMA - just set up the address
    {
        std::lock_guard<std::recursive_mutex> lock(state_mutex);
        csr_set_clr(0, QNA_CSR_RL);
        rbdl_ba = make_addr(rbdl[1], static_cast<uint16_t>(rbdl[0] & ~1u));
    }
    return process_rbdl();
}

bool deqna_c::process_rbdl()
{
    unsigned desc_count = 0;
    unsigned packets_delivered = 0;
    const unsigned max_descs = 256;
    
    while (desc_count++ < max_descs) {
        if (reset_in_progress.load())
            return false;
        
        // Check for packet first - don't read/mark descriptors if queue empty
        int pkt_type = 2;
        {
            std::lock_guard<std::mutex> qlock(queue_mutex);
            if (read_queue.empty())
                break;
            pkt_type = read_queue.front().type;
        }
        
        uint32_t cur_ba;
        uint16_t csr_snap;
        uint64_t deadline;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            cur_ba = rbdl_ba;
            csr_snap = csr;
            deadline = setup_rx_deadline_ns;
        }
        
        // Normal packets need RE enabled; setup/loopback bypass
        if (pkt_type == 2 && !(csr_snap & QNA_CSR_RE))
            return true;
        
        // Setup/loopback packets (type 0 or 1) wait for 400µs delay
        if (pkt_type != 2 && deadline != 0 && timeout_c::abstime_ns() < deadline)
            return true;  // Not ready yet, try again later
        
        // Read descriptor
        uint16_t words[QE_RING_WORDS] = {0};
        if (!dma_read_words(cur_ba, words, QE_RING_WORDS)) {
            // DMA failed (likely due to interrupt pending) - don't set RI/NI
            // Just mark list invalid and return, we'll retry later
            WARNING("DEQNA: RX descriptor DMA failed at %06o, will retry", cur_ba);
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            csr_set_clr(QNA_CSR_RL, 0);  // Mark list invalid
            return false;
        }
        
        // Check valid first - if descriptor not valid, stop and wait for host to set it up
        // DON'T set RL here - RSX just sets V bits without rewriting RCLH
        // We'll check again on next worker iteration
        if (~words[1] & QNA_DSC_V) {
            return true;  // Stop for now, try again later when driver sets V
        }
        
        // Handle chain
        if (words[1] & QNA_DSC_C) {
            const uint16_t flag = 0xFFFF;
            dma_write_words(cur_ba, &flag, 1);
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = make_addr(words[1], words[2]) & ~1u;
            continue;
        }
        
        // Get packet BEFORE marking descriptor as processed
        // This prevents marking descriptors consumed when queue is empty
        packet_t pkt;
        {
            std::lock_guard<std::mutex> qlock(queue_mutex);
            if (read_queue.empty())
                break;  // Don't mark descriptor - we'll use it when packets arrive
            pkt = std::move(read_queue.front());
            read_queue.pop_front();
        }
        
        // NOW mark descriptor as processed (we have a packet to deliver)
        const uint16_t flag = 0xFFFF;
        dma_write_words(cur_ba, &flag, 1);
        packets_delivered++;
        
        // Calculate buffer info
        uint32_t address = make_addr(words[1], words[2]);
        uint16_t w_length = static_cast<uint16_t>(~words[3] + 1);
        uint16_t b_length = static_cast<uint16_t>(w_length * 2);
        
        if (words[1] & QNA_DSC_H) { address++; if (b_length) b_length--; }
        if (words[1] & QNA_DSC_L) { if (b_length) b_length--; }
        
        // Write packet data
        size_t rbl = pkt.len - pkt.used;
        uint8_t *rbuf = &pkt.msg[pkt.used];
        
        bool overflow = false;
        if (rbl > b_length) {
            overflow = true;
            pkt.used += b_length;
            rbl = b_length;
        } else {
            pkt.used = pkt.len;
        }
        
        if (rbl > 0) {
            dma_write_words(address, reinterpret_cast<uint16_t*>(rbuf), (rbl + 1) / 2);
        }
        
        // DEQNA-specific: Write 0xC000 after setup packet data (QDTC chip quirk)
        // OpenSIMH: "Strange DEQNA behavior" - writes this marker at end of data
        // Drivers may depend on this to verify setup packet was received
        if (pkt.type == 0 && b_length >= rbl + 2) {
            const uint16_t qdtc_chip_extra = 0xC000;
            dma_write_words(address + rbl, &qdtc_chip_extra, 1);
        }
        
        // Build status
        // Status word 1 format (from OpenSIMH pdp11_xq.h):
        // Bits 15:14 = 00: LASTNOERR (Used, Last segment, no errors)
        // Bits 15:14 = 01: LASTERR (Used, Last segment, with errors)  
        // Bits 15:14 = 10: UNUSED
        // Bits 15:14 = 11: LASTNOT (Used but Not Last segment)
        // Bits 10:8 = RBL high bits
        // Bits 7:3 = Reserved (set to 1 = 0x00F8 for normal packets)
        uint16_t status1 = 0;
        uint16_t report_rbl = static_cast<uint16_t>(pkt.len);
        
        switch (pkt.type) {
        case 0:  // Setup response - per OpenSIMH, use fixed 0x2700
            // This is ESETUP (0x2000) | RBL high bits (0x0700) 
            status1 = 0x2700;
            break;
        case 1:  // Loopback response - no error flags, just RBL
            status1 = static_cast<uint16_t>(report_rbl & 0x0700);
            if (csr_snap & QNA_CSR_EL)
                status1 |= QE_ESETUP;  // Mark as external loopback
            break;
        default: // Normal packet - ALWAYS subtract 60 per DEQNA spec
            // This keeps max packet size in 11 bits (1518-60=1458, fits in 11 bits)
            report_rbl = static_cast<uint16_t>(pkt.len - 60);
            // Status1 = RBL<10:8> | reserved bits (0x00F8) | LASTNOERR (0x0000)
            status1 = static_cast<uint16_t>((report_rbl & 0x0700) | 0x00F8);
            break;
        }
        
        if (overflow) {
            // XQ_RST_LASTERR (0x4000) + overflow + discard flags
            status1 = (status1 & 0x0FFF) | 0x4000 | QE_OVF | QE_DISCARD;
        } else if (pkt.used < pkt.len) {
            // XQ_RST_LASTNOT (0xC000) = Used but Not Last segment
            status1 = (status1 & 0x0FFF) | 0xC000;
        }
        // else: keep LASTNOERR (0x0000 in bits 15:14)
        
        uint16_t status2 = static_cast<uint16_t>((report_rbl & 0xFF) << 8 | (report_rbl & 0xFF));
        uint16_t status[2] = {status1, status2};
        dma_write_words(cur_ba + 8, status, 2);
        
        DEBUG("DEQNA: RX delivered type=%d len=%zu to desc=%06o", pkt.type, pkt.len, cur_ba);
        
        // If packet incomplete, re-queue
        if (pkt.used < pkt.len) {
            std::lock_guard<std::mutex> qlock(queue_mutex);
            read_queue.push_front(std::move(pkt));
        } else {
            // Packet complete - set RI (and XI for setup/loopback responses)
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            // Clear setup/loopback deadline now that we've delivered
            if (pkt.type == 0 || pkt.type == 1) {
                setup_rx_deadline_ns = 0;
                // For setup/loopback, set BOTH XI (deferred from TX) and RI
                csr_set_clr(QNA_CSR_XI | QNA_CSR_RI, 0);
                WARNING("DEQNA: Setup/loopback RX complete, setting XI+RI");
                // IMPORTANT: Return immediately - don't do more DMA while interrupt pending
                // The PRU needs time to process the interrupt before we can do more DMA
                rbdl_ba = cur_ba + QE_RING_BYTES;
                return true;
            } else {
                // Only set RI if not already set - avoid rapid-fire interrupts
                if (!(csr & QNA_CSR_RI)) {
                    csr_set_clr(QNA_CSR_RI, 0);
                }
            }
        }
        
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            rbdl_ba = cur_ba + QE_RING_BYTES;
        }
        
        update_csr_reg();
        return true;  // One packet at a time
    }
    
    return true;
}

//------------------------------------------------------------------------------
// Packet filtering
//------------------------------------------------------------------------------

bool deqna_c::mac_match(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

bool deqna_c::mac_is_zero(const uint8_t *a)
{
    return a[0] == 0 && a[1] == 0 && a[2] == 0 &&
           a[3] == 0 && a[4] == 0 && a[5] == 0;
}

bool deqna_c::mac_is_broadcast(const uint8_t *a)
{
    return a[0] == 0xFF && a[1] == 0xFF && a[2] == 0xFF &&
           a[3] == 0xFF && a[4] == 0xFF && a[5] == 0xFF;
}

bool deqna_c::mac_is_multicast(const uint8_t *a)
{
    return (a[0] & 0x01) != 0;
}

bool deqna_c::accept_packet(const uint8_t *data, size_t len)
{
    if (len < 14)
        return false;
    
    std::lock_guard<std::recursive_mutex> lock(state_mutex);
    
    const uint8_t *dst = data;
    
    // Promiscuous accepts everything
    if (setup.valid && setup.promiscuous) {
        DEBUG("DEQNA: accept_packet: promiscuous mode");
        return true;
    }
    
    // Broadcast always accepted
    if (mac_is_broadcast(dst)) {
        DEBUG("DEQNA: accept_packet: broadcast");
        return true;
    }
    
    // Our hardware MAC (from parameter, always checked)
    if (mac_match(dst, mac_addr)) {
        DEBUG("DEQNA: accept_packet: our MAC");
        return true;
    }
    
    // Check all setup filter MACs (up to QNA_FILTER_MAX=14)
    if (setup.valid) {
        for (int i = 0; i < QNA_FILTER_MAX; i++) {
            if (mac_is_zero(setup.macs[i]))
                continue;
            if (mac_match(dst, setup.macs[i])) {
                DEBUG("DEQNA: accept_packet: setup MAC[%d]", i);
                return true;
            }
        }
        // All-multicast mode accepts any multicast
        if (setup.multicast && mac_is_multicast(dst)) {
            DEBUG("DEQNA: accept_packet: multicast");
            return true;
        }
    }
    
    // Rejected - log why (at DEBUG level to avoid spam)
    DEBUG("DEQNA: reject pkt dst=%02x:%02x:%02x:%02x:%02x:%02x mac_addr=%02x:%02x:%02x:%02x:%02x:%02x setup.valid=%d",
          dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
          mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
          setup.valid);
    
    return false;
}

//------------------------------------------------------------------------------
// Main worker loop
//------------------------------------------------------------------------------

void deqna_c::worker(unsigned instance)
{
    UNUSED(instance);
    WARNING("DEQNA: Worker started");
    
    uint8_t pkt_buf[2048];
    
    while (!workers_terminate) {
        if (reset_in_progress.load()) {
            timeout_c::wait_ms(1);
            continue;
        }
        
        // Handle STA ON deferred interrupt (OK bit transition after SR)
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (sta_on_deadline_ns != 0 && timeout_c::abstime_ns() >= sta_on_deadline_ns) {
                sta_on_deadline_ns = 0;
                csr_set_clr(QNA_CSR_OK, 0);  // Set transceiver OK
                update_csr_reg();
                WARNING("DEQNA: STA ON - OK bit set after 400us delay");
            }
        }
        
        // Skip if INIT asserted
        if (init_asserted || qunibusadapter->line_INIT) {
            timeout_c::wait_ms(1);
            continue;
        }
        
        // Handle TX dispatch request
        bool do_tx = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (tx_kick) {
                tx_kick = false;
                do_tx = true;
            } else if (!(csr & QNA_CSR_XL) && xbdl_ba != 0) {
                do_tx = true;
            }
        }
        if (do_tx) {
            process_xbdl();
        }
        
        // Handle RX dispatch request
        bool do_rx = false;
        {
            std::lock_guard<std::recursive_mutex> lock(state_mutex);
            if (rx_kick) {
                rx_kick = false;
                do_rx = true;
            }
        }
        if (do_rx) {
            process_rbdl();
        }
        
        // Poll for incoming packets from network
        if (pcap.is_open()) {
            bool re_enabled;
            {
                std::lock_guard<std::recursive_mutex> lock(state_mutex);
                re_enabled = (csr & QNA_CSR_RE) != 0;
            }
            
            if (re_enabled) {
                size_t len = 0;
                if (pcap.poll(pkt_buf, sizeof(pkt_buf), &len) && len > 0) {
                    bool accepted = accept_packet(pkt_buf, len);
                    if (accepted) {
                        WARNING("DEQNA: RX accepted len=%zu dst=%02x:%02x:%02x:%02x:%02x:%02x",
                                len, pkt_buf[0], pkt_buf[1], pkt_buf[2], pkt_buf[3], pkt_buf[4], pkt_buf[5]);
                        enqueue_rx(2, pkt_buf, len);
                    }
                    // Don't log rejected packets at WARNING level - too spammy
                }
            }
        }
        
        // Process RX queue if we have packets
        // IMPORTANT: Don't hold state_mutex across process_rbdl() - it does its own locking
        // and holding the lock here blocks register writes from the bus
        {
            bool has_packets;
            {
                std::lock_guard<std::mutex> qlock(queue_mutex);
                has_packets = !read_queue.empty();
            }
            if (has_packets) {
                process_rbdl();
            }
        }
        
        timeout_c::wait_ms(1);
    }
    
    DEBUG("DEQNA: Worker stopped");
}
