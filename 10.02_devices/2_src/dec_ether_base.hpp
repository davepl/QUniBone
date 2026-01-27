/*
 * Common Ethernet device base for QUniBone
 *
 *   May be based in part on the DEQNA implementation in the OpenSIMH project:
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
 *
 * Consolidates shared DMA/descriptor helpers and interrupt/DMA deadlock mitigations
 * used by DEQNA (QBUS) and DEUNA (UNIBUS) implementations.
 */
#ifndef _DEC_ETHER_BASE_HPP_
#define _DEC_ETHER_BASE_HPP_

#include <stdint.h>
#include <stddef.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "logger.hpp"
#include "timeout.hpp"
#include "qunibus.h"
#include "qunibusadapter.hpp"
#include "ddrmem.h"
#include "qunibusdevice.hpp"
#include "priorityrequest.hpp"
#include "pcap_bridge.hpp"

class dec_ether_base_c : public qunibusdevice_c {
public:
    dec_ether_base_c() :
            qunibusdevice_c(),
            intr_request(this),
            dma_request(this),
            dma_desc_request(this)
    {}

    ~dec_ether_base_c() override = default;

    // Common Ethernet helper functions (shared by DEQNA/DEUNA).
    static inline bool mac_is_zero(const uint8_t *mac)
    {
        return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
               mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
    }

    static inline bool mac_is_broadcast(const uint8_t *mac)
    {
        return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
               mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff;
    }

    static inline bool mac_is_multicast(const uint8_t *mac)
    {
        return (mac[0] & 0x01) != 0;
    }

    static inline bool mac_equal(const uint8_t *a, const uint8_t *b)
    {
        return std::memcmp(a, b, 6) == 0;
    }

    template <typename T, size_t N>
    static constexpr size_t arraysize(const T (&)[N]) noexcept
    {
        return N;
    }

    static inline bool parse_mac(const std::string &text, uint8_t out[6])
    {
        unsigned values[6];
        if (text.empty())
            return false;
        if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x",
                        &values[0], &values[1], &values[2],
                        &values[3], &values[4], &values[5]) != 6)
            return false;
        for (int i = 0; i < 6; ++i) {
            if (values[i] > 0xff)
                return false;
            out[i] = static_cast<uint8_t>(values[i]);
        }
        return true;
    }

protected:
    // Bus requests for interrupts and DMA (common to both devices)
    intr_request_c intr_request;
    dma_request_c dma_request;
    dma_request_c dma_desc_request;

    // Network bridge (common)
    PcapBridge pcap;

    // DMA synchronization and tracking
    std::recursive_mutex dma_mutex;
    std::atomic<unsigned> dma_in_progress{0};  // For diagnostic output only
    std::atomic<bool> reset_in_progress{false};  // Flag to abort operations during reset

    // Device-specific interrupt update
    virtual void update_intr(void) = 0;
    // Optional hook when DMA transitions to idle (dma_in_progress -> 0)
    virtual void on_dma_quiet(void) {}

    // DMA tracking guard (for diagnostic output)
    struct dma_inflight_guard {
        dec_ether_base_c &dev;
        explicit dma_inflight_guard(dec_ether_base_c &device) : dev(device)
        {
            dev.dma_in_progress.fetch_add(1, std::memory_order_acq_rel);
        }
        ~dma_inflight_guard()
        {
            if (dev.dma_in_progress.fetch_sub(1, std::memory_order_acq_rel) == 1)
                dev.on_dma_quiet();
        }
    };

    inline bool addr_in_ram(uint32_t addr, uint64_t byte_count) const
    {
        if (byte_count == 0)
            return true;
        if (!qunibus)
            return false;
        uint64_t addr64 = addr;
        uint64_t max = qunibus->addr_space_byte_count;
        bool ok = !(max == 0 || addr64 >= max || byte_count > max - addr64);
        return ok;
    }

    inline void note_intr_asserted(void)
    {
        // SIMPLIFIED: No-op. DMA holdoff logic has been removed.
    }

    inline void note_intr_deasserted(void)
    {
        // SIMPLIFIED: No-op. DMA holdoff logic has been removed.
    }

    inline void holdoff_dma_if_intr_pending(void)
    {
        // SIMPLIFIED: No DMA holdoff. The QBUS allows concurrent DMA and interrupt
        // handling. The PRU handles NPR (DMA) and BR (interrupt) independently.
        // Previous versions blocked DMA while interrupts were pending, causing
        // deadlocks and TX watchdog timeouts.
    }

    inline bool dma_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
    {
        if (wordcount == 0)
            return true;
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;
        uint64_t addr64 = addr;
        uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
        uint64_t max = qunibus->addr_space_byte_count;
        if (!addr_in_ram(addr, byte_count)) {
            WARNING("%s: dma_read_words bounds check failed: addr=%06o words=%zu max=%llu",
                    name.value.c_str(), addr, wordcount, static_cast<unsigned long long>(max));
            return false;
        }

        if (ddrmem && ddrmem->enabled &&
            addr64 >= ddrmem->qunibus_startaddr &&
            (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
            for (size_t i = 0; i < wordcount; ++i) {
                if (!ddrmem->exam(addr + static_cast<uint32_t>(i * 2), &buffer[i]))
                    return false;
            }
            return true;
        }

        std::lock_guard<std::recursive_mutex> lock(dma_mutex);
        holdoff_dma_if_intr_pending();
        dma_inflight_guard guard(*this);
        update_intr(); // gate bus-level INTR while DMA is active
        const int max_attempts = 3;
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
            if (dma_request.success)
                return true;
            if (attempt + 1 < max_attempts)
                timeout_c::wait_us(10);
        }
        return false;
    }

    inline bool dma_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
    {
        if (wordcount == 0)
            return true;
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;
        uint64_t addr64 = addr;
        uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
        uint64_t max = qunibus->addr_space_byte_count;
        if (!addr_in_ram(addr, byte_count)) {
            WARNING("%s: dma_write_words bounds check failed: addr=%06o words=%zu max=%llu",
                    name.value.c_str(), addr, wordcount, static_cast<unsigned long long>(max));
            return false;
        }

        if (ddrmem && ddrmem->enabled &&
            addr64 >= ddrmem->qunibus_startaddr &&
            (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
            for (size_t i = 0; i < wordcount; ++i) {
                if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                    return false;
            }
            return true;
        }

        std::lock_guard<std::recursive_mutex> lock(dma_mutex);
        holdoff_dma_if_intr_pending();
        dma_inflight_guard guard(*this);
        update_intr(); // gate bus-level INTR while DMA is active
        const int max_attempts = 3;
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            qunibusadapter->DMA(dma_request, true, QUNIBUS_CYCLE_DATO, addr,
                    const_cast<uint16_t *>(buffer), wordcount);
            if (dma_request.success)
                return true;
            if (attempt + 1 < max_attempts)
                timeout_c::wait_us(10);
        }
        return false;
    }

    inline bool desc_read_words(uint32_t addr, uint16_t *buffer, size_t wordcount)
    {
        if (wordcount == 0)
            return true;
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;
        uint64_t addr64 = addr;
        uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
        uint64_t max = qunibus->addr_space_byte_count;
        if (!addr_in_ram(addr, byte_count)) {
            WARNING("%s: desc_read_words bounds check failed: addr=%06o words=%zu max=%llu",
                    name.value.c_str(), addr, wordcount, static_cast<unsigned long long>(max));
            return false;
        }

        if (ddrmem && ddrmem->enabled &&
            addr64 >= ddrmem->qunibus_startaddr &&
            (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
            for (size_t i = 0; i < wordcount; ++i) {
                if (!ddrmem->exam(addr + static_cast<uint32_t>(i * 2), &buffer[i]))
                    return false;
            }
            return true;
        }

        std::lock_guard<std::recursive_mutex> lock(dma_mutex);
        holdoff_dma_if_intr_pending();
        dma_inflight_guard guard(*this);
        update_intr(); // gate bus-level INTR while DMA is active
        const int max_attempts = 3;
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            qunibusadapter->DMA(dma_desc_request, true, QUNIBUS_CYCLE_DATI, addr, buffer, wordcount);
            if (dma_desc_request.success)
                return true;
            if (attempt + 1 < max_attempts)
                timeout_c::wait_us(10);
        }
        return false;
    }

    inline bool desc_write_words(uint32_t addr, const uint16_t *buffer, size_t wordcount)
    {
        if (wordcount == 0)
            return true;
        if (reset_in_progress.load(std::memory_order_acquire))
            return false;
        uint64_t addr64 = addr;
        uint64_t byte_count = static_cast<uint64_t>(wordcount) * 2;
        uint64_t max = qunibus->addr_space_byte_count;
        if (!addr_in_ram(addr, byte_count)) {
            WARNING("%s: desc_write_words bounds check failed: addr=%06o words=%zu max=%llu",
                    name.value.c_str(), addr, wordcount, static_cast<unsigned long long>(max));
            return false;
        }

        if (ddrmem && ddrmem->enabled &&
            addr64 >= ddrmem->qunibus_startaddr &&
            (addr64 + byte_count - 2) <= ddrmem->qunibus_endaddr) {
            for (size_t i = 0; i < wordcount; ++i) {
                if (!ddrmem->deposit(addr + static_cast<uint32_t>(i * 2), buffer[i]))
                    return false;
            }
            return true;
        }

        std::lock_guard<std::recursive_mutex> lock(dma_mutex);
        holdoff_dma_if_intr_pending();
        dma_inflight_guard guard(*this);
        update_intr(); // gate bus-level INTR while DMA is active
        const int max_attempts = 3;
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            qunibusadapter->DMA(dma_desc_request, true, QUNIBUS_CYCLE_DATO, addr,
                    const_cast<uint16_t *>(buffer), wordcount);
            if (dma_desc_request.success)
                return true;
            if (attempt + 1 < max_attempts)
                timeout_c::wait_us(10);
        }
        return false;
    }

    inline bool dma_read_bytes(uint32_t addr, uint8_t *buffer, size_t len)
    {
        if (len == 0)
            return true;
        uint64_t byte_count = static_cast<uint64_t>(len);
        if (!addr_in_ram(addr, byte_count))
            return false;

        if (addr & 1) {
            uint16_t word = 0;
            if (addr == 0 || !dma_read_words(addr - 1, &word, 1))
                return false;
            buffer[0] = static_cast<uint8_t>((word >> 8) & 0xff);
            addr += 1;
            buffer += 1;
            len -= 1;
        }

        size_t full_words = len / 2;
        if (full_words) {
            std::vector<uint16_t> words(full_words);
            if (!dma_read_words(addr, words.data(), full_words))
                return false;
            for (size_t i = 0; i < full_words; ++i) {
                buffer[i * 2] = static_cast<uint8_t>(words[i] & 0xff);
                buffer[i * 2 + 1] = static_cast<uint8_t>((words[i] >> 8) & 0xff);
            }
        }

        if (len & 1) {
            uint16_t word = 0;
            if (!dma_read_words(addr + static_cast<uint32_t>(full_words * 2), &word, 1))
                return false;
            buffer[full_words * 2] = static_cast<uint8_t>(word & 0xff);
        }
        return true;
    }

    inline bool dma_write_bytes(uint32_t addr, const uint8_t *buffer, size_t len)
    {
        if (len == 0)
            return true;
        uint64_t byte_count = static_cast<uint64_t>(len);
        if (!addr_in_ram(addr, byte_count))
            return false;

        if (addr & 1) {
            uint16_t word = 0;
            if (addr == 0 || !dma_read_words(addr - 1, &word, 1))
                return false;
            word = static_cast<uint16_t>((word & 0x00ff) | (static_cast<uint16_t>(buffer[0]) << 8));
            if (!dma_write_words(addr - 1, &word, 1))
                return false;
            addr += 1;
            buffer += 1;
            len -= 1;
        }

        size_t full_words = len / 2;
        size_t remaining = len & 1;

        // Chunk writes to avoid allocating huge buffers (len is small for Ethernet frames).
        const size_t chunk_words = 256;
        size_t offset_words = 0;
        while (offset_words < full_words) {
            size_t this_chunk = std::min(chunk_words, full_words - offset_words);
            std::vector<uint16_t> words(this_chunk);
            for (size_t i = 0; i < this_chunk; ++i) {
                size_t byte_index = (offset_words + i) * 2;
                words[i] = static_cast<uint16_t>(buffer[byte_index] |
                        (static_cast<uint16_t>(buffer[byte_index + 1]) << 8));
            }
            if (!dma_write_words(addr + static_cast<uint32_t>(offset_words * 2), words.data(), this_chunk))
                return false;
            offset_words += this_chunk;
        }

        if (remaining) {
            uint16_t word = 0;
            if (!dma_read_words(addr + static_cast<uint32_t>(full_words * 2), &word, 1))
                return false;
            word = static_cast<uint16_t>((word & 0xff00) | buffer[full_words * 2]);
            if (!dma_write_words(addr + static_cast<uint32_t>(full_words * 2), &word, 1))
                return false;
        }
        return true;
    }
};

#endif
