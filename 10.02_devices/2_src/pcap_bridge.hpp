/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2025 Plummer's Software LLC
 * Contributed under the GPL2 License
 */
#ifndef _PCAP_BRIDGE_HPP_
#define _PCAP_BRIDGE_HPP_

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <mutex>

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#else
typedef struct pcap pcap_t;
#endif

class PcapBridge {
public:
    bool open(const std::string &ifname, bool promisc, int snaplen = 2048, int timeout_ms = 1);
    void close(void);

    bool poll(uint8_t *buf, size_t bufcap, size_t *len);
    bool send(const uint8_t *buf, size_t len);
    bool set_filter(const std::string &expr);

    bool is_open(void) const {
        return (pcap_handle != nullptr);
    }

    const std::string &last_error(void) const {
        return error_text;
    }

private:
    pcap_t *pcap_handle = nullptr;
    std::mutex pcap_mutex;
    std::string error_text;
};

#endif
