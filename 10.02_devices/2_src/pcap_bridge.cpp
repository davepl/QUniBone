/*
 * Author: Dave Plummer (davepl@davepl.com)
 * (c) 2025 Plummer's Software LLC
 * Contributed under the GPL2 License
 */

#include "pcap_bridge.hpp"

#include <string.h>

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

bool PcapBridge::open(const std::string &ifname, bool promisc, int snaplen, int timeout_ms)
{
    std::lock_guard<std::mutex> lock(pcap_mutex);
    error_text.clear();

#ifdef HAVE_PCAP
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    pcap_handle = pcap_open_live(ifname.c_str(), snaplen, promisc ? 1 : 0, timeout_ms, errbuf);
    if (!pcap_handle) {
        error_text = errbuf;
        return false;
    }

    return true;
#else
    (void)ifname;
    (void)promisc;
    (void)snaplen;
    (void)timeout_ms;
    error_text = "libpcap not available";
    return false;
#endif
}

void PcapBridge::close(void)
{
    std::lock_guard<std::mutex> lock(pcap_mutex);
#ifdef HAVE_PCAP
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
#endif
    error_text.clear();
}

bool PcapBridge::poll(uint8_t *buf, size_t bufcap, size_t *len)
{
    if (len) {
        *len = 0;
    }

#ifdef HAVE_PCAP
    std::lock_guard<std::mutex> lock(pcap_mutex);
    if (!pcap_handle) {
        error_text = "pcap not open";
        return false;
    }

    struct pcap_pkthdr *hdr = nullptr;
    const u_char *data = nullptr;
    int res = pcap_next_ex(pcap_handle, &hdr, &data);
    if (res == 0) {
        // Timeout - no packet available, but not an error
        return true;
    }
    if (res < 0) {
        error_text = pcap_geterr(pcap_handle);
        return false;
    }

    size_t copy_len = hdr->caplen;
    if (copy_len > bufcap) {
        copy_len = bufcap;
    }
    if (copy_len && data && buf) {
        memcpy(buf, data, copy_len);
    }
    if (len) {
        *len = copy_len;
    }

    return true;
#else
    (void)buf;
    (void)bufcap;
    (void)len;
    error_text = "libpcap not available";
    return false;
#endif
}

bool PcapBridge::send(const uint8_t *buf, size_t len)
{
#ifdef HAVE_PCAP
    std::lock_guard<std::mutex> lock(pcap_mutex);
    if (!pcap_handle) {
        error_text = "pcap not open";
        return false;
    }

    int res = pcap_inject(pcap_handle, buf, len);
    if (res < 0) {
        error_text = pcap_geterr(pcap_handle);
        return false;
    }
    return true;
#else
    (void)buf;
    (void)len;
    error_text = "libpcap not available";
    return false;
#endif
}
