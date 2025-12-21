Author: Dave Plummer (davepl@davepl.com)
(c) 2025 Plummer's Software LLC
Contributed under the GPL2 License

# DELQA (DEQNA/DELQA) Ethernet Emulation

This adds a virtual QBUS Ethernet NIC that follows the DEQNA/DELQA (LANCE-style) programmer's model and bridges frames to the host interface using libpcap.

## Overview

- Registers: RDP/RAP at CSR base, with CSR0..CSR3 (LANCE-style).
- DMA: init block, RX/TX ring descriptors, and frame buffers live in PDP-11 memory.
- Host bridge: libpcap capture/inject on the selected interface.

## Configuration

The runtime uses the device parameter interface (menu `p` command) to configure the NIC:

- `ifname` (string): host interface name (e.g., `eth0`).
- `mac` (string): MAC override (`aa:bb:cc:dd:ee:ff`), empty = use init block.
- `promisc` (bool): enable promiscuous capture (default true).
- `rx_slots` / `tx_slots` (unsigned): ring slots (power of two). `0` means use init block length.
- `base_addr`, `intr_vector`, `intr_level`, `priority_slot`: normal qunibus device params.

## Quickstart (QBUS / 2.11BSD)

1. Build with libpcap installed (ensure `pcap-config` is available or define `HAVE_PCAP`).
2. Start the demo and enable the `delqa` device in the devices menu.
3. On the PDP-11:
   - `ifconfig qe0 <ip> netmask <mask> up`
   - `arp -a`
   - `ping <host>`

## Limitations (MVP)

- RX/TX assumes single-buffer frames (STP|ENP only).
- No multicast filter emulation; promisc is recommended.
- Minimal CSR3 handling.

## Debugging

Set `trace=1` to log init/ring events.
