Author: Dave Plummer (davepl@davepl.com)
(c) 2025 Plummer's Software LLC
Contributed under the GPL2 License

# DELQA (DEQNA/DELQA) Ethernet Emulation

This adds a virtual QBUS Ethernet NIC that follows the DEQNA/DELQA register interface and
bridges frames to the host interface using libpcap.

## Overview

- Registers: direct-mapped DEQNA layout at CSR base (station address bytes, list pointers,
  vector, CSR).
- DMA: RX/TX ring descriptors (qe_ring, 6 words) and frame buffers in PDP-11 memory.
- Interrupts: QE_RCV_INT/QE_XMIT_INT with QE_INT_ENABLE.
- Host bridge: libpcap capture/inject on the selected interface.

## Configuration

The runtime uses the device parameter interface (menu `p` command) to configure the NIC:

- `ifname` (string): host interface name (e.g., `eth0`).
- `mac` (string): MAC override (`aa:bb:cc:dd:ee:ff`), empty = device default.
- `promisc` (bool): enable promiscuous capture (default true).
- `rx_slots` / `tx_slots` (unsigned): ring scan limit per poll (0 = unlimited).
- `base_addr`, `intr_vector`, `intr_level`, `priority_slot`: normal qunibus device params.

## Quickstart (QBUS / 2.11BSD)

1. Build with libpcap installed (ensure `pcap-config` is available or define `HAVE_PCAP`).
2. Start the demo and enable the `delqa` device in the devices menu.
3. On the PDP-11:
   - `ifconfig qe0 <ip> netmask <mask> up`
   - `arp -a`
   - `ping <host>`

## Limitations (MVP)

- Single-buffer frames only; chaining is handled only for ring wrap.
- Multicast filter emulation not implemented; promisc is recommended.
- Minimal error/loopback semantics.

## Debugging

Set `trace=1` to log register and ring events.
