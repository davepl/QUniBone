PRU Arbitration Changes

Summary
These changes let the PRU arbitration proceed even while a device register
access is still pending, and remove the SSYN wait in the arbitration state
machine before granting NPR/BR requests. This prevents a deadlock where CPU
CSR polling holds SSYN while the PRU waits to arbitrate DMA.

Rationale
On a real DELQA, NPR/BR arbitration can proceed even while the CPU is doing
CSR cycles. The previous PRU logic gated arbitration on completion of the
deviceregister event and also waited for SSYN to clear before granting. When
the CPU polls CSR in a tight loop, SSYN remains asserted until ARM acks the
event, which blocked NPR/BR arbitration and prevented DMA completion. The CPU
then waits for DMA completion, creating a deadlock.

Code Changes
1) pru1_main_unibus.c
   - Arbitration now runs regardless of a pending deviceregister event.
   - This allows NPR/BR lines to be asserted and grants to be consumed even
     while CSR accesses are still being processed by ARM.

2) pru1_statemachine_arbitration.c
   - Removed the SSYN wait in State 2 of sm_arb_worker_device().
   - Arbitration now waits only for BG/NPG and BBSY to clear before granting.
     SSYN may still be asserted due to CSR access; we no longer block NPR/BR
     on that condition.

Expected Effect
DMA requests from devices (like DELQA) should no longer stall when the CPU is
polling device registers. This aligns PRU arbitration closer to real bus
master behavior and avoids priority inversion between CSR polling and DMA.

Note
Q-bus Specification Reference
Per DEC's Q-bus specification, NPR arbitration is asynchronous to the current
bus cycle. A device may assert NPR at any time, and NPG is granted when:
  - The current bus master releases BBSY
  - No higher-priority request is pending
SSYN is not part of the NPR/NPG handshake and should not gate arbitration.

What Claude had to say:

"Your analysis and proposed fix look correct to me. Here are my thoughts:

Agreement with the Diagnosis
The deadlock scenario you've identified is exactly what the logs showed:

CPU polls CSR → SSYN asserted
PRU waits for ARM to process the register access
DELQA worker thread tries to do DMA
PRU arbitration blocked waiting for SSYN to clear
ARM can't complete register access until DMA finishes (or vice versa)
Deadlock
This matches the Q-bus specification: NPR/BR arbitration is independent of the current bus cycle. A device can request the bus (assert NPR) even while another cycle is in progress. The grant happens after BBSY clears, not after SSYN clears.

The Fix is Architecturally Correct
On real Q-bus hardware:

SSYN indicates the slave is responding to the current address/data
BBSY indicates the bus is actively being used for a transfer
NPR/NPG arbitration should wait for BBSY to clear, not SSYN
The previous PRU code was too conservative - waiting for SSYN essentially serialized everything through the ARM, which created the priority inversion."
ß