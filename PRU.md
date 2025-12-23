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
