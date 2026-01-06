# QBone/UniBone CPU Emulation Implementation Plan

## Goal
Enable QBone/UniBone to act as the only CPU on a powered backplane, booting and running a PDP-11 system without a physical CPU present. Support two modes:
1) Bus-master memory (cycle-accurate, bus-bound performance)
2) Local DDR memory (fast CPU, bus used only for IO and interrupts)

## Non-goals
- Full cycle-accurate timing for all DEC CPU models (initially focus on correctness and stability)
- Hardware validation (requires real backplane and timing instrumentation)
- Replacing existing physical-CPU operation mode

## Current State (facts to keep in mind)
- There is a CPU emulator on ARM (`10.02_devices/2_src/cpu.cpp`) that already uses `qunibusadapter->cpu_DATA_transfer()` for bus cycles.
- PRU arbitration has a CPU-as-arbitrator worker (`sm_arb_worker_cpu()` in `10.01_base/2_src/pru1_q/pru1_statemachine_arbitration.c`).
- `ARM2PRU_CPU_ENABLE` exists in the mailbox API but is effectively disabled in `pru1_main_qbus.c` (emulate_cpu path is TODO/commented).
- Interrupt delivery for emulated CPU is not fully wired (intr_slave state machine exists but is not enabled).
- `direct_memory` (PMI) path exists to bypass bus for main memory.

## High-level architecture changes
- PRU becomes the bus arbitrator (BG/NPG, BR/NPR) when emulated CPU is enabled.
- ARM CPU emulator gates interrupt arbitration at instruction boundaries (already scaffolded by `unibone_grant_interrupts()`), and receives vectors via PRU -> ARM events.
- Optional: external CPU lines are inhibited using `ARM2PRU_CPU_BUS_ACCESS` when emulation is active.

---

## Phase 0: Survey and guardrails
**Purpose:** establish scope, ensure we do not break existing physical-CPU mode.

Tasks:
- Inventory PRU code variants and ensure size limits are respected.
- Decide whether to reuse `PRUCODE_EMULATION` or introduce a dedicated `PRUCODE_EMUCPU`.
- Identify all CPU-related mailbox requests and their current usage (`ARM2PRU_CPU_ENABLE`, `ARM2PRU_ARB_GRANT_INTR_REQUESTS`).
- Confirm where CPU emulation is started (app menu, config) and decide new UI/CLI hooks.

Deliverable:
- Short design note that lists: chosen PRU code path, required mailbox changes, and the new app entry point.

Success criteria:
- Clear plan to toggle CPU emulation without changing default behavior.

---

## Phase 1: PRU "CPU as Arbitrator" mode (QBUS first)
**Purpose:** make PRU act as the bus arbitrator and interrupt fielding processor.

Files to modify:
- `10.01_base/2_src/pru1_q/pru1_main_qbus.c`
- `10.01_base/2_src/pru1_q/pru1_statemachine_arbitration.c`

Steps:
1) Implement `ARM2PRU_CPU_ENABLE` handling in `pru1_main_qbus.c`:
   - Toggle a local `emulate_cpu` flag.
   - Call `sm_arb_reset()` on mode change.
   - When emulated CPU is enabled, skip external GRANT forwarding logic.

2) In the main loop, select arbitration worker based on `emulate_cpu`:
   - If `emulate_cpu == true`, call `sm_arb_worker_cpu()`.
   - Otherwise, use existing device-client worker path.

3) Ensure PRU ignores external CPU GRANT inputs when emulation is enabled.

4) Add counters or DEBUG traces for:
   - NPR grants, BR grants, SACK timeouts
   - Arbitration decisions

Success criteria:
- With no physical CPU, PRU can grant DMA and BR requests to devices.
- With physical CPU (default), no behavior changes.

Notes:
- Repeat for UNIBUS (`10.01_base/2_src/pru1_u/pru1_main_unibus.c`) once QBUS is stable.

---

## Phase 2: Interrupt delivery to the emulated CPU
**Purpose:** deliver interrupt vectors to the ARM CPU emulator at the correct time.

Files to modify:
- `10.01_base/2_src/pru1_q/pru1_main_qbus.c`
- `10.01_base/2_src/pru1_q/pru1_statemachine_arbitration.c`
- `10.01_base/2_src/arm/qunibusadapter.cpp`
- `10.02_devices/2_src/cpu.cpp`

Decide strategy (prefer A):

A) **Synthesized IAK in PRU (recommended)**
- When `sm_arb_worker_cpu()` grants an interrupt, PRU directly emits the vector and signals ARM via `intr_slave` event.
- This avoids needing an external DIN/IAKO handshake that does not exist without a physical CPU.

Implementation details:
- In `state_arbitration_intr_vector`, add a branch for `emulate_cpu == true`:
  - Drive vector on DAL lines.
  - Signal `mailbox.events.intr_slave` with vector.
  - Clear BR request internally and return to grant-check.
- Ensure device INTR request completion is still handled (`intr_master` for device request completion), or split the two signals so devices still see completion events.

B) **Full CPU IAK emulation (optional, more work)**
- Emulated CPU asserts DIN/IAKO sequences via PRU commands.
- PRU responds as a normal bus slave.
- This is more accurate but requires new mailbox commands and state transitions.

Success criteria:
- Emulated CPU receives and services interrupts.
- Device interrupt requests complete cleanly with no deadlocks.

---

## Phase 3: CPU bus cycles and memory model
**Purpose:** ensure CPU emulator can run in either bus-memory or local-memory mode.

Tasks:
- Verify `direct_memory` path (PMI) works with IO page accesses via bus.
- For bus-memory mode, ensure CPU cycles use `cpu_DATA_transfer()` and arbitration is respected.
- Add a clear config knob (CLI/param) for "bus memory" vs "local memory".

Files:
- `10.02_devices/2_src/cpu.cpp`
- `10.01_base/2_src/arm/qunibusadapter.cpp`
- `10.03_app_demo/` menu / config files

Success criteria:
- Local-memory mode runs noticeably faster than bus-memory mode.
- Bus-memory mode works without deadlocks.

---

## Phase 4: Boot sequencing with no physical CPU
**Purpose:** define a stable boot sequence for CPU emulation.

Steps:
1) In app menu, add "Start emulated CPU" entry.
2) When selected:
   - Inhibit external CPU bus activity (`set_cpu_bus_activity(false)` on QBUS).
   - Set arbitrator mode to CPU emulation (`ARM2PRU_CPU_ENABLE` + `set_arbitrator_active(false)` as needed).
   - Assert then negate INIT/DCLO/ACLO/HALT in a realistic order (`qunibus->init()` / `powercycle()` as appropriate).
   - Load ROM or bootstrap image into DDR memory.
   - Start CPU emulator with reset PC/PSW.

Files:
- `10.03_app_demo/2_src/menu_*` (new menu item)
- `10.02_devices/2_src/cpu.cpp`
- `10.01_base/2_src/arm/qunibus.cpp`

Success criteria:
- System runs from ROM or boot device without a physical CPU.

---

## Phase 5: DMA/INTR interaction and deadlock hardening
**Purpose:** avoid bus stalls from device DMA and register callbacks.

Tasks:
- Review devices that hold `on_after_register_access_mutex` during long operations (RL11, RK11, RF11, RX211, UDA).
- Refactor to avoid blocking register callbacks while DMA is active.
- Add PRU-side timeout for arbitration wait (SYNC/RPLY drop or SACK grant) to avoid infinite hangs.

Files:
- `10.01_base/2_src/pru1_q/pru1_statemachine_arbitration.c`
- `10.02_devices/2_src/*`

Success criteria:
- No hangs under DMA + interrupt load in CPU emulation mode.

---

## Phase 6: Instrumentation and bring-up tests
**Purpose:** get visibility into arbitration, interrupts, and bus usage.

Add:
- PRU counters: grants, timeouts, interrupts delivered.
- ARM logs: CPU interrupt vectors, DMA start/end, arbitration transitions.
- Optional GPIO debug pulses (PRU pins) for scope/LA capture.

Suggested tests:
1) Standalone memory read/write loop (local DDR).
2) IO page access smoke test (read/write to a simple register device).
3) Device interrupt loopback test (DL11 / KW11).
4) DMA burst test with a simple device (RL/RK) after interrupts are stable.
5) Boot small diagnostic or monitor from ROM.

---

## Phase 7: Performance characterization
**Purpose:** understand expected speed vs real PDP-11.

Measure:
- DATI/DATO cycle rate in bus-memory mode.
- Instruction rate in local-memory mode.
- Interrupt latency under DMA load.

Document:
- Typical cycle times and where Linux scheduling impacts appear.

---

## Implementation checklist (per file)
- `10.01_base/2_src/pru1_q/pru1_main_qbus.c`
  - Implement `ARM2PRU_CPU_ENABLE` to toggle emulate_cpu.
  - Use `sm_arb_worker_cpu()` when emulate_cpu is true.
  - Skip external GRANT forwarding when emulated.

- `10.01_base/2_src/pru1_q/pru1_statemachine_arbitration.c`
  - Add emulated CPU interrupt delivery path.
  - Add timeout handling for grant waits.

- `10.01_base/2_src/arm/qunibusadapter.cpp`
  - Ensure `registered_cpu->on_interrupt()` is called for emulated CPU vectors.

- `10.02_devices/2_src/cpu.cpp`
  - Ensure `unibone_grant_interrupts()` is invoked at instruction boundaries.
  - Add config to choose local vs bus memory.

- `10.03_app_demo/2_src/menu_devices.cpp` (or new menu)
  - Add "Start emulated CPU" entry and boot sequence.

---

## Risks / unknowns
- Interrupt semantics without a physical CPU may require careful protocol handling.
- PRU code size limits may force split variants or removal of debug logic.
- Device callbacks that block while holding SSYN/RPLY can still deadlock; these need audit.

---

## Exit criteria
- Emulated CPU boots a simple monitor with no physical CPU present.
- Device interrupts and DMA are stable under load.
- No regressions in physical-CPU mode.

