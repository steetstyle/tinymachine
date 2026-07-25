# Synthetic PCIe Root Port for Direct KVM — Research Document

> **Status:** Final  
> **Author:** kvm-engineer  
> **Date:** 2026-07-23  
> **Context:** TinyMachine direct KVM VMs (no QEMU) need VFIO GPU passthrough where nvidia.ko expects a proper PCIe root port parent.

---

## Table of Contents

1. [The Problem: Why nvidia.ko Needs a Root Port](#1-the-problem-why-nvidiako-needs-a-root-port)
2. [Current PCI Topology in TinyMachine](#2-current-pci-topology-in-tinyos)
3. [QEMU Q35 Reference Topology](#3-qemu-q35-reference-topology)
4. [PCIe Root Port Config Space — Complete Reference](#4-pcie-root-port-config-space--complete-reference)
   - 4.1. Type 1 Header (offsets 0x00–0x3F)
   - 4.2. Power Management Capability (cap ID 0x01)
   - 4.3. PCI Express Capability (cap ID 0x10)
   - 4.4. MSI Capability (cap ID 0x05)
   - 4.5. Subsystem Vendor ID Capability (cap ID 0x0D)
   - 4.6. Extended Capabilities (AER, ACS)
   - 4.7. Complete Byte-Level Template
5. [nvidia.ko Probe Analysis](#5-nvidiako-probe-analysis)
   - 5.1. Probe Sequence
   - 5.2. Root Port Traversal
   - 5.3. Critical Config Reads
   - 5.4. Expected vs Actual in Current TinyMachine
6. [Implementation Approaches](#6-implementation-approaches)
   - 6.1. Approach A: Extended PCI Config Emulation (Recommended)
   - 6.2. Approach B: VFIO Group with Two Devices
   - 6.3. Approach C: Linux Kernel pci-bridge-emul via Kernel Module
   - 6.4. Approach D: Libvfio-user with Synthetic Device
7. [ACPI Requirements](#7-acpi-requirements)
8. [Implementation Effort Estimate](#8-implementation-effort-estimate)
9. [Recommended Approach — Detailed Plan](#9-recommended-approach--detailed-plan)
10. [References](#10-references)

---

## 1. The Problem: Why nvidia.ko Needs a Root Port

When `nvidia.ko` probes a VFIO-passthrough GPU in the guest, it performs several PCI hierarchy traversals that **require a valid parent bridge chain** ending at a PCIe Root Port.

### Critical Traversal Paths

| # | Code Path | Function | What It Reads | If Missing |
|---|-----------|----------|---------------|------------|
| 1 | `nv_pci_probe()` → `pci_find_host_bridge()` | `nv-pci.c` | Host bridge from root bus | Nouveau-style fallback, no RM init |
| 2 | `pci_find_pcie_root_port()` | Linux PCI core | Traverses `pdev->bus->parent` chain | Returns NULL → skips PCIe init |
| 3 | `objClFindRootPort()` | `chipset_pcie.c` | Walks PCI tree from GPU up to root port | rootPort.addr.valid=false → LTR/atomic/rate detection skipped |
| 4 | `clPcieReadPortConfigReg()` | `chipset_pcie.c` | Reads DevCap2, DevCtrl2 via root port | LTR support detection fails |
| 5 | `getPCIELinkRateMBps()` | RMAPI | Reads PCIe link capabilities | "Unknown PCIe speed" error → CUDA fails |
| 6 | `objClInitGpuPortData()` | `chipset_pcie.c` | Initializes upstream/downstream port data | "Unable to get PCI port handles" → init fails |

### Root Cause

In the current TinyMachine setup, the GPU sits at `00:02.0` directly on bus 0 with no parent bridge:

```
00:00.0  Host bridge (PIIX3 emulated)
00:01.0  ISA bridge (PIIX3 emulated)  
00:02.0  VFIO GPU ← NO parent PCIe bridge!
```

When nvidia.ko calls `pci_find_pcie_root_port(gpu_pdev)`, it walks:
```
gpu_pdev->bus = bus 0
bus 0->parent = NULL (bus 0 is the root bus, has no parent)
```

No parent bridge → `pci_find_pcie_root_port()` returns NULL → nvidia.ko skips all RM PCIe init → CUDA fails with "Unknown PCIe speed."

### The Known Fix

From NVIDIA developer forums and Proxmox documentation: **GPU must be behind a `pcie-root-port` device**. QEMU command line:
```
-device pcie-root-port,id=pci.1,bus=pcie.0
-device vfio-pci,host=$GPU,bus=pci.1
```

Without this:
```
NVRM: getPCIELinkRateMBps: Unknown PCIe speed
NVRM: GPU has fallen off the bus.
CUDA initialization fails.
```

---

## 2. Current PCI Topology in TinyMachine

### What boot.rs Does

The `pci_config_read()` function in `boot.rs` (line 695) emulates exactly three devices:

```rust
fn pci_config_read(bus, dev, func, reg, port, size, vfio) -> u32 {
    if bus != 0 { return 0xFFFFFFFF; }
    let (vendor, device, class, hdr_type, sub_id) = match (dev, func) {
        (0, 0) => (0x8086, 0x7000, 0x060000, 0x00, 0x0000),  // PIIX3 host bridge
        (1, 0) => (0x8086, 0x7010, 0x060100, 0x80, 0x0000),  // PIIX3 ISA bridge
        _ => return 0xFFFFFFFF,  // Everything else is invalid!
    };
    // ... return config register value
}
```

**Key limitations:**
1. Only two emulated devices exist: dev=0 (host bridge) and dev=1 (ISA bridge)
2. The ISA bridge uses `hdr_type = 0x80` (which is type 0 with multi-function) — NOT a Type 1 (bridge) header
3. No PCIe capabilities are exposed on any device
4. No bus numbers are tracked — the PIIX3 didn't do PCIe bus translation
5. `dev == 2` returns 0xFFFFFFFF for everything EXCEPT when a VFIO device is attached
6. When VFIO is attached, `dev == 2, func == 0` is forwarded to VFIO config space, but that exposes the GPU with **no parent bridge**

### Current Topology Diagram

```
Bus 0:
  [00:00.0] PIIX3 Host Bridge  — Type 0 header (hdr=0x00), class=0x060000
  [00:01.0] PIIX3 ISA Bridge   — Type 0 header (hdr=0x80), class=0x060100  
  [00:02.0] VFIO GPU           — Type 0 endpoint (hdr=0x00), GPU's real config
  
  Note: No Type 1 (bridge) device exists on bus 0.
  Note: No bus 1 exists — the ISA bridge doesn't create a secondary bus.
```

### What Needs to Change

The desired topology:

```
Bus 0 (Root Complex / primary):
  [00:00.0] Host Bridge           — Type 0, class=0x060000 (keep)
  [00:01.0] PCIe Root Port        — Type 1 BRIDGE, class=0x060400
    Primary bus = 0, Secondary bus = 1, Subordinate bus = 1

Bus 1 (secondary / downstream):
  [01:00.0] VFIO GPU              — Type 0 endpoint (no change to GPU config)
```

---

## 3. QEMU Q35 Reference Topology

### Q35 Chipset Layout (from QEMU source)

QEMU's `hw/pci-host/q35.c` creates:

```
Bus 0 (pcie.0 — Root Complex internal bus):
  [00:00.0] DRAM Controller (Intel 0x8086:0x29c0) — Type 0, class=0x060000
  [00:01.0] PCIe Root Port       — Type 1 bridge, class=0x060400
  [00:01.1] PCIe Root Port       — Type 1 bridge
  ...
  [00:1a.0] USB controller
  [00:1b.0] HD Audio
  [00:1c.0] PCIe Root Port       — Type 1 bridge (chipset-integrated)
  ...
  [00:1f.0] LPC bridge (ISA bridge)
  [00:1f.2] SATA controller
  [00:1f.3] SMBus

Bus 1 (behind Root Port at 00:01.0):
  [01:00.0] VFIO GPU              — Type 0 endpoint
```

### QEMU `gen_pcie_root_port.c` Implementation

From QEMU source (`hw/pci-bridge/gen_pcie_root_port.c`):

```c
static void gen_rp_dev_class_init(ObjectClass *klass, const void *data) {
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_CLASS(klass);

    k->vendor_id = PCI_VENDOR_ID_REDHAT;    // 0x1b36
    k->device_id = PCI_DEVICE_ID_REDHAT_PCIE_RP; // 0x000c
    dc->desc = "PCI Express Root Port";

    rpc->aer_offset = GEN_PCIE_ROOT_PORT_AER_OFFSET;  // 0x100
    rpc->acs_offset = GEN_PCIE_ROOT_PORT_ACS_OFFSET;  // 0x160
}
```

The `rp_realize()` function (in `hw/pci-bridge/pcie_root_port.c`) initializes:

1. **PCI bridge** — Sets up Type 1 header, bus numbers, windows
2. **Subsystem Vendor ID capability** at `ssvid_offset` (cap ID 0x0D)
3. **PCI Express capability** at `exp_offset` with `PCI_EXP_TYPE_ROOT_PORT`
4. **ARI forwarding** — `pcie_cap_arifwd_init()`
5. **Device error reporting** — `pcie_cap_deverr_init()`
6. **Slot capability** — `pcie_cap_slot_init()` (for hotplug)
7. **Root capability** — `pcie_cap_root_init()` (Root Control/Status)
8. **AER capability** at offset 0x100 — `pcie_aer_init()`
9. **ACS capability** at offset 0x160

### QEMU PCI IDs

From `docs/specs/pci-ids.html`:

| Vendor | Device | Description |
|--------|--------|-------------|
| 0x1b36 | 0x0008 | QEMU PCIe Host bridge |
| 0x1b36 | 0x000c | **PCIe Root Port** (`-device pcie-root-port`) |
| 0x1b36 | 0x000e | PCIe-to-PCI bridge |
| 0x8086 | 0x29c0 | Q35 DRAM Controller (host bridge) |
| 0x8086 | 0x2910 | Q35 LPC Bridge (ISA) |
| 0x1af4 | 0x1000 | Virtio-net (legacy Qumranet) |

---

## 4. PCIe Root Port Config Space — Complete Reference

### 4.1. Type 1 Header (offsets 0x00–0x3F)

The Type 1 header differs from Type 0 (endpoint) in several key fields. Here is the full layout:

| Offset | 31:24 | 23:16 | 15:8 | 7:0 | Notes |
|--------|-------|-------|------|-----|-------|
| 0x00 | Device ID (16) | Vendor ID (16) | RO |
| 0x04 | Status (16) | Command (16) | RW |
| 0x08 | Class Code (24) | Revision ID (8) | Class=0x060400 for PCI-PCI bridge |
| 0x0C | BIST (8) | Header Type (8) | Latency Timer (8) | Cache Line Size (8) | **Header Type = 0x01** for bridge |
| 0x10 | BAR0 (32) | Optional — bridge's own MMIO (usually 0) |
| 0x14 | BAR1 (32) | Optional (usually 0) |
| 0x18 | Secondary Latency Timer (8) | Subordinate Bus # (8) | Secondary Bus # (8) | Primary Bus # (8) | **Bus numbers — critical** |
| 0x1C | Secondary Status (16) | I/O Limit (8) | I/O Base (8) |
| 0x20 | Memory Limit (16) | Memory Base (16) | Non-prefetchable MMIO window |
| 0x24 | Prefetchable Memory Limit (16) | Prefetchable Memory Base (16) |
| 0x28 | Prefetchable Base Upper 32 (32) |
| 0x2C | Prefetchable Limit Upper 32 (32) |
| 0x30 | I/O Limit Upper 16 (16) | I/O Base Upper 16 (16) |
| 0x34 | Reserved (24) | **Capabilities Pointer** (8) |
| 0x38 | Expansion ROM Base Address (32) | Usually 0 for root port |
| 0x3C | Bridge Control (16) | Interrupt Pin (8) | Interrupt Line (8) |

#### Critical Register Values for Root Port

| Register | Offset | Value | Meaning |
|----------|--------|-------|---------|
| Vendor ID | 0x00 | 0x1B36 | Red Hat (QEMU convention) |
| Device ID | 0x02 | 0x000C | QEMU PCIe Root Port |
| Command | 0x04 | 0x0007 | I/O+Memory+Bus Master |
| Status | 0x06 | 0x0010 | Capabilities list present |
| Revision ID | 0x08 | 0x00 | Rev 0 |
| Class Code | 0x09 | 0x060400 | PCI-to-PCI bridge |
| Cache Line Size | 0x0C | 0x10 | 64-byte cache line |
| Header Type | 0x0E | **0x01** | **Type 1 = bridge** (THIS IS CRITICAL) |
| BIST | 0x0F | 0x00 | No built-in self test |
| Primary Bus # | 0x18[7:0] | 0x00 | Bus 0 (root complex bus) |
| Secondary Bus # | 0x18[15:8] | 0x01 | Bus 1 (downstream bus where GPU sits) |
| Subordinate Bus # | 0x18[23:16] | 0x01 | Farthest downstream bus |
| I/O Base | 0x1C[7:0] | 0xF0 | No I/O forwarding |
| I/O Limit | 0x1C[15:8] | 0x00 | No I/O forwarding |
| Secondary Status | 0x1E | 0x0000 | No errors |
| Memory Base | 0x20[15:0] | 0x0000 | Forward all non-prefetchable MMIO (base=0) |
| Memory Limit | 0x20[31:16] | 0xFFFF | Forward all non-prefetchable MMIO (limit=max) |
| Prefetchable Base | 0x24[15:0] | 0x0001 | Forward 64-bit prefetchable (above 4GB) |
| Prefetchable Limit | 0x24[31:16] | 0x0001 | Actually for 32-bit, set to 0 if using 64-bit |
| Prefetchable Base Upper | 0x28 | 0x00000000 | Upper 32 bits of 64-bit base |
| Prefetchable Limit Upper | 0x2C | 0x00000001 | Upper 32 bits (e.g., limit at 4GB) |
| Capabilities Pointer | 0x34 | **0x40** | Points to first capability (PM at 0x40) |
| Interrupt Pin | 0x3D | 0x00 | Root port doesn't generate interrupts |
| Interrupt Line | 0x3C | 0x00 | Not used |
| Bridge Control | 0x3E | 0x0000 | No special bridge control |

### 4.2. Power Management Capability (cap ID 0x01)

Located at offset 0x40 (pointed to by Capabilities Pointer).

| Offset | Register | Value | Notes |
|--------|----------|-------|-------|
| 0x40 | Cap ID | 0x01 | PM capability |
| 0x41 | Next Cap Ptr | 0x48 | Points to MSI capability |
| 0x42 | PMC (Capabilities) | 0x0002 | Version 1, No PME/D{1,2}/DSI |
| 0x44 | PMCSR (Control/Status) | 0x0000 | D0 state |
| 0x46 | Bridge Extensions | 0x00 | Not used |
| 0x47 | Data | 0x00 | Not used |

### 4.3. PCI Express Capability (cap ID 0x10)

Located at offset 0x48 (next from PM).

| Offset | Register | Bits | Value | Notes |
|--------|----------|------|-------|-------|
| 0x48 | Cap ID | 7:0 | 0x10 | PCI Express capability |
| 0x49 | Next Cap Ptr | 15:8 | 0x00 | No more capabilities (or 0x60 for SSVID) |
| 0x4A | PCIE Cap Register | 31:16 | | |
| | - Cap version | 19:16 | 0x02 | PCIe v2 |
| | - Device/Port Type | 23:20 | **0x4** | **Root Port** (4 = PCI_EXP_TYPE_ROOT_PORT) |
| | - Slot implemented | 24 | 0x0 | No slot |
| | - IRQ number | 31:25 | 0x00 | Not used |
| 0x4C | Device Capabilities | 31:0 | 0x00008000 | 128-byte max payload, extended tags, L0s/L1 |
| 0x50 | Device Control | 15:0 | 0x0000 | All disabled |
| 0x52 | Device Status | 15:0 | 0x0010 | Transactions pending (TP) flag set |
| 0x54 | Link Capabilities | 31:0 | 0x0004EEC3 | Gen3, 16-lane, 128-byte L0s/L1 |
| 0x58 | Link Control | 15:0 | 0x0000 | Disabled ASPM |
| 0x5A | Link Status | 15:0 | 0x1141 | Gen3, 16-lane, negotiated |
| 0x5C | Slot Capabilities | 31:0 | 0x00000040 | Hot-plug capable (bit 6), no power controller |
| 0x60 | Slot Control | 15:0 | 0x0000 | No attention/power indicators |
| 0x62 | Slot Status | 15:0 | 0x0000 | Empty slot |
| 0x64 | Root Control | 15:0 | 0x0000 | No PME/system error forwarding |
| 0x66 | Root Capabilities | 15:0 | 0x0000 | CRS SW doesn't support |
| 0x68 | Root Status | 31:0 | 0x00000000 | No PME pending |
| 0x6C | Device Capabilities 2 | 31:0 | 0x001C0020 | LTR supported, TPH, OBFF |
| 0x70 | Device Control 2 | 15:0 | 0x0000 | All disabled |
| 0x72 | Device Status 2 | 15:0 | 0x0000 |
| 0x74 | Link Capabilities 2 | 31:0 | 0x0007CFC3 | Crosslink disabled, 16-lane, 16GT/s |
| 0x78 | Link Control 2 | 15:0 | 0x0003 | Target link speed = Gen3 (0x03) |
| 0x7A | Link Status 2 | 15:0 | 0x0003 | Current speed = Gen3 |
| 0x7C-0x7F | Reserved | | | Zero |

**Critical register for nvidia.ko: `Link Status`** (offset 0x5A). NVIDIA reads this to determine `getPCIELinkRateMBps()`. Without it, CUDA fails.

### 4.4. MSI Capability (cap ID 0x05)

The root port does not need functional MSI (it doesn't generate its own interrupts), but QEMU typically includes it for compatibility.

| Offset | Value | Notes |
|--------|-------|-------|
| Cap ID 0x05 @ 0x48 (or wherever) | | Optional — skip if root port doesn't need MSI |

We can skip MSI for the root port. NVIDIA only reads MSI from the GPU's config space, not from the root port.

### 4.5. Subsystem Vendor ID Capability (cap ID 0x0D)

QEMU sets this up in `rp_realize()` via `pci_bridge_ssvid_init()`.

| Offset | Register | Value | Notes |
|--------|----------|-------|-------|
| SSVID Cap ID | 0x0D | Subsystem Vendor ID capability |
| Next Cap Ptr | 0x60 (or 0x00) | |
| Subsystem Vendor ID | 0x1AF4 | Qumranet (for backward compat) |
| Subsystem Device ID | 0x1100 | QEMU default |

### 4.6. Extended Capabilities (AER, ACS)

These live in PCIe extended config space (offsets 0x100+). QEMU sets up:

**AER (Advanced Error Reporting)** at offset 0x100:
- Cap ID: 0x0001 (extended)
- Version: 1
- Full AER block: 48 bytes (0x30)
- Root port AER registers: Root Error Command, Root Error Status, Error Source ID

**ACS (Access Control Services)** at offset 0x160:
- Cap ID: 0x000D (extended)
- Version: 1
- Full ACS block: 12 bytes (0x0C)
- ACS Control: Peer-to-Peer disabled
- ACS Capability: Source Validation, Translation Blocking, P2P Request Redirect

For minimum viability, **AER is required** (nvidia.ko reads Root Status via AER), but **ACS can be skipped**.

### 4.7. Complete Byte-Level Template

Here is the minimum viable PCI config space for a synthetic PCIe root port at BDF 00:01.0.

```
Offset  Value   Field
------  ------  ----------------------------------------
0x00-1  0x1B36  Vendor ID (Red Hat)
0x02-3  0x000C  Device ID (QEMU PCIe Root Port)
0x04-5  0x0007  Command (I/O + Memory + Bus Master)
0x06-7  0x0010  Status (Capabilities list present)
0x08    0x06    Revision: class[23:16] = bridge
0x09    0x04    Class[15:8] = PCI-to-PCI bridge  
0x0A    0x06    Class[7:0] = 0x06 (bridge device)
0x0B    0x00    Revision ID
0x0C    0x10    Cache Line Size (64 bytes)
0x0D    0x00    Latency Timer
0x0E    0x01    Header Type = TYPE 1 (BRIDGE) ← CRITICAL
0x0F    0x00    BIST
0x10-3  0x00000000  BAR0 (no bridge MMIO)
0x14-7  0x00000000  BAR1 (no bridge MMIO)
0x18    0x00    Primary Bus Number = 0
0x19    0x01    Secondary Bus Number = 1
0x1A    0x01    Subordinate Bus Number = 1
0x1B    0x00    Secondary Latency Timer
0x1C    0xF0    I/O Base (disabled)
0x1D    0x00    I/O Limit (disabled)
0x1E-1F 0x0000  Secondary Status
0x20-1  0x0000  Memory Base (forward all)
0x22-3  0xFFFF  Memory Limit (forward all)
0x24-5  0x0000  Prefetchable Base (32-bit, disabled)
0x26-7  0x0000  Prefetchable Limit (32-bit)
0x28-B  0x00000000  Prefetchable Base Upper 32
0x2C-F  0x00000001  Prefetchable Limit Upper 32 (at 4GB)
0x30-1  0x0000  I/O Base Upper 16
0x32-3  0x0000  I/O Limit Upper 16
0x34    0x40    Capabilities Pointer → offset 0x40
0x35-7  0x000000  Reserved
0x38-B  0x00000000  Expansion ROM (disabled)
0x3C    0x00    Interrupt Line
0x3D    0x00    Interrupt Pin (no INTx)
0x3E-3F 0x0000  Bridge Control

--- Capabilities ---

0x40    0x01    PM Capability ID
0x41    0x48    Next Cap Ptr → 0x48 (PCIe cap)
0x42-3  0x0002  PMC: Version 1, no PME
0x44-5  0x0000  PMCSR: D0
0x46    0x00    Bridge Extensions
0x47    0x00    Data

0x48    0x10    PCIe Capability ID
0x49    0x00    Next Cap Ptr → 0x00 (end of list, or SSVID)
0x4A-3  0x0042  PCIE Cap: v2, Type=Root Port(0x4), no slot
0x4C-F  0x00008000  DevCap: 128-byte MPS, ext tag
0x50-1  0x0000  DevCtl
0x52-3  0x0010  DevSta: Transactions Pending
0x54-7  0x0004EEC3  LinkCap: Gen3, 16-lane
0x58-9  0x0000  LinkCtl: ASPM disabled
0x5A-B  0x1141  LinkSta: Gen3 16-lane negotiated ← GPU reads this!
0x5C-F  0x00000040  SlotCap: Hot-plug capable
0x60-1  0x0000  SlotCtl
0x62-3  0x0000  SlotSta
0x64-5  0x0000  RootCtl
0x66-7  0x0000  RootCap
0x68-B  0x00000000  RootSta
0x6C-F  0x001C0020  DevCap2: LTR supported
0x70-1  0x0000  DevCtl2
0x72-3  0x0007CFC3  LinkCap2: 16GT/s, 16-lane
0x74-5  0x0000  LinkCtl2
0x76-7  0x0003  LinkSta2: Gen3, 16GT/s
0x78-B  0x0003  LinkCtl2: Target speed = Gen3

--- Extended Capabilities (optional but recommended) ---

0x100-3  0x00010001  AER Cap: ID=1, Version=1, Next=0x160
0x104-7  0x00000000  Uncorr Err Status
0x108-B  0x00000000  Uncorr Err Mask
0x10C-F  0x00000000  Uncorr Err Severity
0x110-3  0x00000000  Corr Err Status
0x114-7  0x00000000  Corr Err Mask
0x118-B  0x00000013  Adv Err Cap: ECRC Gen+Check
0x11C-F  0x00000000  Header Log 1
0x120-3  0x00000000  Header Log 2
0x124-7  0x00000000  Header Log 3
0x128-B  0x00000000  Header Log 4
0x12C-F  0x00000000  Root Err Cmd
0x130-3  0x00000000  Root Err Status
0x134-7  0x00000000  Err Src ID

0x160-3  0x000D0001  ACS Cap: ID=13, Version=1, Next=0
0x164-7  0x00000001  ACS Cap: Source Validation
0x168-B  0x00000000  ACS Ctl

Total: 0x16C bytes of config space (364 bytes)
```

**Minimum subset (can be reduced further):**
- Type 1 header: 0x00–0x3F (mandatory)
- PM cap at 0x40–0x47 (recommended for all PCIe devices)
- PCIe cap at 0x48–0x7B (CRITICAL — nvidia.ko reads Link Status + DevCap2 + Root Status)
- AER extended cap at 0x100–0x138 (recommended — nvidia.ko reads Root Err Status)
- **Total minimum: ~200 bytes**

---

## 5. nvidia.ko Probe Analysis

### 5.1. Probe Sequence

When `nvidia.ko` probes a GPU, the following sequence occurs (reconstructed from open-gpu-kernel-modules source):

```
1. nv_pci_probe(pdev)
   ├── pci_set_drvdata()
   ├── pci_enable_device()
   │     └── pci_enable_device_flags()
   │           └── pci_read_config_dword(PCI_COMMAND)
   │           └── pci_write_config_dword(PCI_COMMAND, cmd | PCI_COMMAND_MEMORY)
   ├── pci_request_regions(pdev)
   ├── pci_set_master(pdev)
   │
   ├── nv_get_pci_sysfs_config(nvl)  ← opens /sys/bus/pci/devices/.../config
   │
   ├── pci_find_pcie_root_port(pdev)  ← walks parent chain! ← HERE
   │     └── bus = pdev->bus
   │     └── while (bus->parent) bus = bus->parent  ← reaches root bus
   │     └── pci_get_domain_bus_and_slot(0, 0, 0x8) → 00:01.0 ← root port!
   │
   ├── objClInit()  ← in RM (proprietary/userspace)
   │     └── objClFindRootPort() → walks PCI tree
   │           └── clFindP2PBrdg() for upstream port
   │           └── clFindFHBAndGetChipsetInfoIndex() for host bridge
   │           └── objClGpuMapRootPort() → MMIO-maps root port ECAM
   │           └── clPcieReadPortConfigReg(rootPort, DevCap2) → LTR check
   │           └── clPcieReadPortConfigReg(rootPort, LinkCap) → Link speed
   │
   ├── objClInitPcieChipset()
   │     └── kbifInitLtr_HAL() ← uses root port LTR info
   │     └── kbifProbePcieReqAtomicCaps_HAL() ← root port atomic
   │     └── kbifProbePcieCplAtomicCaps_HAL() ← root port atomic
   │
   └── NV_STATUS = NV_OK / NV_ERR_OPERATING_SYSTEM
```

### 5.2. Root Port Traversal

From `chipset_pcie.c`, the root port finding logic:

```c
static void objClGpuMapRootPort(OBJGPU *pGpu, OBJCL *pCl) {
    // Start from GPU's upstream bus, walk bridges upward
    NvU8 bus = pGpu->gpuClData.upstreamPort.addr.bus;  // Bus 1 initially
    void *pHandleUp;
    NvU8 busUp, devUp, funcUp;
    NvU16 vendorIDUp, deviceIDUp;

    do {
        // Find the P2P bridge (parent bridge of current bus)
        pHandleUp = clFindP2PBrdg(pCl, domain, bus,
                                   &busUp, &devUp, &funcUp,
                                   &vendorIDUp, &deviceIDUp);
        if (!pHandleUp) break;

        // Read PCIe capability
        clSetPortPcieCapOffset(pCl, pHandleUp, &PCIECapPtr);
        portCaps = osPciReadDword(pHandleUp,
            CL_PCIE_CAP - CL_PCIE_BEGIN + PCIECapPtr);

        // Check if this is a Root Port
        bus = busUp;  // Move up to parent bus
    } while (!CL_IS_ROOT_PORT(portCaps));
    // CL_IS_ROOT_PORT checks PCI_EXP_TYPE == PCI_EXP_TYPE_ROOT_PORT (0x4)
}
```

This function walks up the PCI hierarchy bridge-by-bridge until it finds a port with `PCI_EXP_TYPE_ROOT_PORT`. **Without a root port, the loop exits immediately** with `pHandleUp == NULL` (clFindP2PBrdg fails because there's no bridge on bus 0 that connects to bus 1).

### 5.3. Critical Config Reads

| Register | Offset | Size | Read By | Example Value | Purpose |
|----------|--------|------|---------|---------------|---------|
| Vendor/Device ID | 0x00 | 4B | `clFindP2PBrdg()` | 0x000C1B36 | Identify bridge type |
| Class Code | 0x08 | 3B | `clFindP2PBrdg()` | 0x060400 | PCI bridge class |
| Header Type | 0x0E | 1B | `clFindP2PBrdg()` | 0x01 | Type 1 = bridge |
| **Primary Bus** | 0x18 | 1B | PCI enumeration | 0x00 | Upstream bus |
| **Secondary Bus** | 0x19 | 1B | PCI enumeration | 0x01 | Downstream bus |
| **Subordinate Bus** | 0x1A | 1B | PCI enumeration | 0x01 | Farthest bus downstream |
| **PCIe Cap ID** | 0x48 | 1B | `clSetPortPcieCapOffset()` | 0x10 | PCIe capability |
| **PCIe Cap Register** | 0x4A | 2B | `CL_IS_ROOT_PORT()` | 0x0042 | Type=Root Port(0x4) |
| Device Capabilities | 0x4C | 4B | `clPcieReadDevCap()` | 0x00008000 | Max payload size |
| Device Control | 0x50 | 2B | Device Initialization | 0x0000 | Current settings |
| Device Status | 0x52 | 2B | Error check | 0x0010 | Transaction pending |
| **Link Capabilities** | 0x54 | 4B | `getPCIELinkRateMBps()` | 0x0004EEC3 | Speed/width negotiated |
| **Link Control** | 0x58 | 2B | ASPM initialization | 0x0000 | ASPM settings |
| **Link Status** | 0x5A | 2B | **getPCIELinkRateMBps()** | 0x1141 | **Current negotiated speed/width** |
| Root Capabilities | 0x66 | 2B | Root Port init | 0x0000 | CRS SW visibility |
| Root Status | 0x68 | 4B | PME handling | 0x00000000 | PME status |
| **Device Capabilities 2** | 0x6C | 4B | LTR check | 0x001C0020 | **LTR support detection** |
| Device Control 2 | 0x70 | 2B | LTR enable | 0x0000 | LTR enabled? |
| Link Capabilities 2 | 0x74 | 4B | Speed detection | 0x0007CFC3 | 16GT/s supported |
| Link Status 2 | 0x7A | 2B | Speed negotiation | 0x0003 | Gen3 negotiated |
| AER Root Err Status | 0x130 | 4B | `clPcieReadAerRootStatus()` | 0x00000000 | Error checking |

**Bold = critical for nvidia.ko probe.**

### 5.4. Expected vs Actual in Current TinyMachine

| Check | nvidia.ko Expects | Current TinyMachine | Result |
|-------|--------------------|----------------|--------|
| Bus 0, Dev 1 exists | Type 1 bridge with PCIe cap | PIIX3 ISA (Type 0, no PCIe cap) | clFindP2PBrdg fails |
| Bus 1 exists | Secondary bus of root port | No bus 1 at all | GPU is on bus 0 |
| rootPort.addr.valid | true | false → skip all PCIe init | RM init incomplete |
| getPCIELinkRateMBps() | Valid link rate | "Unknown PCIe speed" | **CUDA fails** |
| DevCap2[LTR] | Present | N/A (no root port) | LTR detection skipped |
| Root Status | Present | N/A (no AER) | PME handling broken |

---

## 6. Implementation Approaches

### 6.1. Approach A: Extended PCI Config Emulation (Recommended)

**Concept:** Modify the PCI config space emulator in `boot.rs` to:
1. Replace the PIIX3 ISA bridge at dev=1 with a **PCIe Root Port** (Type 1 header)
2. Expose the VFIO GPU at BDF `01:00.0` (on the new secondary bus) instead of `00:02.0`
3. Keep PIIX3 host bridge at `00:00.0` (or optionally upgrade to Q35 DRAM Controller)

**Topology after:**
```
Bus 0:
  [00:00.0] Host Bridge         — Type 0, class=0x060000 (keep or upgrade)
  [00:01.0] PCIe Root Port      — Type 1, class=0x060400, primary=0, secondary=1

Bus 1:
  [01:00.0] VFIO GPU            — Type 0 endpoint (config forwarded to VFIO)
```

**Implementation changes:**

1. **PCI config space state** in `boot.rs`:
   - Add bus range tracking: `secondary_bus: u8` and `subordinate_bus: u8` per bridge
   - Configuration type routing: reads to bus 0 reach root port; reads to bus 1 reach GPU

2. **PCI config data port** handler:
   - Decode bus number from the `pci_config_addr` register
   - For `bus == secondary_bus_of_root_port`: forward to secondary devices
   - For `bus == 0`: check root port devices (0,1) + optionally keep host bridge at (0,0)

3. **Root Port state struct**:
   ```rust
   struct PcieRootPortState {
       primary_bus: u8,       // = 0
       secondary_bus: u8,     // = 1  
       subordinate_bus: u8,   // = 1
       config_regs: [u8; 256], // Our synthetic config space
   }
   ```

4. **VFIO device** stays on bus 1 (dev=0):
   - `devfn = 0x00` (device 0, function 0 on bus 1)
   - In `pci_config_read()`, when `bus == 1` and `dev == 0` and `func == 0`, forward to VFIO

5. **Config space generation**:
   - Pre-initialize the Type 1 header with values from Section 4.7
   - Allow the guest OS to write to Command, Bridge Control, and bus number registers (standard RW behavior)
   - Do NOT allow writes to capabilities area (frozen snapshot)

**Code changes needed:**

| File | Change | Estimate |
|------|--------|----------|
| `boot.rs` | Add `PcieRootPort` struct with 256-byte config array | 40 lines |
| `boot.rs` | Modify `pci_config_read()` for multi-bus routing | 30 lines |
| `boot.rs` | Modify `pci_config_write()` to allow bridge config writes | 20 lines |
| `boot.rs` | Initialize root port config in `run_until_ready()` | 30 lines |
| `boot.rs` | Change VFIO devfn from 0x10 to 0x00 and bus 0 to bus 1 | 10 lines |
| `fresh_boot.rs` | Update VFIO placement (BDF 01:00.0 instead of 00:02.0) | 5 lines |
| `arch/x86_64/port.rs` | No changes needed | 0 lines |

**Total: ~135 lines of new/modified code**

**Advantages:**
- No kernel modules needed
- No PCIem or other external dependencies
- Pure userspace change in TinyMachine
- Minimal risk of breaking other functionality
- Guest sees a consistent PCI topology

**Disadvantages:**
- Extended config space (≥0x100) must be emulated via MMIO or additional PIO mechanisms
- AER extended capability (0x100-0x138) needs ECAM (MMIO at 0xE0000000) or port I/O fallback
- Guest kernel must use `pci=conf1` (port I/O mechanism) — ECAM not available
- Config space beyond 256 bytes not accessible via 0xCF8/0xCFC

### 6.2. Approach B: VFIO Group with Two Devices

**Concept:** Bind TWO devices to VFIO on the host: an actual PCIe Root Port (from the host chipset) + the GPU, and pass both through to the guest as a VFIO group.

**Problems:**
1. Host PCIe root ports are NOT boundable to VFIO — they are core chipset devices
2. A PCIe root port exists at the chipset level; there's no simple BDF we can detach and reassign
3. IOMMU groups typically isolate leaf devices; a root port is part of the root complex IOMMU group (domain 0 in VT-d)

**Verdict:** NOT FEASIBLE for discrete GPU passthrough.

### 6.3. Approach C: Linux Kernel pci-bridge-emul via Kernel Module

**Concept:** Use the Linux kernel's existing `pci-bridge-emul.c` infrastructure to create a fake PCI bridge in the **host** kernel, then pass it through to the guest via VFIO.

**How it works:**
`pci-bridge-emul.c` is used by PCI controller drivers (e.g., Marvell, Aardvark) to create a software-emulated root port when the hardware doesn't have one. It:
1. Allocates a fake Type 1 config space
2. Populates it with vendor/device/class/PCIe cap values
3. Handles config read/write callbacks
4. Can support PCIe extended cap space if needed

**To use for TinyMachine:**
1. Write a small kernel module that creates a `pci_bridge_emul` instance
2. Register it as a VFIO/mdev device
3. Pass it to the guest as a second VFIO device

**Advantages:**
- No changes to TinyMachine userspace PCI emulation
- Full ECAM (extended config space) accessible to guest via MMIO
- Kernel handles all the PCI routing details
- AER, ACS extended capabilities available

**Disadvantages:**
- Requires a kernel module (adds deployment complexity)
- Module needs `pci-bridge-emul` which is typically `CONFIG_PCI_BRIDGE_EMUL=y`
- Need VFIO/mdev infrastructure
- ~500+ lines of kernel module C code
- Cannot be in Rust (kernel C module)
- Increases attack surface

**Verdict:** VIABLE but high complexity for the benefit. Best saved for later if Approach A proves insufficient.

### 6.4. Approach D: Libvfio-user with Synthetic Device

**Concept:** Use `libvfio-user` to create a userspace VFIO device that acts as a PCIe root port, separate from the GPU VFIO device. Connect both to the guest.

**Problems:**
1. `libvfio-user` requires client (QEMU typically) — it implements `vfio-user` protocol over Unix socket
2. TinyMachine doesn't use QEMU, so we'd need to implement a `vfio-user` client
3. Significant complexity for what amounts to emulating 200 bytes of config space
4. The synthetic root port has no actual hardware resources (BARs, MMIO, interrupts)

**Verdict:** OVERKILL for the root port alone. `libvfio-user` is better suited for complex device emulation where full VFIO semantics are needed.

---

## 7. ACPI Requirements

### Does nvidia.ko Need ACPI?

**Short answer: No, for basic configuration. Yes, for proper GPU initialization.**

From examining `nv-pci.c` and `chipset_pcie.c`:

**Required ACPI operations for nvidia.ko:**
1. **`acpi_evaluate_object()`** — Used for _DSM methods on the GPU (power management, PCIe reset)
2. **`pci_find_host_bridge()`** → needs ACPI host bridge device  
3. **NUMA information** — `pxm_to_node()` for coherent GPU memory

**What QEMU Q35 provides:**
- DSDT with PCI bus structure
- _OSC method (OS Control) for PCIe capabilities negotiation
- _DSM methods on PCIe root port for hotplug and error handling
- _PRT (PCI Routing Table) for legacy INTx routing

**What QEMU `-machine q35` actually generates:**
```
Scope (\_SB) {
    Device (PCI0) {  // PCIe Root Complex
        Name (_HID, EisaId ("PNP0A08"))  // PCIe bus
        Name (_CID, EisaId ("PNP0A03"))  // Also legacy PCI
        Name (_ADR, 0x00)
        
        Device (RP01) {  // Root Port at 00:01.0
            Name (_ADR, 0x00010000)  // (dev=1, func=0)
            Method (_OSC, ...) { ... }
        }
        
        Device (GFX0) {  // GPU at 01:00.0 (if known)
            Name (_ADR, 0x00000000)  // (dev=0, func=0 on bus 1)
            // This device's _ADR is relative to bus 1 (secondary)
        }
    }
}
```

**Minimal ACPI requirements for TinyMachine:**
- **Essential:** ACPI host bridge device (`PNP0A08`) for `pci_find_host_bridge()` to work
- **Optional but important:** _OSC method on the root port for PCIe capability negotiation 
- **Optional but recommended:** Minimal _PRT for IRQ routing
- **Can be omitted:** _DSM methods (nvidia.ko handles missing _DSM gracefully on VFIO)

**Implementation:**
- TinyMachine already generates a minimal ACPI DSDT table for the guest
- Need to add `Device (RP01)` entry with proper _ADR for synthetic root port
- ACPI tables are loaded via the initrd (as `/sys/firmware/acpi/tables/DSDT`) or via KVM's `KVM_SET_GSI_ROUTING`

**Fallback without ACPI:**
- The kernel can still enumerate PCI via `pci=conf1` (port 0xCF8/0xCFC)
- However, `pci_find_host_bridge()` requires an ACPI device node
- Without it, `to_pci_host_bridge()` returns NULL → nvidia.ko NUMA detection fails (non-fatal, GPU still works)
- `clFindFHBAndGetChipsetInfoIndex()` will fail → chipset info not available (non-fatal)

**Summary:** ACPI is NOT required for the root port to work. The PCI enumeration via `pci=conf1` bypasses ACPI. However, for `pci_find_host_bridge()` to succeed, a minimal ACPI host bridge table is recommended. We can add this via the existing initrd.

---

## 8. Implementation Effort Estimate

### Approach A (Recommended): Extended PCI Config Emulation

| Phase | Files | Lines | Complexity | Risk |
|-------|-------|-------|------------|------|
| 1. Root Port State | new `pci_root_port.rs` | 80 | Low | Low |
| 2. Config Space Template | embedded in struct initializer | 60 | Low | Low |
| 3. Multi-bus Routing | modify `pci_config_read/write` in `boot.rs` | 50 | Medium | Medium — must not break existing boot |
| 4. VFIO Bus Migration | change devfn in `fresh_boot.rs` | 10 | Low | Low |
| 5. Initialization | init root port at VM startup | 20 | Low | Low |
| 6. Testing | unit tests + integration test | 100 | Medium | Must test without GPU first |
| **Total** | | **~320** | | |

**Timeline:** 2-3 days including testing

**Risk factors:**
- Guest kernel may still fail to find GPU if PCI config mechanism #2 (ECAM) is required
- Some NVIDIA drivers may check "is this root port real?" via vendor/device ID matching
- The `pci=conf1` kernel parameter must be in cmdline to ensure port I/O mechanism

### Approach C (Kernel Module): 1-2 weeks — significantly more complex

### Approach D (libvfio-user): 2-4 weeks — overengineered for this purpose

---

## 9. Recommended Approach — Detailed Plan

### Approach A: Implementation Plan

#### Step 1: Create `tinyos-fork/src/pci_root_port.rs`

New file containing:

```rust
/// Synthetic PCIe Root Port at BDF 00:01.0
pub struct PcieRootPort {
    /// Primary bus number (bus upstream of this bridge)
    pub primary_bus: u8,
    /// Secondary bus number (bus directly downstream)
    pub secondary_bus: u8,
    /// Subordinate bus number (farthest bus downstream)
    pub subordinate_bus: u8,
    /// Raw PCI config space (256 bytes for Type 1 header + capabilities)
    pub config: [u8; 256],
}
```

Initialize with the byte template from Section 4.7.

#### Step 2: Modify `boot.rs`

Add multi-bus PCI routing. The key change in `pci_config_read()`:

```rust
fn pci_config_read(bus, dev, func, ...) {
    if bus == 0 {
        // Root complex devices
        match (dev, func) {
            (0, 0) => /* Host bridge (0x8086:0x7000 or Q35) */
            (1, 0) => /* Synthetic Root Port — forward to PcieRootPort.config */
            (0x1F, 0) => /* Optional: LPC bridge for legacy I/O */
            _ => 0xFFFFFFFF, // No other devices on bus 0
        }
    } else if bus == root_port.secondary_bus {
        // Downstream bus behind root port
        match (dev, func) {
            (0, 0) => /* VFIO GPU — forward to VFIO config fd */
            _ => 0xFFFFFFFF,
        }
    } else {
        0xFFFFFFFF, // Unknown bus
    }
}
```

#### Step 3: Modify VFIO device placement

In `fresh_boot.rs`, change:
```rust
// Old: GPU at device 2, function 0 on bus 0 (devfn = 0x10)
booted.vfio_pci = Some(VfioPciInfo {
    devfn: 0x10, // device 2, function 0 on bus 0
    ...
});

// New: GPU at device 0, function 0 on bus 1 (devfn = 0x00, but bus=1)
// The pci_config_read now routes by bus+devfn
booted.vfio_pci = Some(VfioPciInfo {
    devfn: 0x00, // device 0, function 0 on bus 1
    bus: 1,      // NEW FIELD: on secondary bus
    ...
});
```

#### Step 4: Verify with `lspci` inside guest

After these changes, the guest should see:
```
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma]
00:01.0 PCI bridge: Red Hat, Inc. PCIe Root Port (prog-if 00 [Normal decode])
    Bus: primary=00, secondary=01, subordinate=01, sec-latency=0
    I/O behind: disabled
    Memory behind: ff000000-ffffffff [size=16M]  
    Prefetchable memory behind: disabled
    Capabilities: [40] Power Management version 1
    Capabilities: [48] PCI Express Root Port (Slot), MSI 00
    Kernel driver in use: pcieport

01:00.0 VGA compatible controller: NVIDIA Corporation AD104 [GeForce RTX 4080 Mobile] (rev a1)
    (via VFIO passthrough)
```

#### Step 5: Verify nvidia.ko behavior

Check that:
1. `pci_find_pcie_root_port()` returns a valid pci_dev for the root port
2. `pci_find_host_bridge()` succeeds
3. `getPCIELinkRateMBps()` reads Link Status from root port and returns Gen3
4. `objClInitPcieChipset()` completes without error
5. CUDA applications initialize properly

#### Step 6: Handle extended config space

Since 0xCF8/0xCFC only accesses the first 256 bytes:
- AER extended capabilities (0x100+) are accessed via ECAM (MMIO at 0xE0000000)
- Without ECAM, we can't expose AER via standard port I/O
- **Option A:** Skip AER — nvidia.ko degrades gracefully without it
- **Option B:** Implement minimal ECAM handler via KVM MMIO exit
  - Map the ECAM region as a KVM memory slot
  - Handle ECAM reads/writes via KVM_EXIT_MMIO
  - Translate ECAM address to BDF and forward to our emulated config space

**Recommendation:** Start with Option A (skip AER). Only implement ECAM if nvidia.ko explicitly fails without it.

### Verification Criteria

| Test | Expected Result | Method |
|------|-----------------|--------|
| `lspci -t` inside guest | Proper tree with root port | Serial command |
| `lspci -vv -s 00:01.0` | PCIe Root Port capabilities | Serial command |
| `cat /sys/bus/pci/devices/0000:01:00.0/../..` | Parent is root port | Serial command |
| `nvidia-smi` | GPU detected, driver loaded | Full boot test |
| `cudaGetDeviceProperties()` | CUDA device available | Python in guest |
| Fork latency | No significant regression | Benchmarks |

---

## 10. References

### PCIe Specification
- PCIe Base Spec r6.0 §7.5 — Root Port config header
- PCI Local Bus Spec 3.0 §3.7.5 — Configuration Mechanism #1 (0xCF8/0xCFC)
- PCIe Base Spec r6.0 §7.5.3 — PCI Express Capability structure

### QEMU Source
- `hw/pci-bridge/pcie_root_port.c` — Root port base class
- `hw/pci-bridge/gen_pcie_root_port.c` — Concrete PCIe Root Port device
- `hw/pci-host/q35.c` — Q35 chipset host bridge implementation
- `docs/specs/pci-ids.html` — QEMU PCI vendor/device ID registry
- `include/hw/pci/pci.h` — PCI constants (vendor IDs, class codes)

### Linux Kernel
- `drivers/pci/pci-bridge-emul.c` — Software PCI bridge emulation framework
- `drivers/pci/search.c` — `pci_find_pcie_root_port()` and `pci_get_domain_bus_and_slot()`
- `drivers/pci/pci.c` — `pci_find_host_bridge()`, `pci_enable_device()`
- `include/linux/pci.h` — PCI_EXP_TYPE_ROOT_PORT (0x4) and other constants

### NVIDIA Open GPU Kernel Modules
- `kernel-open/nvidia/nv-pci.c` — PCI probe/resume, `pci_find_pcie_root_port()`, BAR init
- `src/nvidia/src/kernel/platform/chipset/chipset_pcie.c` — Root port detection, LTR, atomic, link rate
- `kernel-open/nvidia/os-pci.c` — PCI handle management, `os_pci_init_handle()`
- `kernel-open/nvidia/nv-pci.h` — Data structures, `nv_linux_state_t`

### Community References
- [NVIDIA Developer Forum: Pass-through GPU-CC with pcie-root-port](https://forums.developer.nvidia.com/t/pass-through-gpu-cc-with-pcie-root-port/309936)
- [Proxmox list: VFIO with pcie-root-port requirement](https://lists.proxmox.com/pipermail/pve-devel/2024-August/065050.html)
- [Blackwell behind PLX bridge - root port issue](https://forums.developer.nvidia.com/t/nvrm-gpu1-plx-pex8747-getbar0-device-has-no-bar0-blackwell-behind-pcie-bridge/376024)
- [Unix SE: VFIO-pci giving EINVAL on probe (bridge complications)](https://unix.stackexchange.com/questions/265541/pci-passthrough-kvm-with-vfio-pci-giving-einval-on-pci-probe)

### TinyMachine Codebase
- `tinyos-fork/src/boot.rs` — Current PCI emulation (PIIX3 only)
- `tinyos-fork/src/fresh_boot.rs` — VFIO GPU at BDF 00:02.0
- `tinyos-fork/src/vfio.rs` — VFIO device operations
- `tinyos-fork/src/kvm.rs` — KVM ioctl wrappers
- `tinyos-fork/src/qemu_backend.rs` — QEMU reference with Q35 chipset
