//! x86_64 Guest Memory Layout — physical address constants for TinyMachine KVM guests.
//!
//! All addresses are guest-physical. The layout is:
//!
//! ```text
//! 0x000000 - 0x001FFF  Reserved (IVT, BDA, EBDA)
//! 0x002000 - 0x007FFF  PVH start_info + cmdline
//! 0x010000 - 0x01FFFF  boot_params + E820 table
//! 0x060000 - 0x07FFFF  GDT (3 descriptors × 8 bytes)
//! 0x070000 - 0x07BFFF  Page tables (PML4 + PDP + PD)
//! 0x07CFFF             Entropy divergence control byte
//! 0x07D000 - 0x07DFFF  Entropy buffer (host CSPRNG → guest CRNG)
//! 0x07E000 - 0x07EFFF  Command buffer (CMD_BUF, host → guest)
//! 0x07F000 - 0x07FFFA  Output buffer (OUT_BUF, guest → host)
//! 0x07FFFA - 0x07FFFF  "READY" signal
//! 0x080000             Stack top (grows down)
//! 0x100000             Kernel load address (conventional 1MB mark)
//! ```

/// Guest physical address of the GDT (24 bytes: null + code + data)
pub const GDT_ADDR: u64 = 0x60000;

/// Guest physical address of the PML4 page table (4KB aligned)
pub const PML4_ADDR: u64 = 0x70000;

/// Guest physical address of the PDP table (4KB aligned)
pub const PDP_ADDR: u64 = 0x71000;

/// Guest physical address of the PD table (4KB aligned, if using 2MB pages)
pub const PD_ADDR: u64 = 0x72000;

/// Initial stack pointer (grows down from 0x80000)
pub const STACK_TOP: u64 = 0x80000;

/// Default guest RAM size (64 MB)
pub const DEFAULT_MEMORY_SIZE: u64 = 64 * 1024 * 1024;

/// Default kernel load address (1 MB — conventional for 64-bit x86)
pub const DEFAULT_LOAD_ADDR: u64 = 0x100000;

/// Guest physical address of the standard Linux boot_params structure.
/// startup_64 expects RSI → boot_params. Must be in low memory (< 640KB).
pub const BOOT_PARAMS_ADDR: u64 = 0x10000;

/// Size of the boot_params structure (Linux expects setup header + padding)
pub const BOOT_PARAMS_SIZE: u64 = 4096;

/// Max physical address for initrd (standard Linux value: < 4GB)
pub const INITRD_ADDR_MAX: u32 = 0x37FF_FFFF;

/// PVH boot protocol: guest physical address of hvm_start_info
pub const PVH_START_INFO_ADDR: u64 = 0x2000;

/// PVH boot protocol magic constant
pub const HVM_START_MAGIC: u32 = 0x336ec578;

/// Size of struct hvm_start_info (6 fields = 32 bytes)
pub const HVM_START_INFO_SIZE: u64 = 32;

/// Guest physical address of hvm_modlist_entry (right after start_info)
pub const PVH_MODLIST_ADDR: u64 = PVH_START_INFO_ADDR + HVM_START_INFO_SIZE;

/// Guest physical address of kernel command line string
pub const PVH_CMDLINE_ADDR: u64 = 0x2080;

/// Host→Guest command buffer (in first 1MB, accessible via /dev/mem
/// even with CONFIG_STRICT_DEVMEM=y)
pub const CMD_BUF_PHYS: u64 = 0x7E000;

/// Host→Guest entropy buffer (in first 1MB).
/// Before each KVM_RUN, the host writes 64 bytes of host CSPRNG output here.
/// The guest init.c reads this and feeds it to /dev/random to ensure each
/// KVM fork has a unique CRNG state despite starting from an identical snapshot.
pub const ENTROPY_BUF_PHYS: u64 = 0x7D000;

/// Number of bytes of entropy injected into each forked VM.
pub const ENTROPY_SIZE: u64 = 64;

/// Control byte for per-fork entropy divergence (at 0x7CFFF).
/// The host writes this before each KVM_RUN to tell init.c whether to
/// diverge the kernel CRNG state across forks.
pub const ENTROPY_DIVERGENCE_CTRL_PHYS: u64 = 0x7CFFF;
pub const ENTROPY_DIVERGENCE_ENABLED: u8 = 1;
pub const ENTROPY_DIVERGENCE_DISABLED: u8 = 0;

/// Guest→Host output buffer (in first 1MB)
pub const OUT_BUF_PHYS: u64 = 0x7F000;

/// Maximum command length
pub const BUF_MAX: u64 = 4096;

/// Offset from OUT_BUF_PHYS where "READY" signal is written
pub const READY_SIGNAL_OFFSET: u64 = 4090;

/// KVM_SET_TSS_ADDR value — conventional near top of 32-bit space
pub const TSS_ADDR: u64 = 0xffffd000;

/// Guest physical address of the virtio-net PCI MMIO BAR.
/// Placed in the PCI MMIO hole (above 64MB RAM, below 4GB).
pub const VIRTIO_MMIO_ADDR: u64 = 0xFEBF0000;

/// Size of the virtio-net PCI MMIO BAR (4KB — standard page)
pub const VIRTIO_MMIO_SIZE: u64 = 0x1000;

/// Reserved MMIO regions that must not overlap with guest memory.
/// - 0xFEC00000 — IOAPIC (1 page)
/// - 0xFEE00000 — LAPIC (1 page)
pub const RESERVED_MMIO_REGIONS: &[(u64, u64)] = &[
    (0xFEC00000, 0x1000), // IOAPIC
    (0xFEE00000, 0x1000), // LAPIC
];

/// E820 table offset within boot_params structure
pub const E820_TABLE_OFFSET: u64 = 0x2D0;
/// Size of each E820 entry
pub const E820_ENTRY_SIZE: u64 = 20;
pub const E820_TYPE_USABLE: u32 = 1;
pub const E820_TYPE_RESERVED: u32 = 2;

/// 2MB page size (for initrd alignment)
pub const PAGE_SIZE_2MB: u64 = 2 * 1024 * 1024;

/// Pseudorandom exit reason codes used internally (not KVM-defined)
pub const EXIT_REASON_RANGE_OVERFLOW: u32 = 0xBADC;
pub const EXIT_REASON_RANGE_OOB: u32 = 0xBADD;
pub const EXIT_REASON_TIMEOUT: u32 = 0xDEAD;

/// Default baud rate for serial console
pub const SERIAL_BAUD: u32 = 115200;

// ─── VBIOS POST addresses ─────────────────────────────────────────────
// These are used when booting with VFIO GPU passthrough. The VBIOS
// Option ROM is executed in real mode before the kernel boots to
// initialize the GPU (power up Falcon engines, start GFW firmware).
//
// Memory layout during VBIOS POST (Phase 1):
//   0x000000 - 0x0003FF  IVT (256 × 4-byte entries → iret at stub)
//   0x000400 - 0x0004FF  BDA (minimal equipment word)
//   0x008000 - 0x00801F  16-bit stub (iret + lcall VBIOS + hlt)
//   0x0C0000 - ...       VBIOS Option ROM image
//
// After VBIOS POST completes (HLT), Phase 2 re-initializes the VCPU
// in 64-bit long mode and boots the kernel normally.

/// Guest physical address where the VBIOS Option ROM is loaded.
/// Standard x86 VGA BIOS location: segment 0xC000, physical 0xC0000.
pub const VBIOS_ROM_ADDR: u64 = 0xC0000;

/// Segment selector value for VBIOS ROM (0xC0000 >> 4)
pub const VBIOS_ROM_SEG: u16 = 0xC000;

/// Guest physical address of the 16-bit VBIOS POST stub.
/// At 0x8000 (segment 0x0800), between PVH region (0x008000) and
/// the conventional boot_params area (0x010000).
pub const VBIOS_STUB_ADDR: u64 = 0x8000;

/// Segment selector value for the VBIOS stub (0x8000 >> 4 = 0x0800)
pub const VBIOS_STUB_SEG: u16 = 0x0800;

/// Guest physical address of the real-mode IVT (Interrupt Vector Table).
/// Always at 0x0000 in x86 real mode.
pub const VBIOS_IVT_ADDR: u64 = 0x0000;

/// Size of the IVT: 256 entries × 4 bytes each (far pointer: offset + segment)
pub const VBIOS_IVT_SIZE: u64 = 1024;

/// Guest physical address of the BDA (BIOS Data Area).
pub const VBIOS_BDA_ADDR: u64 = 0x0400;

/// Size of the BDA (256 bytes)
pub const VBIOS_BDA_SIZE: u64 = 256;

/// Minimum valid size for a VBIOS ROM image (512 bytes)
pub const MIN_VBIOS_SIZE: u64 = 512;

/// Maximum valid size for a VBIOS ROM image (4 MB)
pub const MAX_VBIOS_SIZE: u64 = 4 * 1024 * 1024;

/// Stack pointer for real-mode VBIOS POST execution (just below 1MB)
pub const VBIOS_REAL_STACK: u64 = 0xE000;

/// Offset within the VBIOS stub segment where the actual lcall+HLT code starts.
/// The first 16 bytes (0x00-0x0F) hold the IVT-handler iret; the lcall is at offset 0x10.
pub const VBIOS_STUB_ENTRY_OFFSET: u64 = 0x10;

/// VBIOS Option ROM entry point offset within the ROM segment.
/// The VBIOS init function starts at offset 0x0003 from the ROM base.
pub const VBIOS_ROM_ENTRY_OFFSET: u16 = 0x0003;

/// VBIOS real-mode register values for SeaBIOS __callrom() compatibility.
///
/// These are set by vbios_run_until_hlt() before the lcall to the Option ROM.
/// See SeaBIOS optionroms.c __callrom() for the register convention.

/// AX = PCI BDF for the GPU: bus=1, device=0, function=0 → (1<<8)|(0<<3)|0 = 0x0100.
pub const VBIOS_REG_AX: u64 = 0x0100;

/// BX = undefined per PCI BIOS specification.
pub const VBIOS_REG_BX: u64 = 0xFFFF;

/// DX = 0xFFFF = no PnP BIOS data (ES:DI ignored).
pub const VBIOS_REG_DX: u64 = 0xFFFF;

/// RFLAGS: bit 9 = IF (interrupts enabled), bit 1 = reserved (always 1).
pub const VBIOS_REG_RFLAGS: u64 = 0x202;
