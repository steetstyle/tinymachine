//! x86_64 Interrupt Controller constants — IOAPIC, LAPIC, PIC, MSI.
//!
//! These constants describe the x86 APIC architecture as used by KVM's
//! in-kernel irqchip (KVM_CREATE_IRQCHIP). On aarch64/riscv64, the
//! interrupt controller would be GIC (generic interrupt controller)
//! or CLINT/PLIC respectively.

// ─── IOAPIC ────────────────────────────────────────────────────────

/// IOAPIC MMIO base address (guest physical)
pub const IOAPIC_BASE: u64 = 0xFEC00000;

/// LAPIC MMIO base address (guest physical)
pub const LAPIC_BASE: u64 = 0xFEE00000;

/// Number of IOAPIC pins (GSIs 0-23)
pub const IOAPIC_NUM_PINS: u32 = 24;

/// IOAPIC default GSI base for MSI routing
pub const MSI_GSI_BASE: u32 = 24;

/// MSI address (x86 standard: 0xFEE00000)
pub const MSI_ADDRESS_LO: u32 = 0xFEE00000;

/// MSI address high (0 for 32-bit)
pub const MSI_ADDRESS_HI: u32 = 0;

/// MSI data base (starting vector offset for MSI messages)
pub const MSI_DATA_BASE: u32 = 0x40;

// ─── PIC (8259) ────────────────────────────────────────────────────

/// IRQ vector offset for PIC (typical Linux: 0x20 = 32)
pub const PIC_VECTOR_OFFSET: u32 = 0x20;

/// Timer IRQ (PIT channel 0)
pub const IRQ_TIMER: u32 = 0x00;

/// IRQ number for keyboard (PIC pin 1)
pub const IRQ_KEYBOARD: u32 = 0x01;

/// IRQ number for cascade (PIC slave attached to master pin 2)
pub const IRQ_CASCADE: u32 = 0x02;

/// IRQ number for COM1 (PIC pin 4)
pub const IRQ_COM1: u32 = 0x04;

// ─── VFIO / INTx ──────────────────────────────────────────────────

/// GSI for INTx interrupt routing for VFIO GPU (PIRQC → IOAPIC pin 18)
pub const VFIO_INTX_GSI: u32 = 18;

/// VFIO GPU at guest BDF 00:02.0 (device 2, function 0)
pub const VFIO_GPU_DEVFN: u32 = 0x10;
