//! x86_64 Snapshot Types — VM register state for save/restore.
//!
//! These types represent the CPU register state captured in a VM snapshot
//! and restored when forking. The structs mirror KVM's `kvm_regs`,
//! `kvm_sregs`, and `kvm_irqchip` structures but are serializable
//! (Serde) for JSON persistence.
//!
//! On aarch64, these types would be different (KVM_GET_ONE_REG with
//! different register IDs, GICv3 instead of PIC/IOAPIC, etc.).

use serde::{Deserialize, Serialize};

use crate::kvm;

// ─── XSAVE constants ──────────────────────────────────────────────

/// Size of the x86 XSAVE buffer in bytes (standard format, non-compacted).
pub const XSAVE_SIZE: usize = 4096;

/// Type alias for an x86 XSAVE buffer (FPU/SSE/AVX state).
pub type XsaveBuffer = [u8; XSAVE_SIZE];

// ─── CPU register state types ─────────────────────────────────────

/// CPU register state for x86_64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuState {
    /// General-purpose registers from KVM_GET_REGS
    pub regs: KvmRegs,
    /// Special registers from KVM_GET_SREGS
    pub sregs: KvmSregs,
    /// Model-Specific Registers critical for Linux x86_64
    /// (syscall entries, segment bases, TSC, etc.)
    /// Vector of (msr_index, value) pairs.
    #[serde(default)]
    pub msrs: Vec<(u32, u64)>,
    /// XCR registers (XCR0, etc.) — vector of (xcr_number, value) pairs.
    #[serde(default)]
    pub xcrs: Vec<(u32, u64)>,
}

/// KVM general-purpose registers (x86_64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// KVM special registers (segments, CRx, EFER, etc.) for x86_64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvmSregs {
    pub cs: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ss: Segment,
    pub tr: Segment,
    pub ldt: Segment,
    pub gdt: DescTable,
    pub idt: DescTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
}

/// x86 segment descriptor (as returned by KVM_GET_SREGS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub r#type: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
}

/// x86 descriptor table (GDT/IDT).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescTable {
    pub base: u64,
    pub limit: u16,
}

/// Three in-kernel irqchip states: PIC master, PIC slave, IOAPIC.
///
/// Each is a raw `kvm_irqchip` struct (512 bytes data portion) as
/// returned by KVM_GET_IRQCHIP. `None` for legacy snapshots or
/// on architectures without PIC/IOAPIC (e.g., aarch64 with GICv3).
#[derive(Debug, Clone)]
pub struct IrqChipState {
    pub master_pic: Option<Box<[u8; 512]>>,
    pub slave_pic: Option<Box<[u8; 512]>>,
    pub ioapic: Option<Box<[u8; 512]>>,
}

impl IrqChipState {
    /// Returns true if all three chips (master PIC, slave PIC, IOAPIC)
    /// have data present.
    pub fn all_present(&self) -> bool {
        self.master_pic.is_some() && self.slave_pic.is_some() && self.ioapic.is_some()
    }
}

// ─── Conversions between snapshot types and raw KVM types ──────────

impl From<kvm::KvmRegsRaw> for KvmRegs {
    fn from(raw: kvm::KvmRegsRaw) -> Self {
        Self {
            rax: raw.rax, rbx: raw.rbx, rcx: raw.rcx, rdx: raw.rdx,
            rsi: raw.rsi, rdi: raw.rdi, rsp: raw.rsp, rbp: raw.rbp,
            r8: raw.r8, r9: raw.r9, r10: raw.r10, r11: raw.r11,
            r12: raw.r12, r13: raw.r13, r14: raw.r14, r15: raw.r15,
            rip: raw.rip, rflags: raw.rflags,
        }
    }
}

impl From<KvmRegs> for kvm::KvmRegsRaw {
    fn from(regs: KvmRegs) -> Self {
        Self {
            rax: regs.rax, rbx: regs.rbx, rcx: regs.rcx, rdx: regs.rdx,
            rsi: regs.rsi, rdi: regs.rdi, rsp: regs.rsp, rbp: regs.rbp,
            r8: regs.r8, r9: regs.r9, r10: regs.r10, r11: regs.r11,
            r12: regs.r12, r13: regs.r13, r14: regs.r14, r15: regs.r15,
            rip: regs.rip, rflags: regs.rflags,
        }
    }
}

impl From<kvm::KvmSegmentRaw> for Segment {
    fn from(raw: kvm::KvmSegmentRaw) -> Self {
        Self {
            base: raw.base,
            limit: raw.limit,
            selector: raw.selector,
            r#type: raw.type_,
            present: raw.present,
            dpl: raw.dpl,
            db: raw.db,
            s: raw.s,
            l: raw.l,
            g: raw.g,
            avl: raw.avl,
            unusable: raw.unusable,
        }
    }
}

impl From<Segment> for kvm::KvmSegmentRaw {
    fn from(seg: Segment) -> Self {
        Self {
            base: seg.base,
            limit: seg.limit,
            selector: seg.selector,
            type_: seg.r#type,
            present: seg.present,
            dpl: seg.dpl,
            db: seg.db,
            s: seg.s,
            l: seg.l,
            g: seg.g,
            avl: seg.avl,
            unusable: seg.unusable,
            padding: 0,
        }
    }
}

impl From<kvm::KvmDtableRaw> for DescTable {
    fn from(raw: kvm::KvmDtableRaw) -> Self {
        Self {
            base: raw.base,
            limit: raw.limit,
        }
    }
}

impl From<DescTable> for kvm::KvmDtableRaw {
    fn from(dt: DescTable) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
            padding: [0; 3],
        }
    }
}

impl From<kvm::KvmSregsRaw> for KvmSregs {
    fn from(raw: kvm::KvmSregsRaw) -> Self {
        Self {
            cs: raw.cs.into(),
            ds: raw.ds.into(),
            es: raw.es.into(),
            fs: raw.fs.into(),
            gs: raw.gs.into(),
            ss: raw.ss.into(),
            tr: raw.tr.into(),
            ldt: raw.ldt.into(),
            gdt: raw.gdt.into(),
            idt: raw.idt.into(),
            cr0: raw.cr0,
            cr2: raw.cr2,
            cr3: raw.cr3,
            cr4: raw.cr4,
            cr8: raw.cr8,
            efer: raw.efer,
            apic_base: raw.apic_base,
        }
    }
}

impl From<KvmSregs> for kvm::KvmSregsRaw {
    fn from(sregs: KvmSregs) -> Self {
        Self {
            cs: sregs.cs.into(),
            ds: sregs.ds.into(),
            es: sregs.es.into(),
            fs: sregs.fs.into(),
            gs: sregs.gs.into(),
            ss: sregs.ss.into(),
            tr: sregs.tr.into(),
            ldt: sregs.ldt.into(),
            gdt: sregs.gdt.into(),
            idt: sregs.idt.into(),
            cr0: sregs.cr0,
            cr2: sregs.cr2,
            cr3: sregs.cr3,
            cr4: sregs.cr4,
            cr8: sregs.cr8,
            efer: sregs.efer,
            apic_base: sregs.apic_base,
            interrupt_bitmap: [0; 4],
        }
    }
}
