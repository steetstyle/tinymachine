//! aarch64 Snapshot Types — VM register state stubs.
//!
//! On aarch64, VM register state is managed via `KVM_GET_ONE_REG` /
//! `KVM_SET_ONE_REG` with architecture-specific register IDs
//! (e.g., `KVM_REG_ARM64` for general-purpose, system, and FP/SIMD
//! registers). The interrupt controller is GICv3 (not PIC/IOAPIC).
//!
//! # Stub
//! These types are placeholders until aarch64 VM snapshot support
//! is implemented. They compile but carry minimal state.

use serde::{Deserialize, Serialize};

use crate::kvm;

// ─── XSAVE constants ──────────────────────────────────────────────

/// STUB: aarch64 uses KVM_GET_ONE_REG for FP/SIMD state, not XSAVE.
/// Placeholder value for type compatibility.
pub const XSAVE_SIZE: usize = 4096;

/// STUB: placeholder for XSAVE buffer type.
pub type XsaveBuffer = [u8; XSAVE_SIZE];

// ─── CPU register state types ─────────────────────────────────────

/// STUB: aarch64 CPU state placeholder.
///
/// Actual implementation will use `KVM_GET_ONE_REG` with per-register IDs.
/// See `KVM_REG_ARM64` definitions in `linux/kvm.h`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuState {
    /// Placeholder for aarch64 register state
    pub regs: KvmRegs,
    /// Placeholder for aarch64 system register state
    pub sregs: KvmSregs,
    /// Placeholder for implementation-defined register values
    #[serde(default)]
    pub msrs: Vec<(u32, u64)>,
    /// Placeholder for FP/SIMD state
    #[serde(default)]
    pub xcrs: Vec<(u32, u64)>,
}

/// STUB: aarch64 general-purpose registers (x0-x30, PC, SP, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvmRegs {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// STUB: aarch64 system registers (placeholder).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvmSregs {
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub sctlr_el1: u64,
    /// Placeholder — actual aarch64 KVM_SREGS has ~30 system registers
    pub _extra: Vec<(u64, u64)>,
}

/// STUB: aarch64 has no x86 segments; placeholder type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub base: u64,
    pub _placeholder: u64,
}

/// STUB: aarch64 has no x86 descriptor tables; placeholder type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescTable {
    pub base: u64,
    pub limit: u16,
}

/// STUB: aarch64 uses GICv3, not PIC/IOAPIC. Placeholder.
#[derive(Debug, Clone)]
pub struct IrqChipState;

impl IrqChipState {
    pub fn all_present(&self) -> bool {
        false
    }
}

// ─── Stub conversions ─────────────────────────────────────────────

impl From<kvm::KvmRegsRaw> for KvmRegs {
    fn from(_raw: kvm::KvmRegsRaw) -> Self {
        // aarch64 KVM_GET_ONE_REG uses different register encoding
        Self {
            x0: 0, x1: 0, x2: 0, x3: 0, x4: 0, x5: 0,
            x6: 0, x7: 0, x8: 0, x9: 0, x10: 0, x11: 0,
            x12: 0, x13: 0, x14: 0, x15: 0, x16: 0, x17: 0,
            x18: 0, x19: 0, x20: 0, x21: 0, x22: 0, x23: 0,
            x24: 0, x25: 0, x26: 0, x27: 0, x28: 0, x29: 0,
            lr: 0, sp: 0, pc: 0, pstate: 0,
        }
    }
}

impl From<KvmRegs> for kvm::KvmRegsRaw {
    fn from(_regs: KvmRegs) -> Self {
        kvm::KvmRegsRaw::default()
    }
}

impl From<kvm::KvmSegmentRaw> for Segment {
    fn from(_raw: kvm::KvmSegmentRaw) -> Self {
        Self { base: 0, _placeholder: 0 }
    }
}

impl From<Segment> for kvm::KvmSegmentRaw {
    fn from(_seg: Segment) -> Self {
        kvm::KvmSegmentRaw::default()
    }
}

impl From<kvm::KvmDtableRaw> for DescTable {
    fn from(_raw: kvm::KvmDtableRaw) -> Self {
        Self { base: 0, limit: 0 }
    }
}

impl From<DescTable> for kvm::KvmDtableRaw {
    fn from(_dt: DescTable) -> Self {
        kvm::KvmDtableRaw::default()
    }
}

impl From<kvm::KvmSregsRaw> for KvmSregs {
    fn from(_raw: kvm::KvmSregsRaw) -> Self {
        Self {
            ttbr0_el1: 0, ttbr1_el1: 0, tcr_el1: 0, sctlr_el1: 0,
            _extra: Vec::new(),
        }
    }
}

impl From<KvmSregs> for kvm::KvmSregsRaw {
    fn from(_sregs: KvmSregs) -> Self {
        kvm::KvmSregsRaw::default()
    }
}
