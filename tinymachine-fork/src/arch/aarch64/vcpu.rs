//! aarch64-specific KVM Vcpu ioctl operations (STUB).
//!
//! These stubs exist to satisfy the architecture dispatch layer when
//! building for aarch64. Each function returns an error indicating the
//! operation is not yet implemented for this architecture.
//!
//! When implementing aarch64 support, replace these stubs with actual
//! KVM ioctl calls using aarch64-specific KVM constants (KVM_GET_ONE_REG,
//! KVM_SET_ONE_REG, etc.) and register definitions.

use std::os::fd::RawFd;

use crate::kvm::{KvmError, MpState, Result};
use crate::arch::kvm_types::*;

/// STUB: aarch64 uses KVM_GET_ONE_REG instead of KVM_GET_REGS
pub fn get_regs(_vcpu_fd: RawFd) -> Result<KvmRegsRaw> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_REGS not implemented (use KVM_GET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_ONE_REG instead of KVM_SET_REGS
pub fn set_regs(_vcpu_fd: RawFd, _regs: &KvmRegsRaw) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_REGS not implemented (use KVM_SET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_GET_ONE_REG for system registers
pub fn get_sregs(_vcpu_fd: RawFd) -> Result<KvmSregsRaw> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_SREGS not implemented (use KVM_GET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_ONE_REG for system registers
pub fn set_sregs(_vcpu_fd: RawFd, _sregs: &KvmSregsRaw) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_SREGS not implemented (use KVM_SET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_ONE_REG for CPU feature registers
pub fn set_cpuid2(_vcpu_fd: RawFd, _entries: &[KvmCpuidEntry2Raw]) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_CPUID2 not implemented (use KVM_SET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_GET_MP_STATE (same ioctl, works on aarch64)
pub fn get_mp_state(_vcpu_fd: RawFd) -> Result<MpState> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_MP_STATE stub".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_MP_STATE (same ioctl, works on aarch64)
pub fn set_mp_state(_vcpu_fd: RawFd, _state: MpState) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_MP_STATE stub".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_GET_ONE_REG for FP/SIMD state
pub fn get_xsave(_vcpu_fd: RawFd) -> Result<[u8; 4096]> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_XSAVE not implemented (use KVM_GET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_ONE_REG for FP/SIMD state
pub unsafe fn set_xsave(_vcpu_fd: RawFd, _xsave: &[u8; 4096]) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_XSAVE not implemented (use KVM_SET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_GET_ONE_REG for SVE/FPSIMD registers
pub fn get_xcrs(_vcpu_fd: RawFd) -> Result<Vec<(u32, u64)>> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_XCRS not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_ONE_REG for SVE/FPSIMD registers
pub unsafe fn set_xcrs(_vcpu_fd: RawFd, _xcrs: &[(u32, u64)]) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_XCRS not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_GET_ONE_REG for implementation-defined registers
pub unsafe fn save_critical_msrs(_vcpu_fd: RawFd) -> Result<Vec<(u32, u64)>> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_MSRS not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_SET_ONE_REG for implementation-defined registers
pub unsafe fn restore_msrs(_vcpu_fd: RawFd, _msrs: &[(u32, u64)]) -> Result<u32> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_MSRS not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

// ─── Fork helpers: CPUID filtering ─────────────────────────────────

/// STUB: aarch64 has no CPUID concept; no filtering needed.
pub fn filter_cpuid_for_fork(_entries: &mut [KvmCpuidEntry2Raw]) {}

// ─── Fork helpers: XSAVE buffer construction ──────────────────────

/// STUB: aarch64 FP/SIMD state is managed via KVM_GET_ONE_REG /
/// KVM_SET_ONE_REG, not XSAVE. Returns a zeroed buffer as placeholder.
pub fn build_clean_xsave(_xcr0_value: u64) -> [u8; 4096] {
    [0u8; 4096]
}

/// STUB: aarch64 interrupt injection (may use KVM_INTERRUPT or PSCI)
pub fn inject_interrupt(_vcpu_fd: RawFd, _irq: u32) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_INTERRUPT stub".into(),
        errno: libc::ENOSYS,
    })
}

// ─── KVM-level CPUID query (uses /dev/kvm fd) ─────────────────────

/// STUB: aarch64 does not have CPUID; use KVM_GET_ONE_REG for feature discovery
pub fn get_supported_cpuid(_kvm_fd: RawFd) -> Result<Vec<KvmCpuidEntry2Raw>> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_SUPPORTED_CPUID not implemented (use KVM_GET_ONE_REG)".into(),
        errno: libc::ENOSYS,
    })
}
