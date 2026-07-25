//! aarch64-specific KVM Vm ioctl operations (STUB).
//!
//! These stubs exist to satisfy the architecture dispatch layer when
//! building for aarch64. Each function returns an error indicating the
//! operation is not yet implemented for this architecture.
//!
//! aarch64 does not have PIC/IOAPIC/PIT. It uses GIC (Generic Interrupt
//! Controller) v2/v3/v4 instead, which is created via KVM_CREATE_DEVICE
//! with KVM_DEV_TYPE_ARM_VGIC_V3. PIT emulation is x86-specific.
//! GSI routing on aarch64 uses the GICv3 ITS (Interrupt Translation Service)
//! for MSI routing, which is a different API than KVM_SET_GSI_ROUTING.

use std::os::fd::RawFd;

use crate::kvm::{KvmError, Result};
use crate::arch::kvm_types::*;

/// STUB: aarch64 uses KVM_CREATE_DEVICE(KVM_DEV_TYPE_ARM_VGIC_V3) instead
pub fn create_irqchip(_vm_fd: RawFd) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_CREATE_IRQCHIP not implemented (use KVM_CREATE_DEVICE with VGIC)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 has no PIT (8254); uses arch timer instead
pub fn create_pit(_vm_fd: RawFd) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_CREATE_PIT2 not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_CREATE_DEVICE + VGIC attr to save state
pub unsafe fn get_irqchip(_vm_fd: RawFd, _chip_id: u32) -> Result<KvmIrqChipRaw> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_GET_IRQCHIP not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses KVM_CREATE_DEVICE + VGIC attr to restore state
pub unsafe fn set_irqchip(_vm_fd: RawFd, _chip: &KvmIrqChipRaw) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_IRQCHIP not implemented (x86-specific)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 uses GICv3 ITS for MSI routing (different API)
pub unsafe fn set_gsi_routing(_vm_fd: RawFd, _entries: &[KvmIrqRoutingEntryRaw]) -> Result<()> {
    Err(KvmError::Ioctl {
        context: "aarch64: KVM_SET_GSI_ROUTING not implemented (use VGIC ITS)".into(),
        errno: libc::ENOSYS,
    })
}

/// STUB: aarch64 does not have IOAPIC routing; MSI routing uses GIC ITS
pub fn build_gsi_routing_table(
    _msi_gsi_base: u32,
    _msi_count: u32,
    _msi_address_lo: u32,
    _msi_address_hi: u32,
    _msi_data_base: u32,
) -> Vec<KvmIrqRoutingEntryRaw> {
    Vec::new() // Return empty until aarch64 routing is implemented
}
