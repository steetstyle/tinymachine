//! VFIO GPU Passthrough — direct GPU access for KVM sandboxes
//!
//! This module implements VFIO-based GPU passthrough for the PyTorch Tier 3
//! `FreshBootBackend`. It enumerates available GPU devices via sysfs, manages
//! VFIO containers and IOMMU groups, and registers the passthrough device
//! with KVM for direct guest access.
//!
//! # Architecture
//!
//! VFIO (Virtual Function I/O) allows a userspace driver (or KVM guest) to
//! directly control a PCI device. The flow:
//!
//! 1. GPU must be bound to the `vfio-pci` kernel driver (not `nvidia`/`amdgpu`)
//! 2. Open `/dev/vfio/vfio` → container fd
//! 3. Find GPU's IOMMU group from `/sys/bus/pci/devices/.../iommu_group`
//! 4. Open `/dev/vfio/<group_nr>` → group fd
//! 5. `VFIO_GROUP_SET_CONTAINER` → attach group to container
//! 6. `VFIO_SET_IOMMU` → enable Type1 IOMMU on container
//! 7. `VFIO_GROUP_GET_DEVICE_FD` → get device fd
//! 8. Map device BARs via `KVM_CREATE_DEVICE` + `KVM_SET_DEVICE_ATTR`
//! 9. Register VFIO group with KVM via KVM_DEV_VFIO_GROUP
//!
//! GPU-type-specific operations (power preinit, firmware loading) are
//! handled by pluggable `GpuBackend` implementations.

mod base;
mod device;
mod pci_config;
pub mod backend;
mod gpu;

// Re-export main struct
pub use base::VfioPassthroughBase;

// Re-export types
pub use device::{
    BarRegionInfo, GpuDeviceInfo, MsiConfig, Result, VfioError, VFIO_BAR_SLOT_BASE,
    VFIO_MAX_BAR_SLOTS,
};

// Re-export public functions
pub use device::{detect_gpu_devices, is_bound_to_vfio};
pub use pci_config::read_bar_u32;

// Re-export backend factory
pub use backend::{detect_gpu_backend, GpuBackend};

// Re-export GPU backends
pub use gpu::{AmdGpuBackend, NvidiaGpuBackend};
