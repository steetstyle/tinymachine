//! GpuBackend trait — GPU-type-specific operations for VFIO passthrough

use std::fmt::Debug;

use crate::vfio::device::{GpuDeviceInfo, VfioError};
use crate::vfio::base::VfioPassthroughBase;

/// GPU-type-specific operations for VFIO-passthrough GPUs.
///
/// Each GPU vendor/architecture implements this trait to provide:
/// - Power pre-initialization (waking up engine power domains after FLR)
/// - Firmware loading (GSP bootloader, VBIOS, etc.)
/// - Diagnostics (register dumps for debugging)
pub trait GpuBackend: Debug + Send {
    /// Human-readable name for this backend (e.g. "nvidia-gsp", "amd-rocm")
    fn name(&self) -> &'static str;

    /// Check if this backend applies to the given GPU device.
    fn matches(device: &GpuDeviceInfo) -> bool
    where
        Self: Sized;

    /// Power-preinit the GPU after VFIO FLR to enable engine power domains.
    ///
    /// Called during `VfioPassthroughBase::init()`, after the device fd is
    /// opened and BARs are queried, but BEFORE the guest boots.
    fn power_preinit(&self, base: &VfioPassthroughBase) -> std::result::Result<(), VfioError>;

    /// Load firmware into the GPU (e.g., GSP bootloader).
    ///
    /// Called after `power_preinit()` and after BAR pre-assignment.
    fn load_firmware(&self, base: &VfioPassthroughBase) -> std::result::Result<(), VfioError>;

    /// Whether this GPU needs VBIOS Option ROM POST.
    fn needs_vbios_post(&self) -> bool {
        true
    }

    /// Read diagnostic registers after boot for debugging.
    fn post_boot_diagnostics(&self, base: &VfioPassthroughBase) -> String;
}

/// Auto-detect the GPU backend based on vendor/device IDs.
pub fn detect_gpu_backend(device: &GpuDeviceInfo) -> Option<Box<dyn GpuBackend>> {
    if crate::vfio::gpu::NvidiaGpuBackend::matches(device) {
        Some(Box::new(crate::vfio::gpu::NvidiaGpuBackend))
    } else if crate::vfio::gpu::AmdGpuBackend::matches(device) {
        Some(Box::new(crate::vfio::gpu::AmdGpuBackend))
    } else {
        None
    }
}
