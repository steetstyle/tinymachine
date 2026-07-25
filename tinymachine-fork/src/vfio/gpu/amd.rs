//! AMD GPU backend — stub implementation for AMD/ROCm GPUs

use crate::vfio::backend::GpuBackend;
use crate::vfio::base::VfioPassthroughBase;
use crate::vfio::device::{GpuDeviceInfo, VfioError};

/// AMD GPU backend — placeholder for future ROCm support.
///
/// Currently a no-op backend: AMD VFIO passthrough works without any
/// GPU-specific power pre-init or firmware loading (the amdgpu kernel
/// driver handles all initialization in the guest).
#[derive(Debug)]
pub struct AmdGpuBackend;

impl GpuBackend for AmdGpuBackend {
    fn name(&self) -> &'static str {
        "amd-rocm"
    }

    fn matches(device: &GpuDeviceInfo) -> bool {
        device.vendor_id == 0x1002
    }

    fn power_preinit(&self, _base: &VfioPassthroughBase) -> std::result::Result<(), VfioError> {
        // AMD GPUs are fully initialized by the guest kernel's amdgpu driver.
        Ok(())
    }

    fn load_firmware(&self, _base: &VfioPassthroughBase) -> std::result::Result<(), VfioError> {
        // No firmware loading needed — amdgpu driver loads firmware in-guest.
        Ok(())
    }

    fn post_boot_diagnostics(&self, _base: &VfioPassthroughBase) -> String {
        "AMD GPU: no diagnostics available (stub)".into()
    }
}
