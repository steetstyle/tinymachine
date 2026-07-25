//! GPU-type backend implementations for VFIO passthrough

mod nvidia;
mod amd;

pub use nvidia::NvidiaGpuBackend;
pub use amd::AmdGpuBackend;
