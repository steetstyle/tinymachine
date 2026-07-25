//! KVM Boot Protocol — architecture-specific implementation.
//!
//! This module re-exports the architecture-specific boot implementation
//! from `arch/<arch>/boot.rs`. The actual boot protocol (PVH on x86_64,
//! DTB + PSCI on aarch64) lives in the arch module.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::boot::{BootConfig, BootedVm, boot_linux};
//! let vm = unsafe { boot_linux(&kvm, &config) }?;
//! ```
//!
//! All types and functions are re-exported from `crate::arch::boot`.
//! See `crate::arch::boot` for documentation.

pub use crate::arch::boot::*;
