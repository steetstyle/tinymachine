//! aarch64 Architecture Support — constants, types, and helpers.
//!
//! # Status
//! aarch64 support is stubbed. The boot module provides type stubs,
//! and the vcpu module provides stub KVM ioctl implementations.
//! When implementing actual aarch64 support:
//!
//! 1. Replace `boot.rs` stubs with real aarch64 PVH boot protocol
//! 2. Replace `vcpu.rs` stubs with KVM_GET_ONE_REG/KVM_SET_ONE_REG calls
//! 3. Add aarch64-specific KVM types to `kvm_types.rs`
//! 4. Add aarch64-specific port/layout/interrupt modules

pub mod boot;
pub mod port;
pub mod snapshot_types;
pub mod vcpu;
pub mod vm;
