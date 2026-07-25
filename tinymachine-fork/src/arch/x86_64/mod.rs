//! x86_64 Architecture Support — constants, types, and helpers for x86 KVM.
//!
//! This module consolidates all x86_64-specific values in one place.
//! When adding aarch64 or riscv64 support, create `arch/aarch64/` and
//! `arch/riscv64/` sibling modules with equivalent constants/structs,
//! then introduce an `Arch` trait in `arch/mod.rs`.

pub mod boot;
pub mod cpu;
pub mod exit;
pub mod interrupt;
pub mod kvm_types;
pub mod layout;
pub mod paths;
pub mod port;
pub mod snapshot_types;
pub mod vcpu;
pub mod vm;

// Re-export commonly used items at the x86_64 level for convenience.
pub use cpu::*;
pub use exit::*;
pub use interrupt::*;
pub use kvm_types::*;
pub use layout::*;
pub use paths::*;
pub use port::*;
