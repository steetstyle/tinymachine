//! Architecture-specific constants, types, and helpers.
//!
//! # Architecture Selection
//!
//! The `target` module alias points to the currently compiled architecture.
//! All arch-dependent submodules (port, cpu, layout, interrupt, kvm_types)
//! are re-exported at `crate::arch::*` for convenient access.
//!
//! ```rust,ignore
//! // These import styles work inside the tinyos-fork crate:
//! use crate::arch::port::COM1_BASE;           // explicit module path
//! use crate::arch::target::port::COM1_BASE;   // via target alias
//! use crate::arch::COM1_BASE;                 // flat (glob re-export)
//! ```
//!
//! # Adding a new architecture
//!
//! 1. Create `arch/<new_arch>/mod.rs` with identical submodules:
//!    `cpu`, `port`, `layout`, `interrupt`, `kvm_types`, `paths`, `exit`, `vcpu`, `vm`
//! 2. Add a `#[cfg(target_arch = "...")]` block below
//! 3. Each submodule must export the same public API

// ─── x86_64 ────────────────────────────────────────────────────────
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as target;
#[cfg(target_arch = "x86_64")]
pub use x86_64::boot;  // re-export boot module so crate::arch::boot works

// ─── aarch64 ──────────────────────────────────────────────────────
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as target;
#[cfg(target_arch = "aarch64")]
pub use aarch64::boot;

// ─── Future: riscv64 ───────────────────────────────────────────────
// #[cfg(target_arch = "riscv64")]
// pub mod riscv64;
// #[cfg(target_arch = "riscv64")]
// pub use riscv64 as target;

// ─── Glob re-export for backward compat ─────────────────────────────
// All items from `target::*` (constants, types, modules) are available
// at `crate::arch::*`. New code should prefer explicit module paths
// (`crate::arch::port::COM1_BASE`) or the `target` alias
// (`crate::arch::target::port::COM1_BASE`).
pub use target::*;
