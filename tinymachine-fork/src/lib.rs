//! TinyMachine Fork Engine — KVM CoW fork + Wasm sandbox
//!
//! # Safety
//! This crate contains `unsafe` blocks for:
//! - KVM ioctl calls (raw `libc::ioctl` on KVM fd)
//! - `mmap`/`munmap` for guest memory and kvm_run mapping
//! - CPU state save/restore via `KVM_GET_REGS`/`KVM_SET_REGS` etc.
//! - x86_64 `rdtsc` for performance measurement
//!
//! Every `unsafe` block has a `// SAFETY:` justification.

pub mod arch;
pub mod kvm;
pub mod snapshot;
pub mod serial;
pub mod fork;
#[cfg(feature = "wasm")]
pub mod wasm;
pub mod pool;
pub mod pci_root_port;
pub mod uops;
pub mod cache;
pub mod profiler;
pub mod lazy;
pub mod shared_mem;
pub mod boot;
pub mod variant;
pub mod template_registry;
pub mod layer_registry;
pub mod composer;
pub mod kernel_registry;
pub mod vfio;
pub mod fresh_boot;
pub mod host_gpu_fork;
pub mod qemu_backend;
pub mod seccomp;
#[cfg(test)]
pub mod test_helpers;
#[cfg(test)]
pub mod process_replay;

pub use kvm::Kvm;
pub use kernel_registry::KernelRegistry;
pub use snapshot::Snapshot;
pub use fork::ForkEngine;
pub use pool::ForkPool;
pub use fresh_boot::FreshBootBackend;
pub use tinymachine_api::ExecutionTier;
use tinymachine_api::sandbox::BackendFactory;

/// Register all available sandbox backends from this crate into the global
/// `tinymachine_api` backend registry.
///
/// Call this once at startup (e.g. in `main()`) before using
/// `tinymachine_api::create_backend()`.
///
/// # Registered backends
///
/// | Tier | Backend |
/// |------|---------|
/// | `FreshBoot` | `FreshBootBackend` |
/// | `Wasm` | `WasmBackend` |
/// | `HostGpu` | `HostGpuForkBackend` |
/// | `QemuVm` | `QemuBackend` |
///
/// `KvmFork` is *not* registered here because it requires a pre-built
/// template snapshot. Use the CLI or orchestrator's own pool setup instead.
pub fn register_all_backends() {
    // FreshBoot: always available (self-contained, no external deps)
    let fresh_boot_factory: BackendFactory = Box::new(|| {
        Box::new(fresh_boot::FreshBootBackend::new())
    });
    tinymachine_api::register_backend(ExecutionTier::FreshBoot, fresh_boot_factory);

    // Wasm: in-process sandbox (requires wasm feature)
    #[cfg(feature = "wasm")]
    {
        let wasm_factory: BackendFactory = Box::new(|| {
            Box::new(wasm::WasmBackend::new())
        });
        tinymachine_api::register_backend(ExecutionTier::Wasm, wasm_factory);
    }

    // HostGpu: host-process GPU fork via tinygrad worker
    let host_gpu_factory: BackendFactory = Box::new(|| {
        Box::new(host_gpu_fork::HostGpuForkBackend::new())
    });
    tinymachine_api::register_backend(ExecutionTier::HostGpu, host_gpu_factory);

    // QemuVm: QEMU-backed VM with SeaBIOS + VBIOS Option ROM for GPU passthrough
    let qemu_factory: BackendFactory = Box::new(|| {
        Box::new(qemu_backend::QemuBackend::new())
    });
    tinymachine_api::register_backend(ExecutionTier::QemuVm, qemu_factory);

    #[cfg(feature = "wasm")]
    tracing::info!("TinyMachine backends registered: FreshBoot, Wasm, HostGpu, QemuVm");
    #[cfg(not(feature = "wasm"))]
    tracing::info!("TinyMachine backends registered: FreshBoot, HostGpu, QemuVm (wasm disabled — no cranelift JIT)");
}
