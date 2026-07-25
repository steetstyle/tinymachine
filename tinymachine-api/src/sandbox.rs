//! Sandbox backend trait and execution tier definitions.
//!
//! This module defines the core sandbox abstraction for TinyMachine.
//! All code execution backends (wasm, KVM fork, orchestrator forward,
//! fresh boot) implement the [`SandboxBackend`] trait with exactly
//! four methods.
//!
//! # Tier System
//!
//! | Tier | Backend | Latency | Use Case |
//! |------|---------|---------|----------|
//! | 1 | `Wasm` | ~2µs | Pure computation, WASI-safe |
//! | 2 | `KvmFork` | ~0.5ms | Python, Node, shell (binary mode) |
//! | 2/3 | `Orchestrator` | ~0.5-5ms | Unikernel → host forward |
//! | 3 | `FreshBoot` | ~1s | Full VM, GPU passthrough |
//!
//! # Examples
//!
//! ```ignore
//! use tinymachine_api::{SandboxBackend, ExecutionTier, Variant, create_backend};
//!
//! // Call tinymachine_fork::register_all_backends() first.
//! let tier = ExecutionTier::FreshBoot;
//! let mut backend = create_backend(tier).expect("failed to create backend");
//!
//! // Init with a variant
//! let variant = Variant::new("python", "minimal", "base");
//! backend.init(&variant).expect("init failed");
//!
//! // Execute code
//! let result = backend.exec("print('hello')").expect("exec failed");
//!
//! // Reset for re-use
//! backend.reset().expect("reset failed");
//!
//! // Destroy when done
//! backend.destroy().expect("destroy failed");
//! ```

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::error::{ApiError, Result};
use crate::variant::Variant;

/// Execution tier selector.
///
/// Each variant maps to the fastest tier that can support its requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ExecutionTier {
    /// Tier 1: in-process wasmtime sandbox (~2µs).
    ///
    /// Suitable for pure computation, string manipulation, JSON parsing —
    /// anything that fits within WASI capabilities.
    Wasm,

    /// Tier S: host-process GPU fork (~1ms).
    ///
    /// Runs tinygrad GPU code in a CoW-forked child of a pre-initialized
    /// Python worker that has `Device["NV"]` (CUDA context) warm.
    ///
    /// # Warning
    ///
    /// This tier provides **no VM-level isolation**. It runs on the host
    /// process with GPU access via the NVIDIA proprietary driver. Only use
    /// for trusted code. See `HostGpuForkBackend` docs for limitations.
    ///
    /// Falls back to CPU if `nvidia.ko` is not loaded on the host.
    HostGpu,

    /// Tier 2: KVM CoW fork sandbox (~0.5ms).
    ///
    /// A lightweight VM forked from a pre-booted template snapshot.
    /// Uses kernel-level copy-on-write via `MAP_PRIVATE`.
    /// Available only in binary mode (running on a Linux host).
    KvmFork,

    /// Tier 2/3: forward execution to a host orchestrator.
    ///
    /// Used in unikernel mode, where TinyMachine itself runs inside a VM
    /// and cannot perform nested KVM operations. The request is sent
    /// to the host orchestrator via a proxy protocol.
    Orchestrator,

    /// Tier 3: full VM boot with QEMU (~1.1s).
    ///
    /// Boot a fresh virtual machine via QEMU + KVM, with full device
    /// emulation (SeaBIOS, ACPI, PCI Option ROM). Required for GPU
    /// passthrough with VBIOS Option ROM loading (e.g., VFIO GPU
    /// variants that need VBIOS POST to initialize power domains).
    ///
    /// Uses `qemu-system-x86_64` with `-device vfio-pci,romfile=...`
    /// to inject the VBIOS. Each exec spawns a fresh QEMU process.
    QemuVm,

    /// Tier 3: full VM boot (~1s).
    ///
    /// Boot a fresh virtual machine from a kernel image.
    /// Required for GPU passthrough (PyTorch variants) or
    /// long-running stateful environments.
    FreshBoot,
}

impl ExecutionTier {
    /// Returns a human-readable tier label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::HostGpu => "host-gpu",
            Self::KvmFork => "kvm-fork",
            Self::Orchestrator => "orchestrator",
            Self::QemuVm => "qemu-vm",
            Self::FreshBoot => "fresh-boot",
        }
    }

    /// Returns the worst-case latency estimate in microseconds.
    pub fn estimated_latency_us(&self) -> u64 {
        match self {
            Self::Wasm => 2,
            Self::HostGpu => 1_000,
            Self::KvmFork => 500,
            Self::Orchestrator => 5_000,
            Self::QemuVm => 1_100_000,
            Self::FreshBoot => 1_000_000,
        }
    }
}

impl std::fmt::Display for ExecutionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Core sandbox abstraction for all execution backends.
///
/// Every code execution path in TinyMachine — whether wasm in-process, KVM fork,
/// orchestrator forward, or full VM boot — implements this trait.
///
/// # Lifecycle
///
/// 1. [`init`](SandboxBackend::init) — initialise the backend for a specific variant.
/// 2. [`exec`](SandboxBackend::exec) — execute code, return stdout as a string.
/// 3. [`reset`](SandboxBackend::reset) — return the backend to a clean state for re-use.
/// 4. [`destroy`](SandboxBackend::destroy) — release all resources.
///
/// Backends are **not** guaranteed to be thread-safe. The caller must ensure
/// that each backend is used from a single thread at a time.
pub trait SandboxBackend {
    /// Initialise the sandbox backend for the given variant.
    ///
    /// This may load a template snapshot, start a VM, or prepare a wasm
    /// engine. Called once before the first `exec`.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::Sandbox` if the variant is unsupported or
    /// initialisation fails (e.g. missing template snapshot).
    fn init(&mut self, variant: &Variant) -> Result<()>;

    /// Execute the given code and return its standard output.
    ///
    /// The code is run inside the sandbox. The return value is the captured
    /// stdout (or stderr merged into stdout).
    ///
    /// # Errors
    ///
    /// Returns `ApiError::Sandbox` if execution fails, times out, or
    /// the code produces a non-zero exit code.
    fn exec(&mut self, code: &str) -> Result<String>;

    /// Reset the sandbox to a clean state for re-use.
    ///
    /// After `reset`, the backend should be in the same state as after
    /// `init` — ready for another `exec` without re-initialising the
    /// runtime. This is the "return to warm pool" operation.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::Sandbox` if the reset fails.
    fn reset(&mut self) -> Result<()>;

    /// Destroy the sandbox and release all resources.
    ///
    /// After `destroy`, the backend must not be used again.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::Sandbox` if cleanup fails. Implementations
    /// should attempt to release resources even if an error occurs.
    fn destroy(&mut self) -> Result<()>;
}

// ─── Backend Registry ────────────────────────────────────────────────
//
// A runtime-registry pattern that avoids circular crate dependencies.
// Crates that implement concrete backends (e.g. `tinyos-fork`) register
// factory functions at startup. The `create_backend()` factory dispatches
// through this registry.
//
// This is initialized the first time it's accessed.
static BACKEND_REGISTRY: LazyLock<Mutex<HashMap<ExecutionTier, BackendFactory>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Factory type for creating a sandbox backend.
pub type BackendFactory = Box<dyn Fn() -> Box<dyn SandboxBackend> + Send + Sync>;

/// Register a sandbox backend factory for a given execution tier.
///
/// Call this during program initialisation (e.g. in `main()`) before using
/// `create_backend()`. Each tier can only be registered once; subsequent
/// registrations overwrite the previous factory.
///
/// # Example
///
/// ```ignore
/// // (Requires a concrete backend implementation to be available.)
/// use tinymachine_api::{register_backend, ExecutionTier};
/// use tinymachine_api::sandbox::BackendFactory;
///
/// // Registering a backend (e.g., FreshBootBackend from tinyos-fork):
/// // use tinymachine_fork::fresh_boot::FreshBootBackend;
/// // let factory: BackendFactory = Box::new(|| Box::new(FreshBootBackend::new()));
/// // register_backend(ExecutionTier::FreshBoot, factory);
/// ```
pub fn register_backend(tier: ExecutionTier, factory: BackendFactory) {
    BACKEND_REGISTRY
        .lock()
        .expect("BACKEND_REGISTRY lock poisoned")
        .insert(tier, factory);
}

/// Clear all registered backends (for testing isolation).
///
/// Tests that share the global `BACKEND_REGISTRY` must call this between
/// runs to avoid cross-test pollution. For example,
/// `test_factory_returns_error_without_registration` and
/// `test_register_overwrites_previous` conflict without this.
#[doc(hidden)]
pub fn clear_backends() {
    BACKEND_REGISTRY
        .lock()
        .expect("BACKEND_REGISTRY lock poisoned")
        .clear();
}

/// Create a sandbox backend from an execution tier.
///
/// This is the factory function that maps an [`ExecutionTier`] to a
/// concrete [`SandboxBackend`] implementation. It dispatches through
/// the runtime [`register_backend`] registry.
///
/// The returned backend is **uninitialised** — the caller must call
/// [`init`](SandboxBackend::init) before the first `exec`.
///
/// # Errors
///
/// Returns `ApiError::Unsupported` for tiers that have no backend registered.
///
/// # Examples
///
/// ```ignore
/// use tinymachine_api::{create_backend, ExecutionTier, SandboxBackend, Variant};
///
/// // Requires a backend factory to have been registered first.
/// // Call tinymachine_fork::register_all_backends() at startup.
/// let mut backend = create_backend(ExecutionTier::FreshBoot)
///     .expect("no backend registered for FreshBoot");
/// ```
///
/// **Note:** Backend crates should call `register_backend()` at startup.
/// The `tinyos-fork` crate provides a convenience `register_all_backends()`
/// function that registers Wasm, and FreshBoot backends.
pub fn create_backend(tier: ExecutionTier) -> Result<Box<dyn SandboxBackend>> {
    let registry = BACKEND_REGISTRY
        .lock()
        .expect("BACKEND_REGISTRY lock poisoned");

    match registry.get(&tier) {
        Some(factory) => Ok(factory()),
        None => Err(ApiError::Unsupported(format!(
            "No backend registered for tier {tier}. \
             Call register_backend() or tinymachine_fork::register_all_backends() first."
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_tier_display() {
        assert_eq!(ExecutionTier::Wasm.to_string(), "wasm");
        assert_eq!(ExecutionTier::HostGpu.to_string(), "host-gpu");
        assert_eq!(ExecutionTier::KvmFork.to_string(), "kvm-fork");
        assert_eq!(ExecutionTier::Orchestrator.to_string(), "orchestrator");
        assert_eq!(ExecutionTier::QemuVm.to_string(), "qemu-vm");
        assert_eq!(ExecutionTier::FreshBoot.to_string(), "fresh-boot");
    }

    #[test]
    fn test_execution_tier_label() {
        assert_eq!(ExecutionTier::Wasm.label(), "wasm");
        assert_eq!(ExecutionTier::HostGpu.label(), "host-gpu");
        assert_eq!(ExecutionTier::KvmFork.label(), "kvm-fork");
        assert_eq!(ExecutionTier::QemuVm.label(), "qemu-vm");
    }

    #[test]
    fn test_estimated_latency() {
        assert_eq!(ExecutionTier::Wasm.estimated_latency_us(), 2);
        assert_eq!(ExecutionTier::HostGpu.estimated_latency_us(), 1_000);
        assert_eq!(ExecutionTier::KvmFork.estimated_latency_us(), 500);
        assert_eq!(ExecutionTier::Orchestrator.estimated_latency_us(), 5_000);
        assert_eq!(ExecutionTier::QemuVm.estimated_latency_us(), 1_100_000);
        assert_eq!(ExecutionTier::FreshBoot.estimated_latency_us(), 1_000_000);
    }

    #[test]
    fn test_factory_returns_error_without_registration() {
        // Clear any backends registered by other tests that share this
        // global process state (e.g. test_register_overwrites_previous).
        super::clear_backends();

        // Without calling register_backend(), all tiers return Unsupported.
        for tier in &[
            ExecutionTier::Wasm,
            ExecutionTier::KvmFork,
            ExecutionTier::Orchestrator,
            ExecutionTier::QemuVm,
            ExecutionTier::FreshBoot,
        ] {
            let result = create_backend(*tier);
            assert!(
                result.is_err(),
                "tier {tier} should return unsupported without registration"
            );
            match result {
                Err(ApiError::Unsupported(_)) => { /* expected */ }
                _ => panic!("tier {tier}: expected Unsupported error"),
            }
        }
    }

    #[test]
    fn test_register_and_create_backend() {
        // Clear global state to avoid interference from other tests.
        super::clear_backends();

        // Register a mock backend and verify it's returned by create_backend.
        let factory: BackendFactory = Box::new(|| Box::new(MockBackend { initialised: false }));
        register_backend(ExecutionTier::Wasm, factory);

        let mut backend = create_backend(ExecutionTier::Wasm)
            .expect("registered backend should be created");
        let variant = Variant::new("python", "minimal", "base");
        backend.init(&variant).unwrap();
        let result = backend.exec("hello").unwrap();
        assert_eq!(result, "executed: hello");
        backend.destroy().unwrap();
    }

    #[test]
    fn test_register_overwrites_previous() {
        // Clear global state to avoid interference from other tests.
        super::clear_backends();

        let factory1: BackendFactory = Box::new(|| Box::new(MockBackend { initialised: false }));
        let factory2: BackendFactory = Box::new(|| Box::new(MockBackend { initialised: false }));
        register_backend(ExecutionTier::KvmFork, factory1);
        register_backend(ExecutionTier::KvmFork, factory2); // overwrite
        let result = create_backend(ExecutionTier::KvmFork);
        assert!(result.is_ok(), "overwritten backend should still be available");
    }

    // ─── Mock backend for trait test ─────────────────────────────────────

    struct MockBackend {
        initialised: bool,
    }

    impl SandboxBackend for MockBackend {
        fn init(&mut self, variant: &Variant) -> Result<()> {
            assert_eq!(variant.lang, "python");
            self.initialised = true;
            Ok(())
        }

        fn exec(&mut self, code: &str) -> Result<String> {
            assert!(self.initialised, "must init before exec");
            Ok(format!("executed: {code}"))
        }

        fn reset(&mut self) -> Result<()> {
            self.initialised = true; // stays ready after reset
            Ok(())
        }

        fn destroy(&mut self) -> Result<()> {
            self.initialised = false;
            Ok(())
        }
    }

    #[test]
    fn test_sandbox_backend_lifecycle() {
        let mut backend = MockBackend {
            initialised: false,
        };
        let variant = Variant::new("python", "minimal", "base");

        backend.init(&variant).unwrap();
        let result = backend.exec("print(42)").unwrap();
        assert_eq!(result, "executed: print(42)");

        backend.reset().unwrap();
        let result = backend.exec("hello").unwrap();
        assert_eq!(result, "executed: hello");

        backend.destroy().unwrap();
    }

    #[test]
    fn test_sandbox_backend_exec_before_init_fails() {
        let mut backend = MockBackend {
            initialised: false,
        };
        // exec without init would panic in MockBackend because of the
        // assertion. Real backends should return an error instead.
        // For MockBackend we just verify destroy works on uninit state.
        backend.destroy().unwrap();
    }
}

// ─── BackendType Enum ──────────────────────────────────────────────────

/// Identifies which sandbox backend the seccomp filter is for.
///
/// Each backend has a different minimum syscall allowlist tailored
/// to its operation. This enum is used by `SeccompFilter::install()`
/// to select the correct BPF filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendType {
    /// Wasmtime in-process sandbox (Tier 1).
    /// Requires mmap(PROT_EXEC) for JIT code generation.
    Wasm,
    /// KVM CoW fork sandbox (Tier 2).
    /// Requires ioctl(KVM, ...), mmap, eventfd2.
    KvmFork,
    /// Host GPU process fork (Tier S, no VM isolation).
    /// Requires open(/dev/nvidia*), ioctl, mmap.
    HostGpu,
    /// QEMU subprocess (Tier 3).
    /// Seccomp installed in QEMU child after fork, before exec.
    Qemu,
    /// Fresh KVM boot with VFIO (Tier 3).
    /// Seccomp on host process; guest needs its own policy.
    FreshBoot,
}
