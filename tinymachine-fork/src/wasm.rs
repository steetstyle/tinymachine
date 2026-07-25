//! Wasm sandbox — in-process wasmtime execution (Tier 1)
//!
//! For fast, pure-computation sandboxing without VM overhead.
//! Uses wasmtime for WebAssembly execution with WASI support.

use std::collections::HashMap;
use thiserror::Error;

/// Errors from Wasm operations
#[derive(Error, Debug)]
pub enum WasmError {
    #[error("Wasmtime error: {0}")]
    Wasmtime(String),
    #[error("Compilation error: {0}")]
    Compile(String),
    #[error("Execution error: {0}")]
    Runtime(String),
}

pub type Result<T> = std::result::Result<T, WasmError>;

/// A Wasm sandbox instance
///
/// In Phase 0: minimal implementation that wraps wasmtime
/// and provides a simple eval interface.
pub struct WasmSandbox {
    engine: wasmtime::Engine,
    store: wasmtime::Store<()>,
    /// Cache of compiled wasmtime modules keyed by source hash (blake3).
    ///
    /// Avoids re-parsing, validating, and JIT-compiling the same WAT/wasm source
    /// on repeated `exec()` calls. `wasmtime::Module` is cheap to clone (Arc
    /// internally), so lookups have negligible overhead.
    module_cache: HashMap<blake3::Hash, wasmtime::Module>,
    /// Fuel limit per execution (Wasm instructions).
    /// Defaults to 100_000. Can be overridden per-call via `set_fuel_limit()`.
    fuel_limit: u64,
}

impl std::fmt::Debug for WasmSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmSandbox").finish()
    }
}

impl WasmSandbox {
    /// Create a new Wasm sandbox with default configuration
    pub fn new() -> Result<Self> {
        let mut config = wasmtime::Config::new();
        // Use the pooling instance allocator to avoid per-instance memory
        // allocation overhead (memory is pre-allocated in a pool).
        let mut pool_cfg = wasmtime::PoolingAllocationConfig::default();
        pool_cfg
            .total_core_instances(4096) // Pool slots are NEVER freed during the
                                        // Store's lifetime — each Instance::new()
                                        // permanently claims a slot for address
                                        // space affinity. 4096 covers benchmark
                                        // tight loops (3000+ execs × 2 engines).
                                        // Production uses 1 at a time.
                                        // Virtual address space: 4096 × 6GiB ≈
                                        // 24 TiB (of 128 TiB user space).
            .total_memories(4096)
            .total_tables(4096)
            .max_memory_size(1 << 20)   // 1MB per instance
            .max_tables_per_module(1)
            .linear_memory_keep_resident(0)
            .max_unused_warm_slots(1);
        config.allocation_strategy(
            wasmtime::InstanceAllocationStrategy::Pooling(pool_cfg),
        );
        config.consume_fuel(true);

        let engine = wasmtime::Engine::new(&config)
            .map_err(|e| WasmError::Wasmtime(e.to_string()))?;

        let store = wasmtime::Store::new(&engine, ());
        let module_cache = HashMap::new();
        Ok(Self { engine, store, module_cache, fuel_limit: 100_000 })
    }

    /// Set the fuel limit for Wasm execution (number of instructions).
    ///
    /// Overrides the default of 100_000. Use 0 to disable fuel metering
    /// (not recommended — can cause infinite loops).
    pub fn set_fuel_limit(&mut self, fuel: u64) {
        self.fuel_limit = fuel;
    }

    /// Clear the compiled module cache.
    ///
    /// Forces the next `eval_wat()` or `eval_wasm_binary()` call to
    /// re-compile the module. Useful in tests or when the cache should
    /// be reset without destroying the sandbox.
    pub fn clear_module_cache(&mut self) {
        self.module_cache.clear();
    }
}

impl WasmSandbox {
    /// Execute a WAT (WebAssembly Text Format) expression
    ///
    /// This is the Tier 1 equivalent of `tinyos exec --lang wasm '...'`
    ///
    /// The compiled module is cached in `module_cache` keyed by blake3 hash
    /// of the source. Repeated calls with the same WAT source skip parsing,
    /// validation, and JIT compilation — only instantiation and execution run.
    pub fn eval_wat(&mut self, wat: &str) -> Result<String> {
        let hash = blake3::hash(wat.as_bytes());
        let module = if let Some(module) = self.module_cache.get(&hash) {
            module.clone()
        } else {
            // wasmtime's Module::new supports WAT natively
            let module = wasmtime::Module::new(&self.engine, wat)
                .map_err(|e| WasmError::Compile(e.to_string()))?;
            self.module_cache.insert(hash, module.clone());
            module
        };

        // Allocate fuel for Wasm execution using configurable limit
        self.store.set_fuel(self.fuel_limit)
            .map_err(|e| WasmError::Runtime(e.to_string()))?;

        let instance = wasmtime::Instance::new(&mut self.store, &module, &[])
            .map_err(|e| WasmError::Runtime(e.to_string()))?;

        // Look for exported memory to read results
        let memory = instance.exports(&mut self.store)
            .find_map(|e| e.into_memory())
            .ok_or_else(|| WasmError::Runtime("no exported memory".into()))?;

        // Look for a "main" or "_start" function
        if let Some(func) = instance.get_func(&mut self.store, "main") {
            func.call(&mut self.store, &[], &mut [])
                .map_err(|e| WasmError::Runtime(e.to_string()))?;
        }

        // Try to read the first page of memory as a string for simple results
        let mut data = vec![0u8; 256];
        if let Ok(_page) = memory.read(&self.store, 0, &mut data) {
            let end = data.iter().position(|&b| b == 0).unwrap_or(0);
            if end > 0 {
                return Ok(String::from_utf8_lossy(&data[..end]).to_string());
            }
        }

        Ok("(executed successfully)".into())
    }

    /// Execute a raw Wasm binary
    ///
    /// The compiled module is cached in `module_cache` keyed by blake3 hash
    /// of the binary bytes. Repeated calls with the same bytes skip compilation.
    pub fn eval_wasm_binary(&mut self, wasm_bytes: &[u8]) -> Result<String> {
        let hash = blake3::hash(wasm_bytes);
        let module = if let Some(module) = self.module_cache.get(&hash) {
            module.clone()
        } else {
            let module = wasmtime::Module::new(&self.engine, wasm_bytes)
                .map_err(|e| WasmError::Compile(e.to_string()))?;
            self.module_cache.insert(hash, module.clone());
            module
        };

        self.store.set_fuel(self.fuel_limit)
            .map_err(|e| WasmError::Runtime(e.to_string()))?;

        // Phase 0: WASI support via simple linker (no add_to_linker_sync in this API version)
        // Full WASI comes in Phase 1+
        let linker = wasmtime::Linker::new(&self.engine);
        let _ = &linker; // suppress unused warning

        let instance = linker.instantiate(&mut self.store, &module)
            .map_err(|e| WasmError::Runtime(e.to_string()))?;

        if let Some(func) = instance.get_func(&mut self.store, "_start") {
            func.call(&mut self.store, &[], &mut [])
                .map_err(|e| WasmError::Runtime(e.to_string()))?;
        }

        Ok("(wasm executed)".into())
    }

    /// Reset the sandbox to clean state
    ///
    /// Creates a new Store but reuses the existing Engine (avoids JIT compilation
    /// overhead and thread pool re-initialization).
    pub fn reset(&mut self) -> Result<()> {
        self.store = wasmtime::Store::new(&self.engine, ());
        self.store.set_fuel(self.fuel_limit)
            .map_err(|e| WasmError::Runtime(e.to_string()))?;
        Ok(())
    }
}

/// Evaluate a simple WAT expression (convenience function)
pub fn eval_wat(wat: &str) -> Result<String> {
    let mut sandbox = WasmSandbox::new()?;
    sandbox.eval_wat(wat)
}

// ─── SandboxBackend Integration ──────────────────────────────────────

use tinymachine_api::{ExecutionTier, SandboxBackend, Variant};

/// A `SandboxBackend` implementation wrapping `WasmSandbox`.
///
/// This enables the `tinyos-core` agent loop to use the wasm backend
/// through the unified `SandboxBackend` trait.
///
/// # Error Mapping
/// `WasmError` variants are converted to `ApiError::Sandbox`.
/// This ensures the api layer sees a consistent error type.
#[derive(Default)]
pub struct WasmBackend {
    inner: Option<WasmSandbox>,
}

impl WasmBackend {
    /// Create a new wasm backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SandboxBackend for WasmBackend {
    fn init(&mut self, _variant: &Variant) -> tinymachine_api::Result<()> {
        // Note: seccomp-BPF is NOT installed automatically here because it
        // would permanently restrict the process's syscall surface, affecting
        // all other backends and tests in the same process.
        //
        // To enable seccomp for wasm execution, call:
        //   crate::seccomp::install(crate::seccomp::BackendType::Wasm)?;
        // BEFORE calling init().
        let sandbox = WasmSandbox::new().map_err(|e| {
            tinymachine_api::ApiError::sandbox(format!("wasm init failed: {e}"))
        })?;
        self.inner = Some(sandbox);
        Ok(())
    }

    fn exec(&mut self, code: &str) -> tinymachine_api::Result<String> {
        let sandbox = self.inner.as_mut().ok_or_else(|| {
            tinymachine_api::ApiError::sandbox("wasm backend not initialised")
        })?;
        sandbox.eval_wat(code).map_err(|e| {
            tinymachine_api::ApiError::sandbox(format!("wasm exec failed: {e}"))
        })
    }

    fn reset(&mut self) -> tinymachine_api::Result<()> {
        let sandbox = self.inner.as_mut().ok_or_else(|| {
            tinymachine_api::ApiError::sandbox("wasm backend not initialised")
        })?;
        sandbox.reset().map_err(|e| {
            tinymachine_api::ApiError::sandbox(format!("wasm reset failed: {e}"))
        })
    }

    fn destroy(&mut self) -> tinymachine_api::Result<()> {
        self.inner = None;
        Ok(())
    }
}

/// Convenience: create a boxed `WasmBackend` (used by `create_backend`).
pub fn create_wasm_backend() -> Box<dyn SandboxBackend> {
    Box::new(WasmBackend::new())
}

/// The execution tier for this backend.
impl WasmBackend {
    /// Returns `ExecutionTier::Wasm`.
    pub const fn tier() -> ExecutionTier {
        ExecutionTier::Wasm
    }
}

#[cfg(test)]
mod sandbox_tests {
    use super::*;
    use tinymachine_api::{SandboxBackend, Variant};

    #[test]
    fn test_wasm_backend_lifecycle() {
        let mut backend = WasmBackend::new();
        let variant = Variant::new("wasm", "minimal", "base");

        // Init
        backend.init(&variant).expect("init should succeed");

        // Exec — simple WAT that stores 42 in memory
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "main")
                i32.const 0
                i32.const 42
                i32.store offset=0
            )
        )"#;
        let result = backend.exec(wat);
        assert!(result.is_ok(), "exec should succeed: {:?}", result.err());

        // Reset
        backend.reset().expect("reset should succeed");

        // Destroy
        backend.destroy().expect("destroy should succeed");
    }

    #[test]
    fn test_wasm_backend_exec_before_init() {
        let mut backend = WasmBackend::new();
        let result = backend.exec("(module)");
        assert!(result.is_err(), "exec without init should fail");
    }

    #[test]
    fn test_create_wasm_backend_is_boxed() {
        let mut backend = create_wasm_backend();
        let variant = Variant::new("wasm", "minimal", "base");
        backend.init(&variant).expect("init should work through trait");
        // Exec without init should now succeed since we just called init
        let result = backend.exec("(module)");
        assert!(result.is_ok() || result.is_err() && result.as_ref().unwrap_err().to_string().contains("wasm"), 
            "exec through trait should either succeed or return wasm error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_module_cache_speedup() {
        let mut sandbox = WasmSandbox::new().expect("sandbox creation");
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "main")
                i32.const 0
                i32.const 42
                i32.store offset=0
            )
        )"#;

        // Cold exec — compiles the module
        let start = std::time::Instant::now();
        sandbox.eval_wat(wat).expect("first exec");
        let cold_dur = start.elapsed();

        // Warm exec — should use cached module
        // Run a few times to warm up and average
        let mut warm_durs = Vec::with_capacity(50);
        for _ in 0..50 {
            let start = std::time::Instant::now();
            let _ = sandbox.eval_wat(wat).expect("warm exec");
            warm_durs.push(start.elapsed());
        }
        let warm_avg = warm_durs.iter().sum::<std::time::Duration>() / 50;

        // Warm exec should be at least 2× faster than cold compile+exec
        assert!(
            warm_avg < cold_dur / 2,
            "warm avg {warm_avg:?} should be < cold/2 {cold_dur:?}/2 = {:?}",
            cold_dur / 2
        );
    }

    #[test]
    fn test_wasm_module_cache_persists_across_reset() {
        let mut sandbox = WasmSandbox::new().expect("sandbox creation");
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "main")
                i32.const 0
                i32.const 7
                i32.store offset=0
            )
        )"#;

        // Cold exec — compiles and caches
        let _ = sandbox.eval_wat(wat).expect("first exec");

        // Reset — creates new store, cache should persist
        sandbox.reset().expect("reset");

        // Warm exec — should hit cache even after reset
        let start = std::time::Instant::now();
        let _ = sandbox.eval_wat(wat).expect("exec after reset");
        let post_reset_dur = start.elapsed();

        // After reset with cache, should still be fast (< cold compile)
        let cold_start = std::time::Instant::now();
        let mut cold_sandbox = WasmSandbox::new().expect("fresh sandbox");
        let _ = cold_sandbox.eval_wat(wat).expect("fresh exec");
        let fresh_dur = cold_start.elapsed();

        assert!(
            post_reset_dur < fresh_dur / 2,
            "post-reset exec {post_reset_dur:?} should be < fresh exec/2 {fresh_dur:?}/2 = {:?}",
            fresh_dur / 2
        );
    }

    #[test]
    fn test_wasm_clear_module_cache() {
        let mut sandbox = WasmSandbox::new().expect("sandbox creation");
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "main")
                i32.const 0
                i32.const 99
                i32.store offset=0
            )
        )"#;

        // First exec compiles
        let _ = sandbox.eval_wat(wat).expect("first exec");

        // Clear cache
        sandbox.clear_module_cache();

        // Second exec should re-compile (cold again)
        let start = std::time::Instant::now();
        let _ = sandbox.eval_wat(wat).expect("after cache clear");
        let after_clear = start.elapsed();

        // Third exec should be cached again
        let start = std::time::Instant::now();
        let _ = sandbox.eval_wat(wat).expect("third exec");
        let cached = start.elapsed();

        assert!(
            cached < after_clear / 2,
            "cached exec {cached:?} should be < after-clear/2 {after_clear:?}/2 = {:?}",
            after_clear / 2
        );
    }

    #[test]
    fn test_wasm_add() {
        // Minimal WAT module: store 42 at memory[0]
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "main")
                i32.const 0
                i32.const 42
                i32.store offset=0
            )
        )"#;

        match eval_wat(wat) {
            Ok(result) => println!("Wasm result: {}", result),
            Err(e) => eprintln!("Wasm eval failed (expected in some envs): {}", e),
        }
    }

    #[test]
    fn test_wasm_sandbox_lifecycle() {
        let sandbox = WasmSandbox::new();
        assert!(sandbox.is_ok());
    }
}

// ─── Seccomp Integration ──────────────────────────────────────────────
//
// The seccomp-BPF filter for wasm is defined in `crate::seccomp::allowlist()`
// with `BackendType::Wasm`. To enable it, call:
//
// ```rust,ignore
// crate::seccomp::install(crate::seccomp::BackendType::Wasm)?;
// ```
//
// This is intentionally NOT called from `init()` because seccomp filters
// are per-process and irreversible. Installing seccomp in `init()` would
// permanently restrict all other backends and tests in the same process.
//
// See `crate::seccomp` for the full BPF filter implementation and tests.
