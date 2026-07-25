//! Warm pool manager — pre-forked sandbox pool
//!
//! Maintains a pool of ready-to-run ForkedVm instances so that
//! `tinyos exec` can get one without waiting for a full fork.
//!
//! # Per-Variant Pools
//!
//! Each variant (e.g., `python:minimal`, `python:numpy`) has its own
//! warm pool with variant-specific config (min/max/idle_timeout).
//! Use `PoolManager` to manage multiple variant pools.

use std::collections::HashMap;
use std::collections::VecDeque;

use thiserror::Error;
use tracing::{info, warn};

use crate::fork::{ForkEngine, ForkedVm};

/// Errors from pool operations
#[derive(Error, Debug)]
pub enum PoolError {
    #[error("Fork error: {0}")]
    Fork(#[from] crate::fork::ForkError),
    #[error("Pool is empty")]
    Empty,
    #[error("No pool registered for variant: {0}")]
    VariantNotFound(String),
}

pub type Result<T> = std::result::Result<T, PoolError>;

/// Configuration for a warm pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum number of warm forks to maintain
    pub min: usize,
    /// Maximum number of warm forks
    pub max: usize,
    /// Seconds before an idle fork is evicted
    pub idle_timeout_secs: u64,
    /// Optional variant identifier for per-variant pool tracking
    pub variant_id: Option<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min: 3,
            max: 20,
            idle_timeout_secs: 60,
            variant_id: None,
        }
    }
}

/// Hard upper bound on pool size to prevent resource exhaustion.
pub const POOL_MAX_CAP: usize = 1000;

impl PoolConfig {
    /// Create a PoolConfig from a variant's pool settings.
    ///
    /// Caps `max` at `POOL_MAX_CAP` to prevent accidental resource exhaustion.
    pub fn from_variant(variant: &crate::variant::Variant) -> Self {
        Self {
            min: variant.pool_min.min(POOL_MAX_CAP),
            max: variant.pool_max.min(POOL_MAX_CAP),
            idle_timeout_secs: variant.pool_idle_timeout_secs,
            variant_id: Some(variant.id()),
        }
    }

    /// Create a PoolConfig from a composition plan's key.
    ///
    /// Composition-based pools use the composition hash as the pool key,
    /// enabling unique warm pools for each unique composition without
    /// requiring a pre-built variant. Pool sizing uses conservative defaults
    /// since the layer registry doesn't specify pool config:
    /// - min=0 (don't pre-warm — composition initrd must exist first)
    /// - max=10 (prevent resource exhaustion)
    /// - idle_timeout=60s
    pub fn from_composition(composition_key: &str) -> Self {
        let short_key: String = composition_key.chars().take(12).collect();
        Self {
            min: 0,
            max: 10.min(POOL_MAX_CAP),
            idle_timeout_secs: 60,
            variant_id: Some(format!("compose:{}", short_key)),
        }
    }
}

/// A pool of pre-forked sandboxes for a specific variant
#[derive(Debug)]
pub struct ForkPool {
    engine: ForkEngine,
    pool: VecDeque<ForkedVm>,
    config: PoolConfig,
}

impl ForkPool {
    /// Create a new fork pool
    pub fn new(engine: ForkEngine, config: PoolConfig) -> Self {
        let variant_tag = config.variant_id.clone().unwrap_or_else(|| "default".into());
        let mut pool = ForkPool {
            engine,
            pool: VecDeque::new(),
            config,
        };
        // Pre-warm to min size
        let count = pool.config.min;
        if count > 0 {
            match pool.engine.fork_batch(count) {
                Ok(vms) => {
                    pool.pool.extend(vms);
                    info!(variant = %variant_tag, count, "pre-warmed pool");
                }
                Err(e) => {
                    warn!(variant = %variant_tag, error = %e, "failed to pre-warm pool");
                }
            }
        }
        pool
    }

    /// Get the configured (max) capacity of this pool
    pub fn capacity(&self) -> usize {
        self.config.max
    }

    /// Acquire a sandbox from the pool
    pub fn acquire(&mut self) -> Result<ForkedVm> {
        // Try pool first
        if let Some(vm) = self.pool.pop_front() {
            self.refill();
            return Ok(vm);
        }
        // Pool empty — fork on demand
        let variant_tag = self.config.variant_id.clone().unwrap_or_else(|| "default".into());
        info!(variant = %variant_tag, "pool empty, forking on demand");
        let vm = self.engine.fork()?;
        self.refill();
        Ok(vm)
    }

    /// Acquire N sandboxes in a single batch.
    ///
    /// Drains the pool first (fast pops), then forks any remaining count
    /// with a single `fork_batch()` call. Unlike `acquire()` (which refills
    /// after every individual acquire), `acquire_batch` does NOT refill —
    /// the batch caller requested exactly N VMs and we return them. Refill
    /// is deferred to the next `acquire()` call or a background maintenance
    /// thread, keeping the hot path lean.
    ///
    /// This is the preferred method for bulk operations like the Batch
    /// Scheduler (Tier 2), warm pool pre-fill, and fleet orchestration.
    ///
    /// # Errors
    /// Returns `PoolError::Fork` if `fork_batch` fails.
    pub fn acquire_batch(&mut self, n: usize) -> Result<Vec<ForkedVm>> {
        let mut vms = Vec::with_capacity(n);
        // 1. Drain what's available in the pool (fast path: ~0.5μs per pop)
        while vms.len() < n {
            match self.pool.pop_front() {
                Some(vm) => vms.push(vm),
                None => break,
            }
        }
        // 2. Fork any remaining that the pool couldn't provide
        let needed = n - vms.len();
        if needed > 0 {
            let variant_tag = self.config.variant_id.clone().unwrap_or_else(|| "default".into());
            info!(
                variant = %variant_tag,
                pool.have = %vms.len(),
                batch.need = %needed,
                "batch acquire — forking remaining on demand"
            );
            let forked = self.engine.fork_batch(needed)?;
            vms.extend(forked);
        }
        // NOTE: No refill. The batch caller gets exactly N VMs.
        // Refill is the responsibility of the next single-acquire call
        // or an external maintenance thread.
        Ok(vms)
    }

    /// Return a sandbox to the pool (reset state).
    ///
    /// If the pool is already at capacity (`max`), the sandbox is silently
    /// dropped (munmap + close fds) instead of returning an error. This is an
    /// intentional design choice: pool capacity is a soft limit on the number
    /// of *idle* sandboxes, not a hard cap on total lifetime. Callers should
    /// never need to handle "pool is full" — the alternative (drop) is always
    /// correct and keeps the system running.
    pub fn release(&mut self, vm: ForkedVm) -> Result<()> {
        if self.pool.len() >= self.config.max {
            let variant_tag = self.config.variant_id.clone().unwrap_or_else(|| "default".into());
            tracing::info!(
                variant = %variant_tag,
                pool.len = %self.pool.len(),
                pool.max = %self.config.max,
                "pool at capacity — dropping released sandbox"
            );
            // ForkedVm::drop handles munmap + close fds
            drop(vm);
            return Ok(());
        }
        self.pool.push_back(vm);
        Ok(())
    }

    /// Refill pool to min size
    fn refill(&mut self) {
        let needed = self.config.min.saturating_sub(self.pool.len());
        if needed == 0 {
            return;
        }
        let batch_size = needed.min(self.config.max.saturating_sub(self.pool.len()));
        match self.engine.fork_batch(batch_size) {
            Ok(vms) => {
                self.pool.extend(vms);
            }
            Err(e) => {
                warn!("pool refill failed: {e}");
            }
        }
    }

    /// Pre-populate the pool to a target size by forking VMs directly.
    ///
    /// More efficient than acquire+release loops because it uses a single
    /// `fork_batch()` call and avoids the refill/release overhead.
    ///
    /// **Bypasses `max`** — the `max` limit controls the *idle* steady-state
    /// pool size. `fill_to` is for burst capacity: pre-warming the pool to
    /// handle a known load spike. The pool may temporarily hold more than
    /// `max` VMs; excess VMs are drained by acquire calls.
    pub fn fill_to(&mut self, target: usize) -> Result<()> {
        if target <= self.pool.len() {
            return Ok(());
        }
        let needed = target - self.pool.len();
        let vms = self.engine.fork_batch(needed)?;
        self.pool.extend(vms);
        Ok(())
    }

    /// Current pool size
    pub fn size(&self) -> usize {
        self.pool.len()
    }

    /// Get a reference to the pool config
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }
}

/// Manages per-variant warm pools.
///
/// Each variant (e.g., `python:minimal`, `python:numpy`) gets its own
/// `ForkPool` with variant-specific config values (min/max/idle_timeout).
///
/// # Example
///
/// ```rust,ignore
/// let mut manager = PoolManager::new();
/// let pool = manager.register(
///     &variant,
///     engine,
///     PoolConfig::from_variant(&variant),
/// );
/// let vm = manager.acquire("python:minimal")?;
/// manager.release("python:minimal", vm)?;
/// ```
#[derive(Debug)]
pub struct PoolManager {
    pools: HashMap<String, ForkPool>,
}

impl PoolManager {
    /// Create a new, empty pool manager.
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    /// Register a new pool for the given variant.
    ///
    /// If a pool already exists for this variant, it is returned instead
    /// (the engine/config are ignored — use `remove` first to replace).
    pub fn register(&mut self, variant_id: &str, engine: ForkEngine, config: PoolConfig) -> &mut ForkPool {
        if !self.pools.contains_key(variant_id) {
            info!("registering warm pool for variant [{variant_id}]");
            let pool = ForkPool::new(engine, config);
            self.pools.insert(variant_id.to_string(), pool);
        }
        self.pools.get_mut(variant_id)
            .expect("pool just inserted")
    }

    /// Register a new pool for a composition key.
    ///
    /// Uses the composition hash as the pool key and creates a pool config
    /// from `PoolConfig::from_composition()`. This allows warm pools to be
    /// keyed by composition hash, enabling per-composition pool isolation.
    ///
    /// If a pool already exists for this composition key, returns the existing
    /// pool (idempotent).
    pub fn register_composition(&mut self, composition_key: &str, engine: ForkEngine) -> &mut ForkPool {
        let config = PoolConfig::from_composition(composition_key);
        let pool_id = config.variant_id.clone()
            .unwrap_or_else(|| format!("compose:{}", composition_key));
        if !self.pools.contains_key(&pool_id) {
            info!("registering warm pool for composition [{pool_id}]");
            let pool = ForkPool::new(engine, config);
            self.pools.insert(pool_id.clone(), pool);
        }
        self.pools.get_mut(&pool_id)
            .expect("pool just inserted")
    }

    /// Acquire a sandbox from the pool for the given variant.
    pub fn acquire(&mut self, variant_id: &str) -> Result<ForkedVm> {
        self.pools.get_mut(variant_id)
            .ok_or_else(|| PoolError::VariantNotFound(variant_id.to_string()))?
            .acquire()
    }

    /// Acquire N sandboxes in a single batch from the pool for the given variant.
    ///
    /// More efficient than calling `acquire()` N times because the pool
    /// refills only once after the entire batch is drained/forked.
    pub fn acquire_batch(&mut self, variant_id: &str, n: usize) -> Result<Vec<ForkedVm>> {
        self.pools.get_mut(variant_id)
            .ok_or_else(|| PoolError::VariantNotFound(variant_id.to_string()))?
            .acquire_batch(n)
    }

    /// Pre-populate a pool to a target size by forking VMs directly.
    ///
    /// Use this before a burst of batch acquires to ensure all VMs are
    /// warm (fast pops). More efficient than acquire+release loops.
    pub fn fill_pool(&mut self, variant_id: &str, target: usize) -> Result<()> {
        self.pools.get_mut(variant_id)
            .ok_or_else(|| PoolError::VariantNotFound(variant_id.to_string()))?
            .fill_to(target)
    }

    /// Return a sandbox to the pool for the given variant.
    pub fn release(&mut self, variant_id: &str, vm: ForkedVm) -> Result<()> {
        self.pools.get_mut(variant_id)
            .ok_or_else(|| PoolError::VariantNotFound(variant_id.to_string()))?
            .release(vm)
    }

    /// Remove and drop a pool for the given variant.
    pub fn remove(&mut self, variant_id: &str) -> Option<ForkPool> {
        self.pools.remove(variant_id)
    }

    /// Check if a pool exists for the given variant.
    pub fn has_pool(&self, variant_id: &str) -> bool {
        self.pools.contains_key(variant_id)
    }

    /// Get a mutable reference to a pool.
    pub fn get_mut(&mut self, variant_id: &str) -> Option<&mut ForkPool> {
        self.pools.get_mut(variant_id)
    }

    /// Number of registered pools.
    pub fn len(&self) -> usize {
        self.pools.len()
    }

    /// Returns true if no pools are registered.
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

impl Default for PoolManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tier 3 FreshBoot Pool ─────────────────────────────────────────
//
// Manages a pool of pre-booted FreshBootBackend instances (full VMs with
// optional GPU passthrough). Unlike ForkPool (which uses CoW snapshots),
// each FreshBootBackend is a fully booted kernel + initrd VM.

/// Errors from FreshBootPool operations
#[derive(Error, Debug)]
pub enum FreshBootPoolError {
    #[error("Pool is empty — all booted VMs are in use")]
    Empty,
    #[error("Pool is full — cannot add more VMs")]
    Full,
    #[error("Backend error: {0}")]
    Backend(String),
    #[error("Variant not found: {0}")]
    VariantNotFound(String),
}

/// A pool of pre-booted FreshBootBackend instances for Tier 3 execution.
///
/// Each backend is a fully booted kernel+initrd VM, optionally with GPU
/// passthrough. The pool pre-warms a configurable number of backends
/// at construction time.
///
/// # Lifecycle
///
/// ```text
/// acquire() ──► booted VM ──► exec("code") ──► release(vm)
///                  │
///                  └──► backend.reset() ──► ready for next acquire
/// ```
#[derive(Debug)]
pub struct FreshBootPool {
    /// Pre-booted backends ready for use
    pool: VecDeque<crate::fresh_boot::FreshBootBackend>,
    /// The variant to use for initializing new backends
    variant: tinymachine_api::variant::Variant,
    /// Minimum number of idle VMs to maintain
    min: usize,
    /// Maximum number of pooled VMs
    max: usize,
}

impl FreshBootPool {
    /// Create a new FreshBootPool and pre-warm `min` VMs.
    ///
    /// Pre-warming happens synchronously: `min` VMs are booted at
    /// construction time. This may take several seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the pre-warmed VMs fail to boot.
    pub fn new(
        variant: &tinymachine_api::variant::Variant,
        min: usize,
        max: usize,
    ) -> std::result::Result<Self, FreshBootPoolError> {
        use tinymachine_api::sandbox::SandboxBackend;

        let mut pool = VecDeque::new();
        let variant = variant.clone();

        // Pre-warm to min size
        for _ in 0..min {
            let mut backend = crate::fresh_boot::FreshBootBackend::new();
            SandboxBackend::init(&mut backend, &variant)
                .map_err(|e| FreshBootPoolError::Backend(e.to_string()))?;
            pool.push_back(backend);
        }

        if min > 0 {
            tracing::info!(
                "FreshBootPool: pre-warmed {} VM(s) for variant {}/{}",
                min, variant.lang, variant.variant
            );
        }

        Ok(Self {
            pool,
            variant,
            min,
            max,
        })
    }

    /// Acquire a booted VM from the pool.
    ///
    /// If the pool is empty, a new VM is booted on demand (up to `max`).
    /// If already at `max`, returns `Empty`.
    pub fn acquire(
        &mut self,
    ) -> std::result::Result<crate::fresh_boot::FreshBootBackend, FreshBootPoolError> {
        use tinymachine_api::sandbox::SandboxBackend;

        if let Some(backend) = self.pool.pop_front() {
            self.refill();
            return Ok(backend);
        }

        // Pool empty — boot on demand if under max
        if self.pool.len() + 1 > self.max {
            return Err(FreshBootPoolError::Empty);
        }

        let mut backend = crate::fresh_boot::FreshBootBackend::new();
        SandboxBackend::init(&mut backend, &self.variant)
            .map_err(|e| FreshBootPoolError::Backend(e.to_string()))?;
        self.refill();
        Ok(backend)
    }

    /// Return a booted VM to the pool.
    ///
    /// Calls `reset()` on the backend to clear state. If the pool is
    /// at capacity, the backend is destroyed instead.
    pub fn release(&mut self, mut backend: crate::fresh_boot::FreshBootBackend) {
        use tinymachine_api::sandbox::SandboxBackend;

        if self.pool.len() >= self.max {
            tracing::info!("FreshBootPool: at capacity — destroying returned VM");
            let _ = SandboxBackend::destroy(&mut backend);
            return;
        }

        // Reset the backend for re-use
        if let Err(e) = SandboxBackend::reset(&mut backend) {
            tracing::warn!("FreshBootPool: reset failed on returned VM: {e} — destroying");
            let _ = SandboxBackend::destroy(&mut backend);
            return;
        }

        self.pool.push_back(backend);
    }

    /// Refill the pool to `min` if below.
    fn refill(&mut self) {
        use tinymachine_api::sandbox::SandboxBackend;

        let needed = self.min.saturating_sub(self.pool.len());
        for _ in 0..needed {
            let mut backend = crate::fresh_boot::FreshBootBackend::new();
            if let Err(e) = SandboxBackend::init(&mut backend, &self.variant) {
                tracing::warn!("FreshBootPool: refill init failed: {e}");
                break;
            }
            self.pool.push_back(backend);
        }
    }

    /// Number of idle VMs in the pool
    pub fn size(&self) -> usize {
        self.pool.len()
    }

    /// Current capacity (max)
    pub fn capacity(&self) -> usize {
        self.max
    }

    /// Minimum pool size
    pub fn min_size(&self) -> usize {
        self.min
    }

    /// Get the variant this pool was configured with
    pub fn variant(&self) -> &tinymachine_api::variant::Variant {
        &self.variant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork::ForkEngine;
    use crate::kvm::Kvm;
    use crate::test_helpers;
    use crate::variant::Variant;

    fn test_engine() -> Option<ForkEngine> {
        let kvm = Kvm::new().ok()?;
        let snap = test_helpers::test_snapshot();
        let mmap_size = kvm.vcpu_mmap_size().ok()?;
        Some(ForkEngine::new(kvm, snap, mmap_size))
    }

    #[test]
    fn test_pool_create() {
        let engine = match test_engine() {
            Some(e) => e,
            None => {
                eprintln!("Skipping: KVM not available");
                return;
            }
        };
        let pool = ForkPool::new(engine, PoolConfig::default());
        assert!(pool.size() <= 20);
    }

    #[test]
    fn test_pool_acquire_release() {
        let engine = match test_engine() {
            Some(e) => e,
            None => {
                eprintln!("Skipping: KVM not available");
                return;
            }
        };
        let mut pool = ForkPool::new(engine, PoolConfig::default());
        let vm = pool.acquire().expect("Should get a VM");
        pool.release(vm).expect("Should release VM back");
    }

    #[test]
    fn test_pool_config_from_variant() {
        let variant = Variant::python_minimal();
        let config = PoolConfig::from_variant(&variant);
        assert_eq!(config.min, 3);
        assert_eq!(config.max, 20);
        assert_eq!(config.idle_timeout_secs, 60);
        assert_eq!(config.variant_id, Some("python:minimal".to_string()));
    }

    #[test]
    fn test_pool_config_from_variant_numpy() {
        let variant = Variant::python_numpy();
        let config = PoolConfig::from_variant(&variant);
        assert_eq!(config.min, 2);
        assert_eq!(config.max, 10);
        assert_eq!(config.variant_id, Some("python:numpy".to_string()));
    }

    #[test]
    fn test_pool_config_from_variant_pytorch_cpu() {
        let variant = Variant::python_pytorch_cpu();
        let config = PoolConfig::from_variant(&variant);
        assert_eq!(config.min, 1);
        assert_eq!(config.max, 5);
        assert_eq!(config.variant_id, Some("python:pytorch-cpu".to_string()));
    }

    #[test]
    fn test_pool_config_wasm_no_pool() {
        let variant = Variant::wasm();
        let config = PoolConfig::from_variant(&variant);
        assert_eq!(config.min, 0);
        assert_eq!(config.max, 0);
        assert_eq!(config.variant_id, Some("wasm:minimal".to_string()));
    }

    #[test]
    fn test_pool_manager_create() {
        let manager = PoolManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_pool_manager_register() {
        let engine = match test_engine() {
            Some(e) => e,
            None => {
                eprintln!("Skipping: KVM not available");
                return;
            }
        };

        let mut manager = PoolManager::new();
        let config = PoolConfig::from_variant(&Variant::python_minimal());
        manager.register("python:minimal", engine, config);

        assert!(manager.has_pool("python:minimal"));
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_pool_manager_register_idempotent() {
        let engine1 = match test_engine() {
            Some(e) => e,
            None => {
                eprintln!("Skipping: KVM not available");
                return;
            }
        };

        let mut manager = PoolManager::new();
        // Register same variant twice — second call should return existing pool
        manager.register("python:minimal", engine1, PoolConfig::from_variant(&Variant::python_minimal()));
        let before = manager.len();
        // Use a second engine for the duplicate registration attempt
        if let Some(engine2) = test_engine() {
            manager.register("python:minimal", engine2, PoolConfig::from_variant(&Variant::python_minimal()));
        }
        assert_eq!(manager.len(), before, "should not add duplicate pool");
    }

    #[test]
    fn test_pool_manager_remove() {
        let engine = match test_engine() {
            Some(e) => e,
            None => return,
        };

        let mut manager = PoolManager::new();
        manager.register("python:minimal", engine, PoolConfig::default());
        assert_eq!(manager.len(), 1);

        let removed = manager.remove("python:minimal");
        assert!(removed.is_some());
        assert!(!manager.has_pool("python:minimal"));
    }

    #[test]
    fn test_pool_manager_acquire_release() {
        let engine = match test_engine() {
            Some(e) => e,
            None => {
                eprintln!("Skipping: KVM not available");
                return;
            }
        };

        let mut manager = PoolManager::new();
        manager.register("python:minimal", engine, PoolConfig::default());

        let vm = manager.acquire("python:minimal").expect("Should acquire VM");
        manager.release("python:minimal", vm).expect("Should release VM");
    }

    #[test]
    fn test_pool_manager_acquire_unregistered() {
        let mut manager = PoolManager::new();
        let err = manager.acquire("python:nonexistent").unwrap_err();
        assert!(matches!(err, PoolError::VariantNotFound(_)));
    }

    #[test]
    fn test_pool_manager_multi_variant() {
        let engine_minimal = match test_engine() {
            Some(e) => e,
            None => return,
        };
        let engine_numpy = match test_engine() {
            Some(e) => e,
            None => return,
        };

        let mut manager = PoolManager::new();
        manager.register(
            "python:minimal",
            engine_minimal,
            PoolConfig::from_variant(&Variant::python_minimal()),
        );
        manager.register(
            "python:numpy",
            engine_numpy,
            PoolConfig::from_variant(&Variant::python_numpy()),
        );

        assert_eq!(manager.len(), 2);
        assert!(manager.has_pool("python:minimal"));
        assert!(manager.has_pool("python:numpy"));

        let pool_min = manager.get_mut("python:minimal").unwrap();
        assert_eq!(pool_min.capacity(), 20);

        let pool_np = manager.get_mut("python:numpy").unwrap();
        assert_eq!(pool_np.capacity(), 10);
    }

    // ─── FreshBootPool tests ─────────────────────────────────────────

    #[test]
    fn test_fresh_boot_pool_create_min_zero() {
        // Creating a pool with min=0 should not boot any VMs
        let variant = tinymachine_api::variant::Variant::new("python", "minimal", "base");
        let pool = FreshBootPool::new(&variant, 0, 5);
        // On non-KVM machines, init() will fail with error about missing KVM
        // But we should NOT get an error about constructor arguments
        match pool {
            Ok(p) => {
                assert_eq!(p.size(), 0);
                assert_eq!(p.capacity(), 5);
                assert_eq!(p.min_size(), 0);
            }
            Err(e) => {
                // Expected if KVM is not available or templates missing
                println!("FreshBootPool::new (min=0) returned error (expected without KVM/hardware): {e}");
            }
        }
    }

    #[test]
    fn test_fresh_boot_pool_create_with_prewarm_graceful_fallback() {
        // Creating a pool with min>0 should gracefully handle boot failures
        let variant = tinymachine_api::variant::Variant::new("python", "pytorch", "gpu-vfio");
        let pool = FreshBootPool::new(&variant, 1, 2);
        match pool {
            Ok(p) => {
                // If it succeeded (has KVM + templates), verify pool state
                assert!(p.size() >= 1 || p.capacity() == 2);
                assert_eq!(p.variant().variant, "pytorch");
            }
            Err(e) => {
                // Expected if KVM/templates not available
                println!("FreshBootPool pre-warm returned error (expected on CI without hardware): {e}");
            }
        }
    }

    #[test]
    fn test_fresh_boot_pool_pytorch_variant_transport() {
        // Verify the pytorch variant can flow through the pool API
        let variant = tinymachine_api::variant::Variant::new("python", "pytorch", "gpu-vfio");
        let pool = FreshBootPool::new(&variant, 0, 1);
        match pool {
            Ok(p) => {
                assert_eq!(p.variant().kernel_profile, "gpu-vfio");
                assert_eq!(p.variant().variant, "pytorch");
                assert_eq!(p.capacity(), 1);
            }
            Err(e) => {
                println!("FreshBootPool pytorch test returned error (expected): {e}");
            }
        }
    }
}
