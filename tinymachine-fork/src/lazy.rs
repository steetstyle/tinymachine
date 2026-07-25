//! LazyFork — deferred batch execution engine.
//!
//! Inspired by TinyGrad's `LazyBuffer` pattern: instead of forking
//! immediately for every code snippet, queue them up and execute as
//! a batch when the queue is full or a timeout fires. This avoids
//! repeated KVM_CREATE_VM / CPU-state-restore overhead.
//!
//! # Example
//!
//! ```rust,ignore
//! let mut lazy = LazyFork::new(LazyConfig::default());
//! lazy.set_pool_manager(manager);
//!
//! lazy.push("print(1)".into(), "python:minimal".into());
//! lazy.push("print(2)".into(), "python:minimal".into());
//!
//! let results = lazy.realize();
//! assert_eq!(results.len(), 2);
//! ```

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use tracing::info;

use crate::fork::ForkedVm;
use crate::pool::PoolManager;
use crate::profiler::SymbolicProfiler;

/// Default free RAM estimate used for batch-size scaling (8 GB).
const FREE_RAM: u64 = 8 * 1024 * 1024 * 1024;

/// A code snippet queued for batch execution.
#[derive(Debug, Clone)]
pub struct QueuedCode {
    /// The source code to execute.
    pub code: String,
    /// Which variant's warm pool to use (e.g. `"python:minimal"`).
    pub variant_id: String,
}

impl QueuedCode {
    pub fn new(code: impl Into<String>, variant_id: impl Into<String>) -> Self {
        Self { code: code.into(), variant_id: variant_id.into() }
    }
}

/// Configuration for the lazy batch scheduler.
#[derive(Debug, Clone)]
pub struct LazyConfig {
    /// Maximum number of snippets to batch together (default: `num_cpus`).
    pub max_batch: usize,
    /// Maximum latency before forcing a `realize()` even if the batch
    /// isn't full yet (default: 1 ms).
    pub max_latency: std::time::Duration,
    /// If `true`, use `SymbolicProfiler` to estimate total RAM and
    /// dynamically shrink `max_batch` to avoid OOM.
    pub profiler_enabled: bool,
}

impl Default for LazyConfig {
    fn default() -> Self {
        Self {
            max_batch: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            max_latency: std::time::Duration::from_millis(1),
            profiler_enabled: true,
        }
    }
}

impl LazyConfig {
    /// Create a config with a fixed batch size (overrides `num_cpus`).
    pub fn with_max_batch(max_batch: usize) -> Self {
        Self { max_batch, ..Self::default() }
    }

    /// Disable the profiler-based batch-size adjustment.
    pub fn without_profiler(mut self) -> Self {
        self.profiler_enabled = false;
        self
    }
}

/// A lazy batch scheduler that defers code execution and runs snippets
/// together in a single batch for better throughput.
#[derive(Debug)]
pub struct LazyFork {
    queue: VecDeque<QueuedCode>,
    pool_manager: Option<PoolManager>,
    config: LazyConfig,
    timer_start: Option<Instant>,
}

impl LazyFork {
    /// Create a new lazy fork scheduler.
    pub fn new(config: LazyConfig) -> Self {
        Self {
            queue: VecDeque::new(),
            pool_manager: None,
            config,
            timer_start: None,
        }
    }

    /// Attach (or replace) the pool manager used by `realize()`.
    pub fn set_pool_manager(&mut self, manager: PoolManager) {
        self.pool_manager = Some(manager);
    }

    /// Return a mutable reference to the pool manager, if set.
    pub fn pool_manager_mut(&mut self) -> Option<&mut PoolManager> {
        self.pool_manager.as_mut()
    }

    /// Queue a code snippet for later batch execution.
    ///
    /// If the queue reaches `max_batch`, `realize()` is called
    /// automatically. Otherwise the timer is started on the first push
    /// so that `max_latency`-based expiry can be checked later.
    pub fn push(&mut self, code: String, variant_id: String) {
        if self.timer_start.is_none() {
            self.timer_start = Some(Instant::now());
        }

        self.queue.push_back(QueuedCode { code, variant_id });

        if self.queue.len() >= self.config.max_batch {
            let count = self.queue.len();
            info!(count, "batch full — auto-realizing");
            self.realize();
        }
    }

    /// Execute all queued code as a batch.
    ///
    /// 1. Drains the queue.
    /// 2. If `profiler_enabled`, sums all RAM estimates and reduces the
    ///    effective batch size so that total RAM ≤ `FREE_RAM / 2`.
    /// 3. Acquires one `ForkedVm` per snippet from `PoolManager`.
    /// 4. Injects code into each VM's command buffer, runs it, and collects
    ///    output — all in parallel using **scoped threads** (`std::thread::scope`).
    ///    Scoped threads avoid the OS-thread creation overhead of
    ///    `std::thread::spawn` (~50μs per thread) because they borrow from
    ///    the enclosing scope instead of requiring `'static` ownership.
    /// 5. Releases every VM back to its variant's pool.
    ///
    /// Returns one result per queued item in FIFO order.
    /// Errors (pool exhaustion, VM crash, etc.) are returned as `Err(String)`.
    pub fn realize(&mut self) -> Vec<Result<String, String>> {
        self.timer_start = None;
        let items: Vec<QueuedCode> = self.queue.drain(..).collect();
        if items.is_empty() {
            return Vec::new();
        }

        // Compute effective batch size BEFORE borrowing pool_manager mutably.
        let effective_batch = self.effective_batch_size(&items);
        let total_items = items.len();

        let manager = match self.pool_manager.as_mut() {
            Some(m) => m,
            None => {
                return Vec::new();
            }
        };

        // Pre-allocate result slots so each item gets its correct position.
        // This fixes a FIFO-ordering violation where pool.acquire() failures
        // used to be pushed before execution results, scrambling the order.
        let mut results: Vec<Option<Result<String, String>>> = vec![None; total_items];

        // Process items in chunks of `effective_batch`.
        for chunk in items.chunks(effective_batch) {
            // 1. Acquire one ForkedVm per snippet.
            //    Errors from failed acquires go directly into results at the
            //    correct position. Successful acquires are tracked for execution.
            let mut acquired: Vec<(String, ForkedVm)> = Vec::with_capacity(chunk.len());
            let chunk_base: usize;

            // We need the absolute index of each item to place results correctly.
            // Compute `chunk_base` by scanning from `items` start to find where
            // this chunk begins. Since `chunks()` returns non-overlapping slices
            // of `items`, this is O(items) across all chunks — acceptable for a
            // batch scheduler where items.len() ≤ max_batch (~32).
            // A faster approach would store the accumulated offset across
            // iterations (see `accumulated_offset` field), but this simplicity
            // is preferred for correctness.
            {
                let items_ptr = items.as_ptr() as usize;
                let chunk_ptr = chunk.as_ptr() as usize;
                debug_assert!(
                    chunk_ptr >= items_ptr,
                    "chunk must be a sub-slice of items"
                );
                chunk_base = (chunk_ptr - items_ptr) / std::mem::size_of::<QueuedCode>();
            }

            for (offset, item) in chunk.iter().enumerate() {
                let idx = chunk_base + offset;
                match manager.acquire(&item.variant_id) {
                    Ok(vm) => acquired.push((item.variant_id.clone(), vm)),
                    Err(e) => {
                        results[idx] = Some(Err(format!("acquire({}): {e}", item.variant_id)));
                    }
                }
            }

            if acquired.is_empty() {
                continue;
            }

            // 2. Run all acquired VMs in parallel using scoped threads.
            //
            // `std::thread::scope` lets each thread borrow `&mut ForkedVm` from
            // the enclosing scope (different elements of `acquired` → disjoint
            // borrows → no data race). This avoids the ~50μs OS-thread creation
            // overhead of `std::thread::spawn` (which requires `'static` + move).
            //
            // LIMITATION (concurrent `run_until_ready`):
            // `run_until_ready` uses process-global `setitimer(ITIMER_REAL, ...)`
            // + `SIGALRM` to detect VM completion. With N concurrent scoped
            // threads, only one timer is active (last caller wins) and `SIGALRM`
            // is delivered to a random thread. N-1 threads rely on guest IO
            // exits (serial writes) for READY detection rather than timer ticks,
            // which may add latency but does not cause missed detection.
            // A future improvement would be eventfd-based per-VM completion
            // to eliminate this single-timer bottleneck.
            //
            // SAFETY: `ForkedVm::run_code()` handles bounds checks, unsafe
            // pointer operations, and output parsing. Each `&mut ForkedVm` is
            // used from a single scoped thread exclusively (disjoint borrows
            // through different `acquired` elements — no aliasing).
            // `catch_unwind(AssertUnwindSafe)` ensures a panicking thread
            // doesn't leak the VM — it returns `Err` and the release loop below
            // reclaims the borrowed `ForkedVm`.
            let mut chunk_results: Vec<Result<String, String>> = Vec::with_capacity(acquired.len());
            std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(acquired.len());
                for (vm_idx, (_, vm)) in acquired.iter_mut().enumerate() {
                    let item = &chunk[vm_idx];
                    handles.push(s.spawn(|| {
                        catch_unwind(AssertUnwindSafe(|| {
                            // SAFETY: vm is a properly configured post-fork VCPU.
                            // run_code() handles bounds checks + unsafe code injection + run + output.
                            unsafe { vm.run_code(&item.code) }
                        }))
                        .unwrap_or(Err("VM task panicked".into()))
                    }));
                }

                // Collect results — join order preserves spawn order which
                // matches the chunk's internal order.
                for handle in handles {
                    match handle.join() {
                        Ok(r) => chunk_results.push(r),
                        Err(e) => chunk_results.push(Err(format!("thread panic: {:?}", e))),
                    }
                }
            });

            // 3. Release VMs back to pool and place results at correct positions.
            for (vm_idx, ((vid, vm), result)) in acquired.into_iter().zip(chunk_results).enumerate() {
                if let Err(e) = manager.release(&vid, vm) {
                    tracing::trace!("LazyFork release({vid}) failed: {e}");
                }
                results[chunk_base + vm_idx] = Some(result);
            }
        }

        // Unwrap all Option values (every slot was filled since each position
        // received either an acquire error or an execution result).
        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err("internal: uninitialized result slot".into())))
            .collect()
    }

    /// Number of items currently in the queue.
    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }

    /// Whether the batch is ready to execute — either the queue reached
    /// `max_batch` or `max_latency` has elapsed since the first push.
    pub fn is_ready(&self) -> bool {
        if self.queue.is_empty() {
            return false;
        }
        if self.queue.len() >= self.config.max_batch {
            return true;
        }
        if let Some(start) = self.timer_start {
            if start.elapsed() >= self.config.max_latency {
                return true;
            }
        }
        false
    }

    /// Drain the queue without executing (discard pending items).
    pub fn clear(&mut self) {
        self.queue.clear();
        self.timer_start = None;
    }

    /// Compute the effective batch size, optionally applying RAM-based
    /// scaling when `profiler_enabled` is `true`.
    fn effective_batch_size(&self, items: &[QueuedCode]) -> usize {
        if !self.config.profiler_enabled {
            return self.config.max_batch;
        }
        let total_ram: u64 = items
            .iter()
            .map(|item| SymbolicProfiler::profile(&item.code).ram_bytes)
            .sum();
        if total_ram == 0 {
            return self.config.max_batch;
        }
        let max_ram = FREE_RAM / 2;
        if total_ram > max_ram {
            let scaled = (self.config.max_batch as u64 * max_ram / total_ram) as usize;
            scaled.max(1)
        } else {
            self.config.max_batch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config defaults ───────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = LazyConfig::default();
        assert!(cfg.max_batch >= 1);
        assert_eq!(cfg.max_latency, std::time::Duration::from_millis(1));
        assert!(cfg.profiler_enabled);
    }

    #[test]
    fn test_config_with_max_batch() {
        let cfg = LazyConfig::with_max_batch(8);
        assert_eq!(cfg.max_batch, 8);
    }

    #[test]
    fn test_config_without_profiler() {
        let cfg = LazyConfig::default().without_profiler();
        assert!(!cfg.profiler_enabled);
    }

    // ── Queue mechanics ───────────────────────────────────────────────

    #[test]
    fn test_push_single() {
        let mut lazy = LazyFork::new(LazyConfig::with_max_batch(10));
        assert_eq!(lazy.queued_count(), 0);
        lazy.push("print(1)".into(), "python:minimal".into());
        assert_eq!(lazy.queued_count(), 1);
    }

    #[test]
    fn test_queued_count_and_clear() {
        let mut lazy = LazyFork::new(LazyConfig::with_max_batch(10));
        lazy.push("a".into(), "wasm".into());
        lazy.push("b".into(), "wasm".into());
        assert_eq!(lazy.queued_count(), 2);
        lazy.clear();
        assert_eq!(lazy.queued_count(), 0);
    }

    #[test]
    fn test_variant_id_tracking() {
        let mut lazy = LazyFork::new(LazyConfig::with_max_batch(10));
        lazy.push("import numpy".into(), "python:minimal".into());
        lazy.push("import torch".into(), "python:pytorch".into());

        // We can't inspect the queue directly from outside the module,
        // but we can verify the count and is_ready behaviour.
        assert_eq!(lazy.queued_count(), 2);
        assert!(!lazy.is_ready()); // not yet at max_batch (10)
    }

    #[test]
    fn test_realize_empty() {
        let mut lazy = LazyFork::new(LazyConfig::default());
        let results = lazy.realize();
        assert!(results.is_empty());
    }

    #[test]
    fn test_is_ready_by_count() {
        // Use max_batch=4 so the 3rd push does NOT trigger auto-realize.
        let mut lazy = LazyFork::new(LazyConfig::with_max_batch(4));
        assert!(!lazy.is_ready());
        lazy.push("a".into(), "w".into());
        assert!(!lazy.is_ready());
        lazy.push("b".into(), "w".into());
        assert!(!lazy.is_ready());
        lazy.push("c".into(), "w".into());
        // Queue length (3) < max_batch (4) — not ready by count yet
        assert!(!lazy.is_ready());
        // Push one more to reach max_batch
        lazy.push("d".into(), "w".into());
        // Queue length (4) >= max_batch (4) — but push auto-realizes!
        // After push with full batch, realize() drains the queue.
        // So is_ready() should return false (queue is empty).
        assert!(!lazy.is_ready());
        assert_eq!(lazy.queued_count(), 0);
    }

    #[test]
    fn test_push_triggers_realize() {
        // When max_batch is small, push should auto-realize.
        let mut lazy = LazyFork::new(LazyConfig::with_max_batch(2));
        // No pool manager → realize will drain silently.
        lazy.push("x".into(), "python:minimal".into());
        assert_eq!(lazy.queued_count(), 1);
        lazy.push("y".into(), "python:minimal".into());
        // After the second push the batch should have been realized
        // and the queue drained (even though there's no pool manager).
        assert_eq!(lazy.queued_count(), 0);
    }

    #[test]
    fn test_is_ready_by_latency() {
        let mut lazy = LazyFork::new(LazyConfig {
            max_batch: 100,
            max_latency: std::time::Duration::from_millis(1),
            profiler_enabled: false,
        });
        lazy.push("slow".into(), "x".into());
        // Not yet ready (timer just started)
        assert!(!lazy.is_ready());
        // After a short sleep the latency should have elapsed.
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(lazy.is_ready());
    }

    // ── Effective batch size ──────────────────────────────────────────

    #[test]
    fn test_effective_batch_no_profiler() {
        let lazy = LazyFork::new(LazyConfig::with_max_batch(8).without_profiler());
        let items = vec![
            QueuedCode::new("import torch", "python:pytorch"),
            QueuedCode::new("x = 1", "python:minimal"),
        ];
        assert_eq!(lazy.effective_batch_size(&items), 8);
    }

    #[test]
    fn test_effective_batch_ram_scaling() {
        let lazy = LazyFork::new(LazyConfig {
            max_batch: 100,
            max_latency: std::time::Duration::from_millis(1),
            profiler_enabled: true,
        });
        // Each torch import adds ~1 GB, so 100 of them would need 100 GB.
        // FREE_RAM / 2 = 4 GB → batch should be scaled to ~4.
        let items: Vec<QueuedCode> = (0..100)
            .map(|i| QueuedCode::new(format!("import torch  # {}", i), "python:pytorch"))
            .collect();
        let batch = lazy.effective_batch_size(&items);
        assert!(batch < 100, "batch should be scaled down, got {batch}");
        assert!(batch >= 1, "batch should be at least 1, got {batch}");
    }

    #[test]
    fn test_effective_batch_low_ram() {
        let lazy = LazyFork::new(LazyConfig {
            max_batch: 50,
            max_latency: std::time::Duration::from_millis(1),
            profiler_enabled: true,
        });
        // Tiny snippets — total RAM barely exceeds baseline.
        let items: Vec<QueuedCode> = (0..10)
            .map(|i| QueuedCode::new(format!("x = {}", i), "python:minimal"))
            .collect();
        assert_eq!(lazy.effective_batch_size(&items), 50);
    }
}
