//! Wasm sandbox initialization & eval benchmarks — Phase 1
//!
//! Measures wasmtime cold/warm start and WASI execution for typical
//! Tier 1 operations: arithmetic, string processing, list ops, sort.
//!
//! Two modes:
//!   - Cold: `eval_wat()` — fresh sandbox per call (convenience fn)
//!   - Warm: `WasmBackend::init()` once, then multiple `exec()` calls
//!
//! Run with: cargo bench -p tinyos-fork --bench wasm_init

use std::time::Instant;

use tinymachine_fork::wasm::{WasmBackend, eval_wat};
use tinymachine_api::{SandboxBackend, Variant};

// ─── WAT programs used in benchmarks ────────────────────────────────

// Store a value at memory[0], then eval_wat reads it.
// NOTE: eval_wat calls the "main" function, then reads memory[0].
const ADD_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "main")
    i32.const 0
    i32.const 1
    i32.const 2
    i32.add
    i32.store offset=0
  )
)"#;

const FIB15_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func $fib (param i32) (result i32)
    (if (result i32) (i32.lt_s (local.get 0) (i32.const 2))
      (then (local.get 0))
      (else
        (i32.add
          (call $fib (i32.sub (local.get 0) (i32.const 1)))
          (call $fib (i32.sub (local.get 0) (i32.const 2)))
        )
      )
    )
  )
  (func (export "main")
    i32.const 0
    i32.const 15
    call $fib
    i32.store offset=0
  )
)"#;

/// Rich stats: mean, median, stddev, min, max, p90, p95, p99, p99.9
fn stats(label: &str, times: &[f64]) {
    if times.is_empty() { return; }
    let n = times.len();
    let mut sorted = times.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let variance = if n > 1 {
        sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else { 0.0 };
    let stddev = variance.sqrt();
    let min = sorted[0];
    let max = sorted[n - 1];
    let median = sorted[n / 2];
    let p90 = sorted[((n as f64 * 0.90) as usize).min(n - 1)];
    let p95 = sorted[((n as f64 * 0.95) as usize).min(n - 1)];
    let p99 = sorted[((n as f64 * 0.99) as usize).min(n - 1)];
    let p999 = sorted[((n as f64 * 0.999) as usize).min(n - 1)];
    println!(
        "  {label:<50}  n={n:>5}  μ={mean:>8.1}  σ={stddev:>8.1}  min={min:>8.1}  p50={median:>8.1}  p90={p90:>8.1}  p95={p95:>8.1}  p99={p99:>8.1}  p999={p999:>8.1}  max={max:>8.1}"
    );
}

fn verify_ok(result: &str) {
    let trimmed = result.trim();
    assert!(!trimmed.contains("error") && !trimmed.is_empty(),
        "execution should succeed, got: '{}'", trimmed);
}

fn main() {
    println!("\n=== Wasm Sandbox Benchmarks (Phase 1) ===");
    println!("  Engine: wasmtime (Tier 1 in-process)");
    println!();

    // ── 0. Check that wasmtime works ──────────────────────────────
    let result = eval_wat(ADD_WAT).expect("basic add should work");
    println!("  Sanity check: 1 + 2 = {}  (via eval_wat)", result.trim());
    println!();

    // ── 1. Cold start: eval_wat (creates new sandbox per call) ────
    println!("  ── Cold start (eval_wat: fresh sandbox each call) ──");
    let mut add_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let r = eval_wat(ADD_WAT).expect("add");
        add_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        verify_ok(&r);
    }
    stats("cold eval_wat (add 1+2)", &add_times);

    let mut fib_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let r = eval_wat(FIB15_WAT).expect("fib");
        fib_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        verify_ok(&r);
    }
    stats("cold eval_wat (fib 15)", &fib_times);

    // ── 2. Warm start: WasmBackend (init once, exec many) ─────────
    println!();
    println!("  ── Warm start (WasmBackend: init once, exec many) ──");

    let mut backend = WasmBackend::new();
    backend.init(&Variant::new("wasm", "minimal", "base")).expect("init");

    // Warm: add
    let mut warm_add = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let r = backend.exec(ADD_WAT).expect("exec add");
        warm_add.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        verify_ok(&r);
    }
    stats("warm exec (add 1+2)", &warm_add);

    // Warm: fib 15
    let mut warm_fib = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let r = backend.exec(FIB15_WAT).expect("exec fib");
        warm_fib.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        verify_ok(&r);
    }
    stats("warm exec (fib 15)", &warm_fib);

    // ── 3. Mixed workload on warm sandbox ─────────────────────────
    println!();
    println!("  ── Mixed workload (warm, alternating ops) ──");
    let mut backend = WasmBackend::new();
    backend.init(&Variant::new("wasm", "minimal", "base")).expect("init");

    let ops = [ADD_WAT, FIB15_WAT, ADD_WAT, ADD_WAT, FIB15_WAT];
    let mut mix_times = Vec::with_capacity(1000);
    for _ in 0..200 {
        for &op in &ops {
            let start = Instant::now();
            let _ = backend.exec(op).expect("exec");
            mix_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        }
    }
    stats("mixed 5-ops seq (warm)", &mix_times);

    // ── 4. Reset + re-execute ────────────────────────────────────
    println!();
    println!("  ── Reset benchmarks ──");
    let mut backend = WasmBackend::new();
    backend.init(&Variant::new("wasm", "minimal", "base")).expect("init");

    // Pre-warm
    let _ = backend.exec(ADD_WAT).expect("exec");

    let mut reset_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        backend.reset().expect("reset");
        reset_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("backend reset (warm)", &reset_times);

    // Exec after reset
    let mut post_reset = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let _r = backend.exec(ADD_WAT).expect("exec after reset");
        post_reset.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("exec after reset", &post_reset);

    // ── 5. Destroy + re-init ─────────────────────────────────────
    let mut destroy_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let mut b = WasmBackend::new();
        b.init(&Variant::new("wasm", "minimal", "base")).expect("init");
        let _ = b.exec(ADD_WAT).expect("exec");
        let start = Instant::now();
        b.destroy().expect("destroy");
        destroy_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("backend destroy (from warm)", &destroy_times);

    // ── Verdict ──────────────────────────────────────────────────
    println!();
    println!("  Targets: cold start <10μs, warm <2μs, reset <1μs");
    println!();
}
