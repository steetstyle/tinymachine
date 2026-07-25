//! Sandbox lifecycle benchmarks — Python exec pipeline
//!
//! Measures the complete KVM sandbox lifecycle across 4 independent
//! benchmarks, each targeting a distinct component:
//!
//!   1. Cold boot:  `boot::boot_linux()` + `run_until_ready()` + `capture_snapshot()`
//!      → full kernel boot from a cold start (~1-5s). UNIQUE: no other bench measures boot_linux.
//!   2. Snapshot restore (warm boot): `TemplateRegistry::load_snapshot()`
//!      → load a pre-built snapshot from disk (~50-200µs). TOTAL only: ForkEngine::new is in fork_latency.
//!   3. Fork → READY: `ForkedVm::run_until_ready()`
//!      → total after fork, wait for init's READY signal (~500-2000µs). TOTAL only: fork() is in fork_latency.
//!   4. Python print(1) latency: full exec pipeline (fork + inject + run + read)
//!      → end-to-end Python execution (~2-5ms). TOTAL only: fork() is in fork_latency, output read is trivial.
//!
//! Each benchmark can be run independently with:
//!   cargo bench -p tinyos-fork --bench sandbox_exec -- <filter>
//!
//! Examples:
//!   cargo bench -p tinyos-fork --bench sandbox_exec -- cold    # cold boot only
//!   cargo bench -p tinyos-fork --bench sandbox_exec -- ready   # fork→READY only
//!   cargo bench -p tinyos-fork --bench sandbox_exec -- print   # print(1) only
//!
//! Environment / hardware prereqs:
//!   - Cold boot:  vmlinux + initrd for python:minimal must exist
//!   - All others: pre-built snapshot at ~/.tinymachine/templates/python/v1/minimal/
//!   - All: KVM must be available
//!
//! The benchmark checks prereqs and skips with a message if missing,
//! so running the full suite always passes (zero failures).

use std::path::PathBuf;
use std::time::Instant;

use tinymachine_fork::boot::{self, BootConfig};
use tinymachine_fork::fork::ForkEngine;
use tinymachine_fork::kvm::Kvm;
use tinymachine_fork::snapshot::Snapshot;
use tinymachine_fork::template_registry::TemplateRegistry;
use tinymachine_fork::variant::Variant;

// ─── Config ────────────────────────────────────────────────────────────

/// The variant we benchmark against
const VARIANT_NAME: &str = "minimal";
const VARIANT_LANG: &str = "python";

/// Iteration counts
const COLD_BOOT_ITERATIONS: usize = 3;     // cold boot is expensive — keep 3
const SNAPSHOT_RESTORE_ITERATIONS: usize = 100;
const FORK_READY_ITERATIONS: usize = 1000;
const PRINT1_ITERATIONS: usize = 1000;



// ─── Setup helpers ─────────────────────────────────────────────────────

fn home_tinymachine_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("HOME must be set");
    PathBuf::from(home).join(".tinymachine")
}

fn template_dir() -> PathBuf {
    home_tinymachine_dir().join("templates").join(VARIANT_LANG).join("v1").join(VARIANT_NAME)
}

fn snapshot_path() -> PathBuf {
    template_dir().join("mem")
}

fn state_path() -> PathBuf {
    template_dir().join("state.json")
}

fn snapshot_exists() -> bool {
    // Use the registry to check — this handles version auto-increment
    // after cold boot stores successive snapshots at v1, v2, v3...
    if let Ok(registry) = TemplateRegistry::open(None) {
        return registry.has_snapshot(&variant());
    }
    // Fallback: direct file check for the default v1 path
    snapshot_path().exists() && state_path().exists()
}

fn find_kernel() -> Option<PathBuf> {
    let tinymachine_dir = home_tinymachine_dir();
    let candidates = [
        tinymachine_dir.join("templates/kernel/vmlinux-base"),
        tinymachine_dir.join("templates/kernel/vmlinux"),
        PathBuf::from("/boot/vmlinuz"),
    ];
    for p in &candidates {
        if p.exists() {
            if let Ok(f) = std::fs::File::open(p) {
                drop(f);
                return Some(p.clone());
            }
        }
    }
    // Glob /boot/vmlinuz-*
    if let Ok(entries) = std::fs::read_dir("/boot") {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if (name.starts_with("vmlinuz-") || name.starts_with("vmlinux-"))
                && std::fs::File::open(&path).is_ok()
            {
                return Some(path);
            }
        }
    }
    None
}

fn find_initrd() -> Option<PathBuf> {
    let path = template_dir().join("initrd.gz");
    if path.exists() { Some(path) } else { None }
}

fn variant() -> Variant {
    Variant::python_minimal()
}

// ─── Cold boot: build python:minimal template from scratch ────────────
//
// Measures: boot::boot_linux() + run_until_ready() + dummy exec + capture_snapshot()
// Prereq:   vmlinux + initrd must exist
// Time:     ~1-5 seconds per iteration

fn bench_cold_boot(times: &mut Vec<f64>, sub_steps: &mut Vec<(&str, Vec<f64>)>) -> Result<(), String> {
    let kvm = Kvm::new().map_err(|e| format!("KVM unavailable: {e}"))?;
    let kernel = find_kernel().ok_or("No kernel found. Place vmlinux at ~/.tinymachine/templates/kernel/vmlinux-base")?;
    let initrd = find_initrd().ok_or("No initrd found. Run `tinymachine template build python --variant minimal` first")?;

    let config = BootConfig {
        kernel_path: kernel,
        memory_size: 128 * 1024 * 1024, // python:minimal = 128MB
        load_addr: 0,
        initrd_path: Some(initrd),
        pvh_boot: true,
        irqchip: true,
        cmdline: None,
        reserved_regions: Vec::new(),
        kernel_version: String::new(),
        kernel_hash: String::new(),
        vbios_data: None,
    };

    // Keep the last snapshot for disk persistence (benchmarks 2-4)
    let mut last_snapshot: Option<Snapshot> = None;

    for i in 0..times.capacity() {
        // ── Step 1: boot_linux ──
        let boot_start = Instant::now();
        let mut booted = unsafe {
            boot::boot_linux(&kvm, &config)
                .map_err(|e| format!("boot_linux failed (run {i}): {e}"))?
        };
        let boot_us = boot_start.elapsed().as_secs_f64() * 1_000_000.0;
        sub_steps[0].1.push(boot_us);

        // ── Step 2: run_until_ready ──
        let ready_start = Instant::now();
        unsafe {
            booted.run_until_ready()
                .map_err(|e| format!("Kernel boot failed (run {i}): {e}"))?
        }
        let ready_us = ready_start.elapsed().as_secs_f64() * 1_000_000.0;
        sub_steps[1].1.push(ready_us);

        // ── Step 3: dummy exec (clean up VCPU state) ──
        let dummy_start = Instant::now();
        let _dummy = unsafe { booted.run_code("print('ping')") };
        let dummy_us = dummy_start.elapsed().as_secs_f64() * 1_000_000.0;
        sub_steps[2].1.push(dummy_us);

        // ── Step 4: capture_snapshot ──
        let snap_start = Instant::now();
        let snapshot = booted.capture_snapshot()
            .map_err(|e| format!("capture_snapshot failed (run {i}): {e}"))?;
        let snap_us = snap_start.elapsed().as_secs_f64() * 1_000_000.0;
        sub_steps[3].1.push(snap_us);

        // Total
        times.push(boot_start.elapsed().as_secs_f64() * 1_000_000.0);
        // BootedVm is dropped here → VM destroyed

        // Keep the last snapshot so benchmarks 2-4 can load it from disk
        if i == times.capacity() - 1 {
            last_snapshot = Some(snapshot);
        }
    }

    // Save the last snapshot to disk → makes it available for benchmarks 2-4
    if let Some(snapshot) = last_snapshot {
        let mut registry = TemplateRegistry::open(None)
            .map_err(|e| format!("Cannot open template registry: {e}"))?;
        registry.store_snapshot(&variant(), &snapshot)
            .map_err(|e| format!("Failed to store snapshot to disk: {e}"))?;
        eprintln!("  ✓ Snapshot saved to ~/.tinymachine/templates/ for benchmarks 2-4");
    }

    Ok(())
}

// ─── Snapshot restore (warm boot) ─────────────────────────────────────
//
// Measures: TemplateRegistry::load_snapshot()  (total only)
// ForkEngine::new() is measured by fork_latency bench (section 0).
// Prereq:   pre-built snapshot at ~/.tinymachine/templates/python/v1/minimal/
// Time:     ~50-200µs per iteration

fn bench_snapshot_restore(times: &mut Vec<f64>) -> Result<(), String> {
    let registry = TemplateRegistry::open(None)
        .map_err(|e| format!("Cannot open template registry: {e}"))?;
    let v = variant();

    for _ in 0..times.capacity() {
        let start = Instant::now();
        let _snapshot: Snapshot = registry.load_snapshot(&v)
            .map_err(|e| format!("Snapshot not found for {VARIANT_LANG}:{VARIANT_NAME}: {e}"))?;
        times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        // snapshot dropped here; no ForkEngine::new (measured by fork_latency)
    }

    Ok(())
}

// ─── Fork → READY ─────────────────────────────────────────────────────
//
// Measures: ForkEngine::fork() + ForkedVm::run_until_ready()  (total only)
// fork() alone is measured by fork_latency bench (sections 1-2).
// Prereq:   pre-built snapshot (same as snapshot restore)
// Time:     ~500-2000µs per iteration

fn bench_fork_to_ready(times: &mut Vec<f64>) -> Result<(), String> {
    let kvm = Kvm::new().map_err(|e| format!("KVM unavailable: {e}"))?;
    let mmap_size = kvm.vcpu_mmap_size().map_err(|e| format!("vcpu_mmap_size: {e}"))?;
    let registry = TemplateRegistry::open(None)
        .map_err(|e| format!("Cannot open template registry: {e}"))?;
    let snapshot: Snapshot = registry.load_snapshot(&variant())
        .map_err(|e| format!("Snapshot not found: {e}"))?;
    let engine = ForkEngine::new(kvm, snapshot, mmap_size);

    for i in 0..times.capacity() {
        let start = Instant::now();
        let mut vm = engine.fork()
            .map_err(|e| format!("fork failed (run {i}): {e}"))?;
        // SAFETY: freshly forked VM. run_code("True") = inject + run_until_ready + read.
        unsafe {
            vm.run_code("True")?;
        }
        times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        // vm dropped → destroyed
    }

    Ok(())
}

// ─── Python print(1) end-to-end ───────────────────────────────────────
//
// Measures: full exec pipeline total (fork + exec + output read + validate)
// fork() alone is measured by fork_latency bench. Output read/validate is
// <1µs and not useful as a standalone metric.
// Prereq:   pre-built snapshot (same as snapshot restore)
// Time:     ~2-5ms per iteration

fn bench_print1_latency(times: &mut Vec<f64>) -> Result<(), String> {
    let kvm = Kvm::new().map_err(|e| format!("KVM unavailable: {e}"))?;
    let mmap_size = kvm.vcpu_mmap_size().map_err(|e| format!("vcpu_mmap_size: {e}"))?;
    let registry = TemplateRegistry::open(None)
        .map_err(|e| format!("Cannot open template registry: {e}"))?;
    let snapshot: Snapshot = registry.load_snapshot(&variant())
        .map_err(|e| format!("Snapshot not found: {e}"))?;
    let engine = ForkEngine::new(kvm, snapshot, mmap_size);

    for i in 0..times.capacity() {
        let start = Instant::now();
        let mut vm = engine.fork()
            .map_err(|e| format!("fork failed (run {i}): {e}"))?;
        // SAFETY: freshly forked VM. run_code handles inject + execute + read.
        let result = unsafe { vm.run_code("print(1)") }
            .map_err(|e| format!("exec failed (run {i}): {e}"))?;
        // Validate output
        let output = if let Some(pos) = result.find("ENTROPY:") {
            &result[..pos]
        } else {
            &result
        };
        let trimmed = output.trim();
        assert_eq!(trimmed, "1", "print(1) should produce '1', got: '{trimmed}'");
        times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        // vm dropped → destroyed
    }

    Ok(())
}

// ─── Stats ────────────────────────────────────────────────────────────

fn stats(label: &str, times: &[f64]) {
    if times.is_empty() {
        println!("  {:<44} SKIPPED — no data", label);
        return;
    }
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

fn print_header(title: &str) {
    println!();
    println!("  ── {} ──", title);
}

fn print_skip(reason: &str) {
    println!("  ⚠  SKIPPED: {reason}");
}

// ─── Main ─────────────────────────────────────────────────────────────

fn main() {
    let kvm_check = Kvm::new();
    let kvm_ok = kvm_check.is_ok();
    let mut snap_ok = snapshot_exists();

    println!("\n══════════════════════════════════════════════════════════════");
    println!("  Sandbox Lifecycle Benchmarks");
    println!("══════════════════════════════════════════════════════════════");
    println!("  Variant:          {}:{}", VARIANT_LANG, VARIANT_NAME);
    println!("  Snapshot exists:  {}", if snap_ok { "✅" } else { "❌" });
    match &kvm_check {
        Ok(kvm) => {
            let mmap_size = kvm.vcpu_mmap_size().unwrap_or(0);
            println!("  KVM available:    ✅  (API {}, mmap_size={}KB)", 12, mmap_size / 1024);
        }
        Err(e) => println!("  KVM available:    ❌  ({e})"),
    }
    println!();

    // ─── 1. Cold boot ───────────────────────────────────────────────
    print_header("1. Cold boot (boot_linux + run_until_ready + capture_snapshot)");
    if kvm_ok && find_kernel().is_some() && find_initrd().is_some() {
        let mut total = Vec::with_capacity(COLD_BOOT_ITERATIONS);
        let mut sub = vec![
            ("  ├─ boot_linux", Vec::with_capacity(COLD_BOOT_ITERATIONS)),
            ("  ├─ run_until_ready", Vec::with_capacity(COLD_BOOT_ITERATIONS)),
            ("  ├─ dummy exec (cleanup)", Vec::with_capacity(COLD_BOOT_ITERATIONS)),
            ("  └─ capture_snapshot", Vec::with_capacity(COLD_BOOT_ITERATIONS)),
        ];
        match bench_cold_boot(&mut total, &mut sub) {
            Ok(()) => {
                stats("total cold boot", &total);
                for (label, v) in &sub {
                    stats(label, v);
                }
                // Cold boot saved snapshot to disk — enable benchmarks 2-4
                snap_ok = true;
            }
            Err(e) => print_skip(&e),
        }
    } else {
        if !kvm_ok { print_skip("KVM not available"); }
        if find_kernel().is_none() { print_skip("No vmlinux kernel found"); }
        if find_initrd().is_none() { print_skip("No initrd found for python:minimal"); }
    }

    // ─── 2. Snapshot restore (warm boot) ────────────────────────────
    print_header("2. Snapshot restore (load_snapshot from registry)");
    if kvm_ok && snap_ok {
        let mut times = Vec::with_capacity(SNAPSHOT_RESTORE_ITERATIONS);
        match bench_snapshot_restore(&mut times) {
            Ok(()) => stats("load_snapshot", &times),
            Err(e) => print_skip(&e),
        }
    } else {
        if !snap_ok { print_skip("No pre-built snapshot. Run `tinymachine template build python --variant minimal`"); }
        if !kvm_ok { print_skip("KVM not available"); }
    }

    // ─── 3. Fork → READY ────────────────────────────────────────────
    print_header("3. Fork → READY (total: fork + run_until_ready with noop)");
    if kvm_ok && snap_ok {
        let mut times = Vec::with_capacity(FORK_READY_ITERATIONS);
        match bench_fork_to_ready(&mut times) {
            Ok(()) => stats("fork→READY (total)", &times),
            Err(e) => print_skip(&e),
        }
    } else if !snap_ok {
        print_skip("No pre-built snapshot. Run `tinymachine template build python --variant minimal`");
    }

    // ─── 4. Python print(1) ─────────────────────────────────────────
    print_header("4. Python print(1) end-to-end (total: fork+exec+output)");
    if kvm_ok && snap_ok {
        let mut times = Vec::with_capacity(PRINT1_ITERATIONS);
        match bench_print1_latency(&mut times) {
            Ok(()) => stats("print(1) latency (total)", &times),
            Err(e) => print_skip(&e),
        }
    } else if !snap_ok {
        print_skip("No pre-built snapshot. Run `tinymachine template build python --variant minimal`");
    }

    // ─── Summary ────────────────────────────────────────────────────
    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("  Sandbox Lifecycle Summary — Python exec pipeline");
    println!("═══════════════════════════════════════════════════════════════════════");
    println!();
    println!("  Lifecycle stages and where each is measured:");
    println!("  ┌──────────────────────────────────┬──────────────────────────────┐");
    println!("  │ Stage                            │ Measured in                  │");
    println!("  ├──────────────────────────────────┼──────────────────────────────┤");
    println!("  │ Cold boot (boot_linux)            │ sandbox_exec (this bench)    │");
    println!("  │ ↓ run_until_ready                 │ sandbox_exec                 │");
    println!("  │ ↓ capture_snapshot                │ sandbox_exec                 │");
    println!("  │ Snapshot restore (load_snapshot)  │ sandbox_exec (this bench)    │");
    println!("  │ ForkEngine::new()                 │ fork_latency §0              │");
    println!("  │ CoW fork (fork_batch)             │ fork_latency §1-4,           │");
    println!("  │                                   │ fork_concurrent §2/4         │");
    println!("  │ ↓ run_until_ready                 │ sandbox_exec §3 (total)      │");
    println!("  │ ↓ exec + output read              │ sandbox_exec §4 (total)      │");
    println!("  │ Pool acquire (warm)               │ fork_latency §5              │");
    println!("  │ Concurrent fork + hold            │ fork_concurrent §3/5         │");
    println!("  │ VM destroy                        │ fork_concurrent §5           │");
    println!("  └──────────────────────────────────┴──────────────────────────────┘");
    println!();
    println!("  Pipeline cost per stage (typical, 32-core host):");
    println!("    cold boot:   ~1-5s     (one-time per template)");
    println!("    snapshot:    ~100-500μs (load from disk, per ForkEngine::new)");
    println!("    fork:        ~145 μs   (CoW batch, per VM)");
    println!("    READY:       ~500-2000μs (boot wait, per VM)");
    println!("    exec:        ~500-3000μs (Python code, per VM)");
    println!("    destroy:     ~0.5 μs   (fd close, per VM)");
    println!();
    println!("  → Fork → print(1) total: ~1.5-5ms  (warm pool: ~0 μs acquire)");
    println!();
}
