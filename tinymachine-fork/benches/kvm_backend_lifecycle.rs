//! KVM Fork SandboxBackend lifecycle benchmarks — Phase 2
//!
//! Measures KVM Fork backend lifecycle through the `SandboxBackend` trait,
//! mirroring the Tier 1 (Wasm) lifecycle benchmark pattern in `wasm_init.rs`.
//!
//! Benchmarks:
//!   1. ForkEngine lifecycle: create, fork, drop (file-backed CoW snapshot)
//!   2. KvmForkBackend init + destroy (skipped if KVM/template unavailable)
//!   3. KvmForkBackend end-to-end exec (skipped if template missing)
//!
//! Run with: cargo bench -p tinymachine-fork --bench kvm_backend_lifecycle
//!
//! All benchmarks gracefully handle missing KVM — the file-backed snapshot
//! bench works everywhere KVM is available (no template dependency).

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use tinymachine_fork::fork::{ForkEngine, KvmForkBackend};
use tinymachine_fork::kvm::Kvm;
use tinymachine_fork::snapshot::{CpuState, DescTable, KvmRegs, KvmSregs, Segment, Snapshot};
use tinymachine_api::{SandboxBackend, Variant};

// ─── Snapshot config ─────────────────────────────────────────────────

/// Realistic minimal snapshot size for CoW fork benchmarking.
/// A minimal Python initrd snapshot is typically 32–64 MB.
const MEM_SIZE: usize = 32 * 1024 * 1024; // 32 MB (faster file init, same CoW behaviour)

/// Guest physical address for shared memory (must be above snapshot size).
const SHARED_MEM_GUEST_PHYS: u64 = 0x2000_0000; // 512 MB — safe above 32 MB snapshot

// ─── Stats helper ────────────────────────────────────────────────────

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
        "  {label:<55}  n={n:>5}  μ={mean:>8.1}  σ={stddev:>8.1}  min={min:>8.1}  p50={median:>8.1}  p90={p90:>8.1}  p95={p95:>8.1}  p99={p99:>8.1}  p999={p999:>8.1}  max={max:>8.1}"
    );
}

/// Format a time in microseconds
fn us(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1_000_000.0
}

// ─── File-backed snapshot (realistic CoW, matched to fork_latency.rs pattern) ─

/// Holds a pre-allocated mem file that can be opened cheaply per-iteration.
/// Avoids recreating the backing file (64 MB write) on every iteration.
struct MemFile {
    path: PathBuf,
    size: usize,
}

impl MemFile {
    /// Create a new mem file of the given size (one-time file write).
    fn new(size: usize) -> Self {
        let dir = std::env::temp_dir().join(format!("tm-bench-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mem.bin");

        let mut f = std::fs::File::create(&path).expect("create mem file");
        let nop_page = [0x90u8; 4096];
        for _ in 0..(size / 4096) {
            f.write_all(&nop_page).expect("write mem");
        }
        f.sync_all().expect("sync");
        drop(f);

        MemFile { path, size }
    }

    /// Create a new Snapshot from the pre-allocated mem file.
    /// This is cheap: just an open() + Snapshot struct construction.
    fn snapshot(&self) -> Snapshot {
        let mem_file = std::fs::File::open(&self.path)
            .expect("open mem file (must be created via MemFile::new first)");

        Snapshot {
            memory: vec![0x90u8; self.size],
            memory_size: self.size as u64,
            cpu: CpuState {
                regs: KvmRegs {
                    rax: 0, rbx: 0, rcx: 0, rdx: 0,
                    rsi: 0, rdi: 0, rsp: 0x7c00, rbp: 0,
                    r8: 0, r9: 0, r10: 0, r11: 0,
                    r12: 0, r13: 0, r14: 0, r15: 0,
                    rip: 0x7c00, rflags: 2,
                },
                sregs: KvmSregs {
                    cs: Segment { base: 0, limit: 0xfffff, selector: 0x10, r#type: 11, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                    ds: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                    es: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                    fs: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                    gs: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                    ss: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                    tr: Segment { base: 0, limit: 0, selector: 0, r#type: 0, present: 0, dpl: 0, db: 0, s: 0, l: 0, g: 0, avl: 0, unusable: 1 },
                    ldt: Segment { base: 0, limit: 0, selector: 0, r#type: 0, present: 0, dpl: 0, db: 0, s: 0, l: 0, g: 0, avl: 0, unusable: 1 },
                    gdt: DescTable { base: 0, limit: 0 },
                    idt: DescTable { base: 0, limit: 0 },
                    cr0: 0x60000010, cr2: 0, cr3: 0, cr4: 0, cr8: 0,
                    efer: 0, apic_base: 0xfee00000,
                },
                msrs: vec![],
                xcrs: vec![],
            },
            load_addr: 0,
            xsave: None,
            irqchips: None,
            mem_fd: Some(mem_file),
            kernel_version: String::new(),
            kernel_hash: String::new(),
        }
    }
}

// ─── KVM check ───────────────────────────────────────────────────────

fn kvm_available() -> bool {
    Kvm::new().is_ok()
}

// ─── Main ────────────────────────────────────────────────────────────

fn main() {
    println!("\n=== KVM Fork SandboxBackend Lifecycle Benchmarks (Phase 2) ===");
    println!("  Engine: KVM + MAP_PRIVATE CoW fork (Tier 2)");
    println!();

    if !kvm_available() {
        println!("  ⚠  KVM not available — all benchmarks skipped");
        println!("  Install KVM: sudo apt install cpu-checker && kvm-ok");
        return;
    }

    // ── 0. Create the backing file once, then sanity check ───────
    let mem_file = MemFile::new(MEM_SIZE);
    println!("  Snapshot: {} MB file-backed (MAP_PRIVATE CoW)", MEM_SIZE / 1024 / 1024);
    let kvm = Kvm::new().expect("KVM available");
    let mmap_size = kvm.vcpu_mmap_size().expect("vcpu_mmap_size");
    let _engine = ForkEngine::new(kvm, mem_file.snapshot(), mmap_size);
    println!("  Sanity check: ForkEngine created");
    println!();

    // ── 1. ForkEngine lifecycle: create + fork + drop ─────────────

    // 1a. ForkEngine::new() only
    println!("  ── ForkEngine::new() (create + drop) ──");
    let mut new_times = Vec::with_capacity(500);
    for _ in 0..500 {
        let start = Instant::now();
        let kvm = Kvm::new().expect("kvm");
        let mmap_size = kvm.vcpu_mmap_size().expect("mmap_size");
        let engine = ForkEngine::new(kvm, mem_file.snapshot(), mmap_size);
        new_times.push(us(start.elapsed()));
        drop(engine);
    }
    stats("ForkEngine::new (create + drop)", &new_times);

    // 1b. Fork: single fork from fresh engine
    println!();
    println!("  ── ForkEngine::fork() (single) ──");
    let mut fork_times = Vec::with_capacity(500);
    for _ in 0..500 {
        let kvm = Kvm::new().expect("kvm");
        let mmap_size = kvm.vcpu_mmap_size().expect("mmap_size");
        let engine = ForkEngine::new(kvm, mem_file.snapshot(), mmap_size);
        let start = Instant::now();
        let _forked = engine.fork().expect("fork");
        fork_times.push(us(start.elapsed()));
    }
    stats("fork (single, 32MB CoW snapshot)", &fork_times);

    // 1c. Fork + drop ForkedVm
    println!();
    println!("  ── ForkEngine create + fork + drop all ──");
    let mut full_times = Vec::with_capacity(500);
    for _ in 0..500 {
        let start = Instant::now();
        let kvm = Kvm::new().expect("kvm");
        let mmap_size = kvm.vcpu_mmap_size().expect("mmap_size");
        let engine = ForkEngine::new(kvm, mem_file.snapshot(), mmap_size);
        let _forked = engine.fork().expect("fork");
        // dropping both forked and engine
        full_times.push(us(start.elapsed()));
    }
    stats("full lifecycle (new + fork + drop)", &full_times);

    // ── 2. Fork batch: instantiate + fork_batch + drop ────────────
    println!();
    println!("  ── ForkEngine::fork_batch() (32MB CoW) ──");
    for batch_size in [1usize, 2, 4, 8, 16, 32] {
        let mut batch_times = Vec::with_capacity(100);
        for _ in 0..100 {
            let kvm = Kvm::new().expect("kvm");
            let mmap_size = kvm.vcpu_mmap_size().expect("mmap_size");
            let engine = ForkEngine::new(kvm, mem_file.snapshot(), mmap_size);
            let start = Instant::now();
            let vms = engine.fork_batch(batch_size).expect("fork_batch");
            let elapsed = us(start.elapsed());
            batch_times.push(elapsed / batch_size as f64);
            assert_eq!(vms.len(), batch_size);
        }
        let label = format!("fork_batch({batch_size:>2})  (per-fork, {batch_size} batch)");
        stats(&label, &batch_times);
    }

    // ── 3. KvmForkBackend lifecycle (SandboxBackend trait) ────────
    println!();
    println!("  ── KvmForkBackend lifecycle (SandboxBackend trait) ──");

    // 3a. Create + destroy (no init)
    let mut destroy_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let backend = KvmForkBackend::new();
        let start = Instant::now();
        let mut b = backend;
        let _ = b.destroy();
        destroy_times.push(us(start.elapsed()));
    }
    stats("create + destroy (no init)", &destroy_times);

    // 3b. Init + destroy (tries real template, may fail gracefully)
    println!();
    println!("  ── init + destroy (variant: python:minimal) ──");

    let variant = Variant::new("python", "minimal", "base");
    let mut init_destroy = Vec::with_capacity(50);
    for _ in 0..50 {
        let mut backend = KvmForkBackend::new();
        let start = Instant::now();
        match backend.init(&variant) {
            Ok(()) => {
                init_destroy.push(us(start.elapsed()));
                let _ = backend.destroy();
            }
            Err(e) => {
                // Template not available — expected in CI without pre-built templates
                if init_destroy.is_empty() {
                    println!("    ⚠  Template not available — init failed: {e}");
                    println!("    Skipping init/destroy bench.");
                    println!("    Build a template first: tinyos template build --variant minimal");
                }
                break;
            }
        }
    }
    if !init_destroy.is_empty() {
        stats("init + destroy (python:minimal)", &init_destroy);
    }

    // 3c. Init + exec + destroy (if template available)
    if !init_destroy.is_empty() {
        println!();
        println!("  ── init + exec + destroy (python:minimal) ──");
        let mut exec_times = Vec::with_capacity(500);
        for _ in 0..500 {
            let mut backend = KvmForkBackend::new();
            match backend.init(&variant) {
                Ok(()) => {
                    let start = Instant::now();
                    match backend.exec("print(1)") {
                        Ok(output) => {
                            exec_times.push(us(start.elapsed()));
                            let trimmed = output.trim();
                            assert!(!trimmed.contains("Traceback"),
                                "exec should not have Python traceback, got: {output}");
                        }
                        Err(e) => {
                            if exec_times.is_empty() {
                                println!("    ⚠  exec failed: {e}");
                            }
                        }
                    }
                    let _ = backend.destroy();
                }
                Err(_) => break,
            }
        }
        if !exec_times.is_empty() {
            stats("init + exec print(1) + destroy", &exec_times);
        }
    }

    // ── 4. Exec with shared memory ─────────────────────────────────
    if !init_destroy.is_empty() {
        println!();
        println!("  ── Shared memory + exec ──");
        use tinymachine_fork::shared_mem::SharedMemoryRegion;

        let mut shared_times = Vec::with_capacity(50);
        for _ in 0..50 {
            let kvm = Kvm::new().expect("kvm");
            let mmap_size = kvm.vcpu_mmap_size().expect("mmap_size");
            let mut engine = ForkEngine::new(kvm, mem_file.snapshot(), mmap_size);

            // Add a small shared region at a guest phys address above
            // the snapshot size (32 MB) to avoid KVM_SET_USER_MEMORY_REGION overlap.
            let region = SharedMemoryRegion::new_anon(4096).expect("anon region");
            engine.add_shared_region(region, SHARED_MEM_GUEST_PHYS);

            let start = Instant::now();
            let _forked = engine.fork().expect("fork with shared mem");
            shared_times.push(us(start.elapsed()));
        }
        if !shared_times.is_empty() {
            stats("fork + 4KB EPT shared memory (32MB CoW)", &shared_times);
        }
    }

    // ── Verdict ──────────────────────────────────────────────────
    println!();
    println!("  Targets: ForkEngine::new <100μs, fork <500μs, fork_batch <200μs/fork");
    println!("  Snapshot: {}MB file-backed (MAP_PRIVATE CoW via mem_fd)", MEM_SIZE / 1024 / 1024);
    println!();
}
