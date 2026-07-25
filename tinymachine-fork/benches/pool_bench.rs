//! Warm pool benchmarks — Phase 1
//!
//! Measures ForkPool throughput under various configurations:
//!   - Pool creation (pre-warm N forks)
//!   - Acquire/release latency (warm pool hits)
//!   - Auto-refill when pool underflows
//!   - Pool exhaustion (Full error handling)
//!   - Throughput: acquire-release ping-pong
//!
//! Run with: cargo bench -p tinyos-fork --bench pool

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use tinymachine_fork::kvm::Kvm;
use tinymachine_fork::fork::ForkEngine;
use tinymachine_fork::pool::{ForkPool, PoolConfig};
use tinymachine_fork::snapshot::{CpuState, DescTable, KvmRegs, KvmSregs, Segment, Snapshot};

fn stub_snapshot() -> Snapshot {
    Snapshot {
        memory: vec![0x90u8; 4096],
        memory_size: 4096,
        cpu: CpuState {
            regs: KvmRegs {
                rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rsp: 0x7c00, rbp: 0,
                r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
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
        mem_fd: None,
        kernel_version: String::new(),
        kernel_hash: String::new(),
    }
}

fn setup_pool(min: usize, max: usize) -> ForkPool {
    let kvm = Kvm::new().expect("KVM not available");
    let mmap_size = kvm.vcpu_mmap_size().expect("mmap size");
    let snap = stub_snapshot();
    let engine = ForkEngine::new(kvm, snap, mmap_size);
    ForkPool::new(engine, PoolConfig {
        min, max,
        idle_timeout_secs: 60,
        variant_id: None,
    })
}

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

fn main() {
    println!("\n=== Warm Pool Benchmarks (Phase 1) ===");
    println!("  Pool: ForkPool — pre-forked sandbox instances (stub 4KB snapshot)");
    println!();

    // ── 1. Pre-warm latency (pool creation) ────────────────────────
    let mut create_times = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        let _pool = setup_pool(5, 20);
        create_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("pool create (pre-warm 5)", &create_times);

    // ── 2. Acquire latency (warm pool) ─────────────────────────────
    let mut pool = setup_pool(20, 1000);

    let mut acq_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let vm = pool.acquire().expect("acquire");
        acq_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        let _ = pool.release(vm);
    }
    stats("pool acquire (warm, sequential)", &acq_times);

    // ── 3. Release latency ─────────────────────────────────────────
    let mut rel_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let vm = pool.acquire().expect("acquire");
        let start = Instant::now();
        let _ = pool.release(vm);
        rel_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("pool release (to warm pool)", &rel_times);

    // ── 4. Acquire all (exhaust) ──────────────────────────────────
    let mut pool = setup_pool(100, 100);
    let mut acq_all_times = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        let _vm = pool.acquire().expect("acquire");
        acq_all_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("pool acquire (100 of 100, draining)", &acq_all_times);

    // ── 5. Acquire from empty (auto-refill) ───────────────────────
    let start = Instant::now();
    match pool.acquire() {
        Ok(_vm) => {
            let refill_us = start.elapsed().as_secs_f64() * 1_000_000.0;
            println!("  pool acquire (empty → refill)   {:>10.1} μs  (auto-refill triggered)", refill_us);
        }
        Err(e) => {
            println!("  pool acquire (empty → refill)   FAILED: {}", e);
        }
    }

    // ── 6. Concurrent acquire (2 threads via Arc<Mutex>) ──────────
    let pool2 = Arc::new(std::sync::Mutex::new(setup_pool(10, 500)));
    let barrier = Arc::new(Barrier::new(2));

    let mut handles = Vec::new();
    for _ in 0..2 {
        let pool_ref = Arc::clone(&pool2);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait();
            let mut local_times = Vec::with_capacity(500);
            for _ in 0..500 {
                let start = Instant::now();
                let mut guard = pool_ref.lock().unwrap();
                if let Ok(vm) = guard.acquire() {
                    let _ = guard.release(vm);
                }
                local_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
            }
            local_times
        }));
    }

    let mut all_concurrent = Vec::new();
    for h in handles {
        all_concurrent.extend(h.join().unwrap());
    }
    stats("pool acquire (2 threads concurrent)", &all_concurrent);

    // ── 7. Throughput: acquire-release ping-pong ──────────────────
    let mut pool3 = setup_pool(5, 50);
    let mut ping_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let vm = pool3.acquire().expect("acquire");
        let _ = pool3.release(vm);
        ping_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("acquire-release ping-pong (1000)", &ping_times);

    // ── Verdict ──────────────────────────────────────────────────
    println!();
    println!("  Note: Warm pool targets <5μs acquire latency (no fork).");
    println!("  Real fork (cold) ~900μs — pool avoids this on hit.");
    println!();
}
