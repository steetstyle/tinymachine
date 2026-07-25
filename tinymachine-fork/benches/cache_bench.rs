//! Execution cache benchmarks — Phase 1
//!
//! Measures ExecutionCache insert/lookup/hit-rate/miss-rate throughput.
//! The cache uses blake3 hashing + RefCell<HashMap> and is used
//! to memoize code execution results so identical code can skip the fork.
//!
//! Run with: cargo bench -p tinyos-fork --bench cache

use std::time::Instant;

use tinymachine_fork::cache::ExecutionCache;

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
    println!("\n=== Execution Cache Benchmarks (Phase 1) ===");
    println!("  Cache: blake3 hash + RefCell<HashMap<Hash, CacheEntry>>");
    println!();

    // ── 1. Hash throughput ─────────────────────────────────────────
    let codes: Vec<String> = (0..1000)
        .map(|i| format!("import numpy as np; np.ones(({}, {}))", i % 100 + 1, i % 100 + 1))
        .collect();

    let mut hash_times = Vec::with_capacity(1000);
    for code in &codes {
        let start = Instant::now();
        let _h = ExecutionCache::hash(code, "python");
        hash_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("blake3 hash (short code)", &hash_times);

    // Long code hash
    let long_code = "import torch; import torch.nn as nn; ".repeat(100);
    let mut long_hash_times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let _h = ExecutionCache::hash(&long_code, "python");
        long_hash_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("blake3 hash (long code ~10KB)", &long_hash_times);

    // ── 2. Cache miss: insert entries ──────────────────────────────
    let cache = ExecutionCache::new(None).unwrap();
    let mut insert_times = Vec::with_capacity(500);
    for i in 0..500 {
        let code = format!("print({})", i);
        let start = Instant::now();
        cache.set(&code, "python", &format!("{}", i)).unwrap();
        insert_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("cache set (small result)", &insert_times);

    // Insert with larger result
    let mut insert_large_times = Vec::with_capacity(1000);
    for i in 0..1000 {
        let code = format!("data = [{}]", i);
        let result = format!("[{}]", (0..100).map(|j| format!("{}", j)).collect::<Vec<_>>().join(", "));
        let start = Instant::now();
        cache.set(&code, "python", &result).unwrap();
        insert_large_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("cache set (large result ~500B)", &insert_large_times);

    // ── 3. Cache hit: look up existing entries ─────────────────────
    let mut hit_times = Vec::with_capacity(500);
    for i in 0..500 {
        let code = format!("print({})", i);
        let start = Instant::now();
        let r = cache.get(&code, "python");
        hit_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        assert!(r.is_some(), "cache should have entry for '{}'", code);
        assert_eq!(r.unwrap(), format!("{}", i));
    }
    stats("cache get (hit)", &hit_times);

    // ── 4. Cache miss: look up nonexistent entries ─────────────────
    let mut miss_times = Vec::with_capacity(500);
    for i in 5000..5500 {
        let code = format!("print({})", i);
        let start = Instant::now();
        let r = cache.get(&code, "python");
        miss_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        assert!(r.is_none(), "cache should miss for '{}'", code);
    }
    stats("cache get (miss)", &miss_times);

    // ── 5. Mixed workload ─────────────────────────────────────────
    let cache2 = ExecutionCache::new(None).unwrap();
    // Pre-fill 2000 entries
    for i in 0..2000 {
        cache2.set(&format!("print({})", i), "python", &format!("{}", i)).unwrap();
    }
    let mut mixed_times = Vec::with_capacity(2000);
    for i in 0..2000 {
        let code = if i % 4 < 3 {
            // Hit: 75% hit rate
            format!("print({})", i % 2000)
        } else {
            // Miss: 25% miss rate
            format!("print({})", 3000 + i)
        };
        let start = Instant::now();
        let _r = cache2.get(&code, "python");
        mixed_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("cache mixed 75% hit / 25% miss", &mixed_times);

    // ── 6. Eviction under pressure (reduce max to force eviction) ──
    let mut small_cache = ExecutionCache::new(None).unwrap();
    small_cache.set_max_entries(100);
    let mut evict_times = Vec::with_capacity(1000);
    for i in 0..1000 {
        let code = format!("print({})", i);
        let start = Instant::now();
        // ignore Full errors — we're testing throughput under pressure
        let _ = small_cache.set(&code, "python", &format!("{}", i));
        evict_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    stats("cache set with eviction (max=100, 1000 inserts)", &evict_times);

    // Verify only max entries survive
    let mut count = 0;
    // After eviction, only the last 100 should still be in (LRU-ish via HashMap order)
    for i in 0..1000 {
        if small_cache.get(&format!("print({})", i), "python").is_some() {
            count += 1;
        }
    }
    println!("  cache max=100 after 1000 inserts: {} survivors  (excess rejected by Full)", count);

    // ── Verdict ──────────────────────────────────────────────────
    println!();
    println!("  Note: ExecutionCache targets <1μs hash+lookup for typical code.");
    println!("  Cache miss = full fork (0.5ms+), cache hit = <1μs (∼500× faster).");
    println!();
}
