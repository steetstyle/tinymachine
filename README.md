# TinyMachine

Ultra-light KVM-based code execution sandbox. Fork a VM in ~0.5ms, memory overhead ~100KB per fork, binary ~2.2MB.

```bash
tinymachine exec --lang wasm '
    (module
        (memory (export "memory") 1)
        (func (export "main")
            i32.const 0
            i32.const 42
            i32.store offset=0
        )
    )'                                      # 4µs
tinymachine exec --lang python 'print(1)'     # ~1.8ms (warm, requires template)
tinymachine template build python --variant minimal
```

## Architecture

Three execution tiers, same `SandboxBackend` trait:

```
┌──────────────────────────────────────────────────────────────┐
│                     SandboxBackend trait                      │
│  init(&mut self, variant)  exec(&mut self, code) → String    │
│  reset(&mut self)          destroy(&mut self)                 │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
     ┌─────────▼─────────┐      ┌─────────▼─────────┐
     │   Tier 1: Wasm     │      │  Tier 2: KVM Fork  │
     │  wasmtime in-proc  │      │  CoW + MAP_PRIVATE │
     │  2-4µs latency     │      │  ~0.5ms latency    │
     │  Wasm linear mem   │      │  Full VM isolation  │
     └───────────────────┘      └─────────┬───────────┘
                                          │
                               ┌──────────▼──────────┐
                               │  Tier 3: Fresh Boot   │
                               │  QEMU / direct KVM    │
                               │  ~1s, GPU passthrough │
                               └─────────────────────┘
```

### Tier 1 — Wasm (wasmtime, in-process)

For pure computation. No kernel involvement. `WasmSandbox` wraps wasmtime with pooling allocator and fuel metering.

```rust
use tinymachine_fork::wasm::eval_wat;

let result = eval_wat(r#"(module
    (memory (export "memory") 1)
    (func (export "main")
        i32.const 0
        i32.const 42
        i32.store offset=0
    )
)"#)?;
```

### Tier 2 — KVM CoW Fork

The core engine. A VM boots once, snapshot is taken. Each exec: `mmap(MAP_PRIVATE)` the snapshot memory → kernel copy-on-write, `KVM_CREATE_VM` + restore CPU state → `KVM_RUN`.

```
Snapshot (128MB, file-backed)
    │
    ├── mmap(MAP_PRIVATE) → Fork #1 (CoW: only dirty pages copied)
    ├── mmap(MAP_PRIVATE) → Fork #2
    ├── mmap(MAP_PRIVATE) → Fork #3
    └── ... → Fork #N  (shared clean pages, ~100KB private per fork)
```

Key decisions (why no Firecracker/QEMU):
- Direct KVM ioctl, no HTTP API, no serialization — `fork()` is a direct fn call, ~0.5µs overhead vs ~100µs for Unix socket IPC
- No device model except 16550 UART + virtio-net proxy — boot ~15ms vs Firecracker's ~125ms
- No irqchip by default — raw `KVM_INTERRUPT` vector 0x20 injection on HLT (saves ~1ms per fork from PIT/PIC/IOAPIC creation)

### Tier 3 — Fresh Boot

Full VM boot from kernel+initrd on demand. Required for GPU passthrough (VFIO) and long-running stateful environments.

`FreshBootBackend` supports two optional flags set before `init()`:

- **`capture_snapshot = true`** — after a successful boot, the VM state is saved to the template registry so Tier 2 (CoW fork) can reuse it. This guarantees both tiers use the same memory size and initrd, preventing the "snapshot builder vs fresh boot" divergence that caused silent file-extraction failures.
- **`memory_size_override: Option<u64>`** — overrides the automatic memory size selection (by default derived from `variant::boot_memory_size_bytes()`). Useful for manual tuning without changing variant definitions.

```rust
let mut backend = FreshBootBackend::new();
backend.capture_snapshot = true;          // Tier 3 → Tier 2 snapshot
backend.memory_size_override = Some(768 * 1024 * 1024);  // force 768 MB
backend.init(&variant)?;
```

### Variant Memory Sizing

Memory size per variant is defined in a single function `variant::boot_memory_size_bytes()` used by both `build_snapshot.rs` and `fresh_boot.rs`:

| Variant names | Memory | Reason |
|---------------|--------|--------|
| `pytorch`, `pytorch-cpu`, `pytorch-nv` | ~4 GB − 20 MB | Below IOAPIC hole for VFIO PCI BAR space |
| `tinygrad-nv` | 768 MB | Initramfs ~281 MB uncompressed |
| `tinygrad`, `tinygrad-cpu`, `numpy` | 512 MB | Initrd ~80-100 MB uncompressed; tmpfs needs 2× headroom |
| all others (`minimal`, …) | 128 MB | Default |

Override from CLI (snapshot builder):
```bash
cargo run --bin build-snapshot -- --variant tinygrad-cpu --memory-mb 1024
```

## How It Works

### Fork Engine

```rust
use tinymachine_fork::{kvm, fork::ForkEngine};

let kvm = kvm::Kvm::new()?;
let snapshot = registry.load_snapshot(&variant)?;
let engine = ForkEngine::new(kvm, snapshot, vcpu_mmap_size);

// Each call creates a fresh sandbox
let mut vm = engine.fork()?;
unsafe { vm.run_code("print('hello')")?; }
```

CPU state restore order (sequence matters, wrong order = crash):
1. CPUID (from cache, avoids ioctl per fork)
2. sregs (segments, CRx, EFER)
3. regs (general purpose, RIP, RSP)
4. MSRs (syscall entries, segment bases)
5. XCRs (XCR0 for AVX/SSE)
6. XSAVE (clean state matching XCR0)

### SandboxBackend Trait

```rust
use tinymachine_api::{SandboxBackend, ExecutionTier, Variant};

// Register backends at startup
tinymachine_fork::register_all_backends();

// Create backend by tier
let mut backend = tinymachine_api::create_backend(ExecutionTier::Wasm)?;
backend.init(&Variant::new("wasm", "minimal", "base"))?;
let output = backend.exec(r#"(module
    (memory (export "memory") 1)
    (func (export "main")
        i32.const 0
        i32.const 42
        i32.store offset=0
    )
)"#)?;
backend.reset()?;
backend.destroy()?;
```

### EPT Shared Memory

Zero-copy shared memory across all forks. 1000 forks × 10GB dataset = 10GB RAM (not 10TB).

```rust
engine.add_shared_region(
    SharedMemoryRegion::open("/data/model.bin")?,
    0x100000,  // guest physical address
);
```

### UOps Security

Code is decomposed into micro-ops before `KVM_RUN`. Policy engine enforces default-deny allowlist:

```rust
use tinymachine_fork::uops::{UOpsAnalyzer, PolicyEngine};

let analyzer = UOpsAnalyzer::new(policy);
let uops = analyzer.analyze(code)?;  // returns PolicyViolation if blocked
```

### Execution Cache

Result memoization via blake3 hash + SQLite. Same code → cache hit → 0 fork overhead:

```rust
let cache = ExecutionCache::open(path)?;
let result = cache.get(code, "python")
    .unwrap_or_else(|| {
        let output = execute(code);
        cache.set(code, "python", &output);
        output
    });
```

### Seccomp-BPF

Per-backend seccomp filters installed at `exec()` time. Wasm gets read/write/exit only. KVM fork gets KVM ioctls + mmap + futex. Fresh boot gets everything.

## Benchmarks

### Fork Latency (128MB snapshot)

| Method | p50 | p99 | Notes |
|--------|-----|-----|-------|
| CoW fork (file-backed) | 1.8ms | 2.1ms | Real deployment mode |
| Memcpy fork (anonymous) | 108ms | 112ms | Phase 1 baseline (replaced) |
| Batch fork (32, amortized) | 115µs/fork | — | Zero context-switch |
| Pool acquire (warm) | 0.1µs | — | Real exec path |

### Wasm

| Metric | Value |
|--------|-------|
| Cold start (compile + exec) | ~50µs |
| Warm exec (cached module) | ~0.6µs |
| Module cache hit rate | 100% for repeated calls |
| Fuel limit | 100k instructions (configurable) |

### Binary Size

| Build | Size |
|-------|------|
| `tinymachine` CLI (release, wasm) | 5.1MB |
| `tinymachine` CLI (release, no wasm) | 1.7MB |
| `libtinymachine_fork.a` | ~2.2MB |

### Comparison

| System | Fork Latency | Per-Fork Memory | Binary Size | Isolation |
|--------|-------------|-----------------|-------------|-----------|
| **TinyMachine** (CoW) | **0.5-1.8ms** | **~100KB** | **1.7-5.1MB** | KVM VM (EPT) |
| ZeroBoot | 0.79ms | ~265KB | ~10MB | KVM VM |
| Firecracker (fork) | ~8ms | ~5MB | ~15MB | KVM VM |
| Firecracker (boot) | ~150ms | ~128MB | ~15MB | KVM VM |
| Docker (cold) | ~200ms | ~50MB | ~1GB+ | cgroup/namespaces |
| bwrap (bubblewrap) | ~10ms | ~2MB | ~1MB | user namespace |

## Project Status

| Feature | Status | Details |
|---------|--------|---------|
| Wasm Tier 1 (wasmtime) | ✅ | Pooling allocator, module cache, fuel metering |
| KVM CoW Fork Tier 2 | ✅ | memfd + MAP_PRIVATE, CPU state restore, EPT |
| Fresh Boot Tier 3 | ✅ | kernel+initrd, VFIO GPU passthrough |
| SandboxBackend trait | ✅ | 4-method lifecycle + factory registry |
| EPT shared memory | ✅ | Zero-copy RO region across forks |
| Template snapshots | ✅ | Build, save, load, list, versioned |
| Layer composition | ✅ | Dynamic initrd assembly, conflict detection |
| Execution cache | ✅ | blake3 + SQLite memoization |
| UOps analyzer | ✅ | Micro-op security + policy engine |
| Seccomp-BPF | ✅ | Per-backend syscall allowlists |
| Symbolic profiler | ✅ | AST-based RAM/CPU/GPU estimation |
| Lazy fork + batch | ✅ | Defer + batch + realize |
| Resource scheduler | ✅ | CPU pin, cgroup v2, GPU queue |
| GPU (VFIO) works | 🟡 | AD104 power-gating root-caused (nova-core ref) |
| Unikernel mode | ⬜ | Phase 3+ |

## Usage

```bash
# Build
cargo build --release

# WASM code execution (takes WAT — WebAssembly Text Format)
tinymachine exec --lang wasm '(module (func (export "_start")))'

# Template management
tinymachine template build python --variant minimal   # Build a snapshot
tinymachine template list                               # List available templates

# Layer management
tinymachine layer list                                  # List installed layers

# Version info
tinymachine version
```

## Dependencies

Minimal. No tokio, no async runtime. Direct syscalls (epoll/io_uring for network).

| Crate | Depends On |
|-------|-----------|
| `tinymachine-fork` | `tinymachine-api`, `tinymachine-config`, `tinymachine-ir`, `libc`, `wasmtime` (optional) |
| `tinymachine-api` | `tinymachine-ir`, `serde` |
| `tinymachine-config` | `serde`, `toml` |
| `tinymachine-ir` | `rustpython-parser` (optional) |

## License

Dual MIT / Apache 2.0
