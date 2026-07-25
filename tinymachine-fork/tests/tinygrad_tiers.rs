//! Tinygrad Tier 2 (KVM Fork) + Tier 3 (Fresh Boot) integration tests.
//!
//! Tests that the tinygrad library works inside KVM sandboxes:
//!
//!   Tier 3 (Fresh Boot):
//!     Boots `vmlinux-base` + `tinygrad-cpu` initrd, runs tinygrad tensor ops
//!     inside the guest and verifies output.
//!
//!   Tier 2 (KVM Fork):
//!     If a pre-built snapshot for tinygrad-cpu exists, forks a CoW VM and
//!     runs the same tinygrad code inside.
//!
//! Prerequisites:
//!   - Kernel: tinymachine-fork/templates/kernel/vmlinux-base
//!   - Initrd: tinymachine-fork/templates/python/v1/tinygrad-cpu/initrd.gz
//!   - KVM must be available (/dev/kvm)
//!   - Tier 2 additionally requires a snapshot at
//!     tinymachine-fork/templates/python/v1/tinygrad-cpu/mem

use std::path::PathBuf;
use std::time::Instant;

// ─── Helper: tinymachine-fork/templates/ base path ───────────────────

fn tinymachine_templates() -> PathBuf {
    // We're in tinymachine-fork/tests/ — go up to workspace root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("templates")
}

fn kernel_path() -> PathBuf {
    tinymachine_templates().join("kernel").join("vmlinux-base")
}

fn tinygrad_cpu_initrd() -> PathBuf {
    tinymachine_templates()
        .join("python")
        .join("v1")
        .join("tinygrad-cpu")
        .join("initrd.gz")
}

fn tinygrad_cpu_snapshot_mem() -> PathBuf {
    tinymachine_templates()
        .join("python")
        .join("v1")
        .join("tinygrad-cpu")
        .join("mem")
}

// ─── Tinygrad test code ─────────────────────────────────────────────

const TINYGRAD_TEST_CODE: &str = r#"
import sys
sys.path.insert(0, '/usr/lib/python3.12/dist-packages')
sys.path.insert(0, '/usr/lib/python3.12/site-packages')

from tinygrad import Tensor

# Test 1: Import and version
print(f"tinygrad imported successfully")

# Test 2: Create tensors (lazy, no JIT needed)
x = Tensor([1, 2, 3])
y = Tensor([4, 5, 6])
z = x + y
print(f"add graph: {x.shape} + {y.shape} -> {z.shape}")

# Test 3: Matrix multiply graph
a = Tensor.randn(3, 4)
b = Tensor.randn(4, 2)
c = a @ b
print(f"matmul graph: {a.shape} @ {b.shape} -> {c.shape}")

# Test 4: ReLU graph
t = Tensor([-2, -1, 0, 1, 2])
r = t.relu()
print(f"relu graph: input shape {t.shape} -> output shape {r.shape}")

# Test 5: Neural network layer (graph only)
from tinygrad.nn import Linear
linear = Linear(4, 2)
inp = Tensor.randn(3, 4)
out = linear(inp)
print(f"linear layer graph: input(3,4) -> output(3,2): shape = {out.shape}")

# Test 6: Dtype and device introspection
print(f"x device: {x.device}, dtype: {x.dtype}")
print(f"z device: {z.device}, dtype: {z.dtype}")

# Test 7: Shape manipulation
x2 = x.reshape(3, 1)
print(f"reshape: {x.shape} -> {x2.shape}")

# Test 8: Tensor creation helpers
z = Tensor.zeros(3, 4)
o = Tensor.ones(2, 3)
f = Tensor.full((2, 2), 7)
print(f"zeros(3,4): {z.shape}, ones(2,3): {o.shape}, full(2,2,7): {f.shape}")

print("ALL TINYGRAD TESTS PASSED")
"#;

// ─── Prerequisites check ────────────────────────────────────────────

fn kvm_available() -> bool {
    std::fs::metadata("/dev/kvm").is_ok()
}

// ═════════════════════════════════════════════════════════════════════
// Tier 3: Fresh Boot
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_tinygrad_tier3_freshboot_cpu() {
    if !kvm_available() {
        eprintln!("Skipping: KVM not available");
        return;
    }

    let kernel = kernel_path();
    let initrd = tinygrad_cpu_initrd();

    if !kernel.exists() {
        eprintln!("Skipping: kernel not found at {}", kernel.display());
        eprintln!("  Build: bash tools/build-variant-initramfs.sh tinygrad-cpu");
        return;
    }
    if !initrd.exists() {
        eprintln!("Skipping: tinygrad-cpu initrd not found at {}", initrd.display());
        eprintln!("  Build: bash tools/build-variant-initramfs.sh tinygrad-cpu");
        return;
    }

    // Register backends so create_backend("freshboot") works
    tinymachine_fork::register_all_backends();

    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fresh_boot::FreshBootBackend;

    let variant = tinymachine_api::variant::Variant::new("python", "tinygrad-cpu", "base");
    eprintln!("\n═══ Tier 3 FreshBoot: variant {}/{} ═══", variant.lang, variant.variant);

    let mut backend = FreshBootBackend::new();

    // init() — boot kernel + initrd
    let t0 = Instant::now();
    SandboxBackend::init(&mut backend, &variant)
        .expect("FreshBootBackend init() should boot VM");
    let boot_ms = t0.elapsed().as_secs_f64() * 1000.0;
    eprintln!("  Boot complete in {boot_ms:.1} ms");

    // exec() — run tinygrad test code
    let t1 = Instant::now();
    let output = SandboxBackend::exec(&mut backend, TINYGRAD_TEST_CODE)
        .expect("exec() tinygrad code should succeed");
    let exec_ms = t1.elapsed().as_secs_f64() * 1000.0;
    eprintln!("  Exec complete in {exec_ms:.1} ms");

    // Verify results
    eprintln!("Guest output:\n{}", &output[..output.len().min(2000)]);

    assert!(
        output.contains("ALL TINYGRAD TESTS PASSED"),
        "tinygrad tests should all pass, got (first 500 chars): {:?}",
        &output[..output.len().min(500)]
    );

    // Check specific test results
    assert!(output.contains("add graph:"), "should have add result");
    assert!(output.contains("matmul graph:"), "should have matmul result");
    assert!(output.contains("relu graph:"), "should have relu result");
    assert!(output.contains("linear layer graph:"), "should have linear layer result");
    assert!(output.contains("reshape:"), "should have reshape result");
    assert!(output.contains("x device:"), "should have device introspection");

    // destroy()
    SandboxBackend::destroy(&mut backend)
        .expect("destroy() should succeed");

    eprintln!("═══ Tier 3 PASSED ({boot_ms:.1}ms boot + {exec_ms:.1}ms exec) ═══");
}

// ═════════════════════════════════════════════════════════════════════
// Tier 2: KVM Fork (requires pre-built snapshot)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_tinygrad_tier2_kvm_fork() {
    if !kvm_available() {
        eprintln!("Skipping: KVM not available");
        return;
    }

    let kernel = kernel_path();
    let mem = tinygrad_cpu_snapshot_mem();

    if !kernel.exists() {
        eprintln!("Skipping: kernel not found at {}", kernel.display());
        return;
    }
    if !mem.exists() {
        eprintln!("Skipping: tinygrad-cpu snapshot not found at {}", mem.display());
        eprintln!("  Build a snapshot first:");
        eprintln!("    1. Ensure tinygrad-cpu initrd exists");
        eprintln!("    2. Run Tier 3 test (freshboot) which captures snapshot");
        eprintln!("    3. Or use: tinyos template build tinygrad-cpu");
        return;
    }

    tinymachine_fork::register_all_backends();

    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fork::KvmForkBackend;

    let variant = tinymachine_api::variant::Variant::new("python", "tinygrad-cpu", "base");
    eprintln!("\n═══ Tier 2 KVM Fork: variant {}/{} ═══", variant.lang, variant.variant);

    let mut backend = KvmForkBackend::new();

    // init() — load snapshot, prepare fork engine
    let t0 = Instant::now();
    SandboxBackend::init(&mut backend, &variant)
        .expect("KvmForkBackend init() should load snapshot");
    let init_us = t0.elapsed().as_secs_f64() * 1_000_000.0;
    eprintln!("  Init (snapshot load) in {init_us:.0} µs");

    // exec() — fork from snapshot, inject code, collect output
    let t1 = Instant::now();
    let output = SandboxBackend::exec(&mut backend, TINYGRAD_TEST_CODE)
        .expect("exec() tinygrad code via KVM fork should succeed");
    let exec_us = t1.elapsed().as_secs_f64() * 1_000_000.0;
    eprintln!("  Exec (fork + run) in {exec_us:.0} µs");

    // Verify results
    eprintln!("Guest output:\n{}", &output[..output.len().min(2000)]);

    assert!(
        output.contains("ALL TINYGRAD TESTS PASSED"),
        "tinygrad tests should all pass, got (first 500 chars): {:?}",
        &output[..output.len().min(500)]
    );

    assert!(output.contains("add graph:"), "should have add result");
    assert!(output.contains("matmul graph:"), "should have matmul result");
    assert!(output.contains("relu graph:"), "should have relu result");
    assert!(output.contains("linear layer graph:"), "should have linear layer result");

    // destroy()
    SandboxBackend::destroy(&mut backend)
        .expect("destroy() should succeed");

    eprintln!("═══ Tier 2 PASSED ({init_us:.0}µs init + {exec_us:.0}µs exec) ═══");
}
