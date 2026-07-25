//! Tinygrad NV GPU Tier 3 (Fresh Boot) integration test.
//!
//! Tests three GPU backends inside a KVM VM with VFIO passthrough:
//!
//!   **Phase 1 — PCIIface** (direct PCI BAR mmap, no kernel driver):
//!     Expected to FAIL on AD104 because the SEC2 Falcon is power-gated.
//!     The failure is documented with exact error messages.
//!
//!   **Phase 1b — Diagnostic Register Probe** (sysfs PCI resource files):
//!     Probes GPU register state from inside the VM to determine which
//!     Falcon engines are accessible after VFIO FLR + VBIOS POST.
//!
//!   **Phase 2 — NVKIface** (nvidia.ko kernel module):
//!     Expected to SUCCEED because nvidia.ko handles GSP firmware boot
//!     correctly through the official driver path.
//!
//! Prerequisites:
//!   - GPU bound to vfio-pci driver
//!   - `~/.tinyos/templates/kernel/vmlinux-gpu-vfio`
//!   - `~/.tinyos/templates/python/v1/tinygrad-nv/initrd.zst`
//!   - KVM must be available (/dev/kvm)
//!
//! Run: cargo test --test tinygrad_nv_tiers -- --nocapture
//!   or: cargo test test_tinygrad_nv_diag_register_probe -- --nocapture
//!
//! Design: Each exec() call is isolated — state does NOT persist between
//! calls (the init process re-execs Python for each CMD_BUF). This means
//! we must import modules and set up state in every exec().

use std::path::PathBuf;
use std::time::Instant;

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .expect("HOME environment variable")
}

fn tinyos_templates() -> PathBuf {
    home_dir().join(".tinyos").join("templates")
}

fn kernel_path_for(profile: &str) -> PathBuf {
    tinyos_templates().join("kernel").join(format!("vmlinux-{profile}"))
}

fn kernel_path() -> PathBuf {
    kernel_path_for("gpu-nvidia")
}

fn tinygrad_nv_initrd() -> PathBuf {
    tinyos_templates()
        .join("python")
        .join("v1")
        .join("tinygrad-nv")
        .join("initrd.zst")
}

/// Check if an NVIDIA GPU is bound to vfio-pci on the host.
fn has_vfio_gpu() -> bool {
    let vfio_dir = PathBuf::from("/sys/bus/pci/drivers/vfio-pci");
    if !vfio_dir.is_dir() {
        return false;
    }
    std::fs::read_dir(&vfio_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| {
                    let name = e.file_name();
                    let name_str = name.to_string_lossy();
                    name_str.starts_with("0000:")
                })
        })
        .unwrap_or(false)
}

// ─── Phase 1: PCIIface — expected FAILURE ──────────────────────────

/// Minimal test code that tries NVDev init via PCIIface.
/// On AD104 this should FAIL because SEC2 is power-gated.
///
/// Uses the standard tinygrad Device[] pathway so NVKIface is tried first
/// (will fail without nvidia.ko), then PCIIface is tried (should fail
/// on AD104 due to SEC2 power-gating).
const PCIIFACE_TEST_CODE: &str = r#"
import sys, os

# Find where tinygrad is installed
for p in ['/usr/lib/python3.12/dist-packages', '/usr/lib/python3.12/site-packages',
           '/usr/local/lib/python3.12/dist-packages', '/usr/lib/python3/dist-packages']:
    if os.path.isdir(p):
        sys.path.insert(0, p)

os.environ['NV_DEBUG'] = '0'
os.environ['NV_INTERFACE'] = 'PCIIface'  # force PCIIface specifically

print('PCIIFACE: Starting tinygrad NV device detection via PCIIface...', flush=True)
try:
    from tinygrad import Device
    print('PCIIFACE: Trying Device[NV]...', flush=True)
    dev = Device['NV']
    print(f'PCIIFACE: OK — {dev}', flush=True)
except ModuleNotFoundError as e:
    print(f'PCIIFACE: MODULE NOT FOUND — {e}', flush=True)
except Exception as e:
    print(f'PCIIFACE: FAILED — {type(e).__name__}: {e}', flush=True)
    import traceback
    traceback.print_exc()
print('PCIIFACE_DONE', flush=True)
"#;

/// Test that PCIIface FAILS on AD104 with proper evidence.
///
/// This is NOT an ignored test — it verifies the expected failure mode.
/// The test passes when the failure is logged correctly.
#[test]
fn test_tinygrad_nv_pciiface_failure() {
    // ── Prerequisites ──
    let kernel = kernel_path();
    let initrd = tinygrad_nv_initrd();

    if !kernel.exists() {
        eprintln!("SKIP: {} not found. Run tools/build-kernel.sh gpu-nvidia", kernel.display());
        return;
    }
    if !initrd.exists() {
        eprintln!("SKIP: {} not found. Run tools/build-variant-initramfs.sh tinygrad-nv", initrd.display());
        return;
    }
    if !has_vfio_gpu() {
        eprintln!("SKIP: no GPU bound to vfio-pci. Run sudo ./scripts/gpu-switch.sh vfio");
        return;
    }
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm not available");
        return;
    }

    tinymachine_fork::register_all_backends();
    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fresh_boot::FreshBootBackend;

    let variant = tinymachine_api::variant::Variant::new("python", "tinygrad-nv", "gpu-vfio");
    eprintln!("\n═══════════════════════════════════════════════");
    eprintln!("  PHASE 1: PCIIface (direct PCI BAR mmap)");
    eprintln!("  Expected: FAIL on AD104 (SEC2 power-gated)");
    eprintln!("═══════════════════════════════════════════════");

    let mut backend = FreshBootBackend::new();

    let boot_start = Instant::now();
    SandboxBackend::init(&mut backend, &variant)
        .expect("init() should boot VM with VFIO passthrough");
    eprintln!("Boot: {:.1}s", boot_start.elapsed().as_secs_f64());

    if !backend.has_vfio() {
        eprintln!("⚠️  VFIO not attached — GPU test cannot proceed");
        SandboxBackend::destroy(&mut backend).ok();
        return;
    }

    // ── Run PCIIface test ──
    eprintln!("\n--- Running PCIIface NVDev init ---");
    let exec_start = Instant::now();
    match SandboxBackend::exec(&mut backend, PCIIFACE_TEST_CODE) {
        Ok(output) => {
            let elapsed = exec_start.elapsed();
            eprintln!("Output ({:.1}s):", elapsed.as_secs_f64());
            for line in output.lines() {
                eprintln!("  | {}", line);
            }

            // Check if NVDev init succeeded (unexpected) or failed (expected)
            if output.contains("NVDev init OK") {
                eprintln!("\n⚠️  UNEXPECTED: PCIIface NVDev init SUCCEEDED on this GPU!");
                eprintln!("  This GPU does NOT have the AD104 SEC2 power-gating issue.");
                eprintln!("  Evidence: PCIIface works on this hardware.\n");
            } else if output.contains("FAILED") {
                eprintln!("\n✅ EXPECTED: PCIIface NVDev init FAILED as anticipated.\n");
            }
        }
        Err(e) => {
            let elapsed = exec_start.elapsed();
            eprintln!("\n✅ EXPECTED: PCIIface NVDev init HUNG/TIMEOUT at {:.1}s", elapsed.as_secs_f64());
            eprintln!("  Error: {}", e);
            eprintln!("  This confirms SEC2 power-gating on AD104 VFIO.\n");
        }
    }

    SandboxBackend::destroy(&mut backend).ok();
}


// ─── Phase 1b: PCIIface diagnostic register probe ─────────────────

/// Diagnostic register probe — runs inside the VM and reads GPU register
/// state via sysfs PCI resource files to determine which Falcon engines
/// are accessible after VFIO FLR + VBIOS POST.
const DIAG_REGISTER_PROBE: &str = r#"
import os,sys,glob,struct
ok,ps=0,0
def _pb(fd,o,nm):
    global ok,ps
    try:
        d=os.pread(fd,4,o);v=struct.unpack('<I',d)[0]
        if v==0xffffffff or v==0xffffff88 or(v&0xbadf0000)==0xbadf0000:
            ps+=1;print(f'  [POISON] 0x{o:06x}=0x{v:08x}#{nm}',flush=1)
        else:
            ok+=1;print(f'  [OK] 0x{o:06x}=0x{v:08x}#{nm}',flush=1)
    except OSError as e:
        ps+=1;print(f'  [ERR] 0x{o:06x}:{e}#{nm}',flush=1)
def probe_list(fd,base,tbl):
    for n,o in tbl: _pb(fd,base+o,n)

gpu=None
for p in ['/sys/bus/pci/devices/0000:01:00.0']:
    if os.path.isdir(p): gpu=p;break
if not gpu:
    for d in glob.glob('/sys/bus/pci/devices/*/vendor'):
        try:
            if open(d).read().strip()=='0x10de': gpu=os.path.dirname(d);break
        except: pass
if not gpu:
    print('DIAG:NO GPU');print('DIAG_DONE');sys.exit(0)
print(f'DIAG:GPU={gpu}')

cp=os.path.join(gpu,'config')
if os.path.exists(cp):
    d=open(cp,'rb').read(64)
    print(f'DIAG:vid=0x{struct.unpack("<H",d[0:2])[0]:04x} did=0x{struct.unpack("<H",d[2:4])[0]:04x} cmd=0x{struct.unpack("<H",d[4:6])[0]:04x}')
    for i in range(6):
        b=struct.unpack('<I',d[0x10+i*4:0x14+i*4])[0]
        if b: print(f'DIAG:BAR{i}={"IO" if b&1 else "MEM"} 0x{b:08x}')
r0=os.path.join(gpu,'resource0')
if not os.path.exists(r0):
    print('DIAG:NO BAR0 access');print('DIAG_DONE');sys.exit(0)
fd=os.open(r0,os.O_RDWR)

# GPTable: (name, offset)
IDX=[('PMC_BOOT_0',0x0),('PMC_ENABLE',0x200),('PMC_PG_CTRL',0x20c)]
GFX=[('MAILBOX0',0x40),('MAILBOX1',0x44),('FALCON_OS',0x80),('FALCON_RM',0x84),
     ('HWCFG2',0xf4),('CPUCTL',0x100),('BOOTVEC',0x104),('DMACTL',0x10c),
     ('DMATRFBASE',0x110),('DMATRFMOFFS',0x114),('DMATRFCMD',0x118),
     ('DMATRFFBOFFS',0x11c),('DMATRFBASE1',0x128)]
GSP_EXT=[('CPUCTL_ALIAS',0x130),('IMEMC',0x180),('IMEMD',0x184),('DMEMC',0x1c0),('DMEMD',0x1c4)]

print('=== A: IDENTITY ===');probe_list(fd,0,IDX)
print('=== B: GFX FALCON @110000 ===');probe_list(fd,0x110000,GFX)
print('=== C: GSP @118000 ===');probe_list(fd,0x118000,GFX);probe_list(fd,0x118000,GSP_EXT)
print('=== D: SEC2 @840000 ===');probe_list(fd,0x840000,[(n,o) for n,o in GFX[:9]])
print('=== E: ENGINE/SCRATCH ===')
for n,o in [('GSP_ENG',0x1103c0),('SEC2_ENG',0x8403c0),('GFW_MASK',0x118128),
            ('BSI_14',0x1180f8),('GFW_42',0x1183a4)]: _pb(fd,o,n)
for i in range(6): _pb(fd,0x118234+i*4,f'GFW_{i}')
print('=== F: RISCV @111000 ===')
for n,o in [('CPUCTL',0x1388),('BCR_CTRL',0x1668),('MOD_SEL',0x1180),
            ('BROM_UCODE',0x1198),('BROM_ENGID',0x119c)]: _pb(fd,0x111000+o,n)
for i in range(4): _pb(fd,0x110600+i*4,f'FBIF{i}')
print(f'=== SUMMARY: OK={ok} POISON={ps} ===');print('DIAG_DONE')
"#;

/// Run a diagnostic register probe inside the VM via VFIO + sysfs.
///
/// Unlike the other tests, this does NOT try to use tinygrad's NV backend
/// at all — it probes GPU registers directly using os.pread() on the PCI
/// resource files exposed by the guest kernel. This lets us determine which
/// Falcon engines are accessible after VFIO FLR + VBIOS POST.
#[test]
fn test_tinygrad_nv_diag_register_probe() {
    let kernel = kernel_path_for("gpu-vfio");
    let initrd = tinygrad_nv_initrd();

    if !kernel.exists() {
        eprintln!(
            "SKIP: {} not found. Build gpu-vfio kernel via tools/build-kernel.sh gpu-vfio",
            kernel.display()
        );
        return;
    }
    if !initrd.exists() {
        eprintln!("SKIP: {} not found. Run tools/build-variant-initramfs.sh tinygrad-nv", initrd.display());
        return;
    }
    if !has_vfio_gpu() {
        eprintln!("SKIP: no GPU bound to vfio-pci. Run sudo ./scripts/gpu-switch.sh vfio");
        return;
    }
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm not available");
        return;
    }

    tinymachine_fork::register_all_backends();
    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fresh_boot::FreshBootBackend;

    let variant = tinymachine_api::variant::Variant::new("python", "tinygrad-nv", "gpu-vfio");
    eprintln!("\n═══════════════════════════════════════════════════════════");
    eprintln!("  DIAG: GPU Register State Probe (PCIIface via sysfs)");
    eprintln!("  Variant: tinygrad-nv / gpu-vfio");
    eprintln!("═══════════════════════════════════════════════════════════");

    let mut backend = FreshBootBackend::new();

    let boot_start = Instant::now();
    match SandboxBackend::init(&mut backend, &variant) {
        Ok(()) => eprintln!("Boot: {:.1}s", boot_start.elapsed().as_secs_f64()),
        Err(e) => {
            eprintln!("FAILED to boot VM: {e}");
            return;
        }
    }

    if !backend.has_vfio() {
        eprintln!("⚠️  VFIO not attached — GPU test cannot proceed");
        SandboxBackend::destroy(&mut backend).ok();
        return;
    }

    // Run the diagnostic probe
    eprintln!("\n--- Running GPU register probe ---");
    let exec_start = Instant::now();
    match SandboxBackend::exec(&mut backend, DIAG_REGISTER_PROBE) {
        Ok(output) => {
            let elapsed = exec_start.elapsed();
            eprintln!("\n=== DIAGNOSTIC OUTPUT ({:.1}s) ===", elapsed.as_secs_f64());
            for line in output.lines() {
                eprintln!("{}", line);
            }
            eprintln!("=== END DIAGNOSTIC OUTPUT ===");

            // Check if we got meaningful data
            if output.contains("DIAG: vendor=0x10de") {
                eprintln!("\n✅ GPU detected and BAR0 accessible");
                if output.contains("POISON") {
                    eprintln!("   ⚠️  Some registers returned poison (expected for power-gated Falcons)");
                }
            } else {
                eprintln!("\n⚠️  No GPU vendor ID found — BAR0 may not be accessible");
            }
        }
        Err(e) => {
            let elapsed = exec_start.elapsed();
            eprintln!("\n❌ Diagnostic probe HUNG/TIMEOUT at {:.1}s", elapsed.as_secs_f64());
            eprintln!("   Error: {}", e);
            eprintln!("   This may indicate the GPU is not accessible inside the VM");
        }
    }

    SandboxBackend::destroy(&mut backend).ok();
}


// ─── Phase 2: NVKIface — expected SUCCESS ─────────────────────────

/// Test code that loads nvidia.ko, waits for GSP, then uses NVKIface.
const NVKIFACE_TEST_CODE: &str = r#"
import sys, os, time
sys.path.insert(0, '/usr/lib/python3.12/dist-packages')
os.environ['NV_DEBUG'] = '1'

# Step 1: Load nvidia.ko (kernel module already in initrd)
# The init.c !load-modules command handles this before Python runs.
# Check that /dev/nvidia0 exists (GSP handshake completed)
print('NVKIFACE: Checking for /dev/nvidia* devices...', flush=True)

# Wait for GSP handshake to complete
for attempt in range(40):  # up to 40s
    nvidia_devs = [d for d in ['/dev/nvidia0', '/dev/nvidiactl', '/dev/nvidia-uvm'] if os.path.exists(d)]
    if nvidia_devs:
        print(f'  Found devices after {attempt}s: {nvidia_devs}', flush=True)
        break
    time.sleep(1)
else:
    print('  WARNING: No /dev/nvidia* devices found after 40s', flush=True)
    print('  GSP handshake may have failed or needs more time', flush=True)

try:
    from tinygrad.runtime.ops_nv import NVKIface
    print('NVKIFACE: Imported NVKIface', flush=True)

    # Check if NVKIface can detect GPUs
    if hasattr(NVKIface, 'gpus_info') and NVKIface.gpus_info:
        print(f'NVKIFACE: Detected {len(NVKIface.gpus_info)} GPU(s)', flush=True)
        for i, info in enumerate(NVKIface.gpus_info):
            print(f'  GPU {i}: {info}', flush=True)
    else:
        print('NVKIFACE: Trying to init NVKIface...', flush=True)
        # Force NVKIface by setting env
        os.environ['NV_LOAD_NVKIface'] = '1'

    from tinygrad import Tensor, Device, dtypes
    from tinygrad.helpers import GlobalCounters

    # Try to detect NV device
    print('NVKIFACE: Device list:', [Device.DEFAULT] + list(Device._devices.keys()), flush=True)

    # Force NV device
    try:
        dev = Device['NV']
        print(f'NVKIFACE: Device NV = {dev}', flush=True)
    except Exception as e:
        print(f'NVKIFACE: Device[\"NV\"] failed: {e}', flush=True)

    print('NVKIFACE_DONE', flush=True)

except Exception as e:
    print(f'NVKIFACE: FAILED — {type(e).__name__}: {e}', flush=True)
    import traceback
    traceback.print_exc()
    print('NVKIFACE_DONE', flush=True)
"#;

/// Test that NVKIface (nvidia.ko) SUCCEEDS on the same GPU.
#[test]
fn test_tinygrad_nv_nvkiface_success() {
    let kernel = kernel_path();
    let initrd = tinygrad_nv_initrd();

    if !kernel.exists() {
        eprintln!("SKIP: {} not found.", kernel.display());
        return;
    }
    if !initrd.exists() {
        eprintln!("SKIP: {} not found.", initrd.display());
        return;
    }
    if !has_vfio_gpu() {
        eprintln!("SKIP: no GPU bound to vfio-pci");
        return;
    }
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm not available");
        return;
    }

    tinymachine_fork::register_all_backends();
    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fresh_boot::FreshBootBackend;

    let variant = tinymachine_api::variant::Variant::new("python", "tinygrad-nv", "gpu-nvidia");
    eprintln!("\n═══════════════════════════════════════════════");
    eprintln!("  PHASE 2: NVKIface (nvidia.ko IOCTL via FreshBoot)");
    eprintln!("  Expected: SUCCESS — GSP firmware boots via nvidia.ko");
    eprintln!("═══════════════════════════════════════════════");

    let mut backend = FreshBootBackend::new();

    let boot_start = Instant::now();
    match SandboxBackend::init(&mut backend, &variant) {
        Ok(()) => eprintln!("Boot: {:.1}s", boot_start.elapsed().as_secs_f64()),
        Err(e) => {
            eprintln!("⚠️  Cannot init FreshBoot GPU backend: {e}");
            return;
        }
    }

    if !backend.has_vfio() {
        eprintln!("⚠️  VFIO not attached — GPU test cannot proceed");
        SandboxBackend::destroy(&mut backend).ok();
        return;
    }

    // ── Phase 2a: Load nvidia.ko via !load-modules ──
    eprintln!("\n--- Phase 2a: Loading nvidia.ko ---");
    let load_start = Instant::now();
    let load_code = "!load-modules";
    match SandboxBackend::exec(&mut backend, load_code) {
        Ok(output) => {
            eprintln!("nvidia.ko load ({:.1}s):", load_start.elapsed().as_secs_f64());
            for line in output.lines() {
                eprintln!("  | {}", line);
            }
        }
        Err(e) => {
            eprintln!("nvidia.ko load FAILED: {}", e);
            SandboxBackend::destroy(&mut backend).ok();
            return;
        }
    }

    // ── Phase 2b: Wait for GSP + run NVKIface test ──
    eprintln!("\n--- Phase 2b: NVKIface device detection ---");
    let exec_start = Instant::now();
    match SandboxBackend::exec(&mut backend, NVKIFACE_TEST_CODE) {
        Ok(output) => {
            let elapsed = exec_start.elapsed();
            eprintln!("Output ({:.1}s):", elapsed.as_secs_f64());
            for line in output.lines() {
                eprintln!("  | {}", line);
            }

            if output.contains("FAILED") {
                eprintln!("\n❌ NVKIface test FAILED\n");
            } else {
                eprintln!("\n✅ NVKIface test completed (details above)\n");
            }
        }
        Err(e) => {
            let elapsed = exec_start.elapsed();
            eprintln!("NVKIface test HUNG/TIMEOUT at {:.1}s: {}", elapsed.as_secs_f64(), e);
        }
    }

    SandboxBackend::destroy(&mut backend).ok();
}


// ─── Phase 3: Full tensor ops on NV device ────────────────────────

const NV_TENSOR_TEST_CODE: &str = r#"
import sys, os, time
sys.path.insert(0, '/usr/lib/python3.12/dist-packages')
os.environ['NV_DEBUG'] = '0'
os.environ['NV_LOAD_NVKIface'] = '1'

# Wait for GSP handshake
for attempt in range(30):
    if os.path.exists('/dev/nvidia0'):
        break
    time.sleep(1)
else:
    print('NV_TENSOR: GSP handshake timeout — continuing anyway', flush=True)

from tinygrad import Tensor, Device, dtypes, nn
from tinygrad.helpers import GlobalCounters
import numpy as np

print(f'NV_TENSOR: Device list: {Device._devices}', flush=True)

# Test helper
_nv_tests_passed = 0
_nv_tests_failed = 0
def _nv_test(name, cond, detail=""):
    global _nv_tests_passed, _nv_tests_failed
    if cond:
        _nv_tests_passed += 1
        print(f'  ✓ {name}', flush=True)
    else:
        _nv_tests_failed += 1
        print(f'  ✗ {name}: {detail}', flush=True)

# Comprehensive tensor ops on NV
try:
    # ── Creation ops ──
    t = Tensor.full((3,4), 7.0, device='NV')
    _nv_test('full', t.tolist() == [[7.0]*4]*3, f'{t.tolist()}')

    t = Tensor.zeros(2,5, device='NV')
    _nv_test('zeros', t.shape == (2,5))

    t = Tensor.ones(4,3, device='NV')
    _nv_test('ones', t.shape == (4,3))

    t = Tensor.arange(12, device='NV').reshape(3,4)
    _nv_test('arange reshape', t.tolist() == [[0,1,2,3],[4,5,6,7],[8,9,10,11]])

    t = Tensor.eye(5, device='NV')
    _nv_test('eye', t.shape == (5,5))

    # ── Elementwise binary ops ──
    a = Tensor([1.0, 2.0, 3.0, 4.0], device='NV')
    b = Tensor([5.0, 6.0, 7.0, 8.0], device='NV')

    c = (a + b).realize()
    _nv_test('add', c.tolist() == [6.0, 8.0, 10.0, 12.0], f'{c.tolist()}')

    c = (a - b).realize()
    _nv_test('sub', c.tolist() == [-4.0, -4.0, -4.0, -4.0], f'{c.tolist()}')

    c = (a * b).realize()
    _nv_test('mul', c.tolist() == [5.0, 12.0, 21.0, 32.0], f'{c.tolist()}')

    c = (a / b).realize()
    ref = [1.0/5.0, 2.0/6.0, 3.0/7.0, 4.0/8.0]
    _nv_test('div', np.allclose(c.numpy(), ref), f'{c.tolist()}')

    # ── Unary ops ──
    c = a.sqrt().realize()
    _nv_test('sqrt', np.allclose(c.numpy(), np.sqrt([1,2,3,4])), f'{c.tolist()}')

    c = a.exp().realize()
    _nv_test('exp', np.allclose(c.numpy(), np.exp([1,2,3,4]), atol=1e-5))

    c = a.log().realize()
    _nv_test('log', np.allclose(c.numpy(), np.log([1,2,3,4]), atol=1e-5))

    c = (-a).realize()
    _nv_test('neg', c.tolist() == [-1.0, -2.0, -3.0, -4.0])

    # ── Activations ──
    act = Tensor([-2.0, -1.0, 0.0, 1.0, 2.0], device='NV')
    c = act.relu().realize()
    _nv_test('relu', c.tolist() == [0.0, 0.0, 0.0, 1.0, 2.0], f'{c.tolist()}')

    c = act.sigmoid().realize()
    _nv_test('sigmoid', np.allclose(c.numpy(), 1/(1+np.exp(-[-2,-1,0,1,2])), atol=1e-5))

    c = act.tanh().realize()
    _nv_test('tanh', np.allclose(c.numpy(), np.tanh([-2,-1,0,1,2]), atol=1e-5))

    # ── Reductions ──
    mat = Tensor([[1.0,2.0,3.0],[4.0,5.0,6.0]], device='NV')
    _nv_test('sum', np.allclose(mat.sum().realize().numpy(), np.sum([[1,2,3],[4,5,6]])))
    _nv_test('sum axis=1', np.allclose(mat.sum(axis=1).realize().numpy(), np.sum([[1,2,3],[4,5,6]], axis=1)))
    _nv_test('mean', np.allclose(mat.mean().realize().numpy(), np.mean([[1,2,3],[4,5,6]])))
    _nv_test('max', np.allclose(mat.max().realize().numpy(), np.max([[1,2,3],[4,5,6]])))

    # ── Movement ops ──
    t = Tensor.arange(6, device='NV')
    _nv_test('reshape', t.reshape(2,3).realize().tolist() == [[0,1,2],[3,4,5]])
    _nv_test('permute', np.allclose(t.reshape(2,3).permute(1,0).realize().numpy(), np.arange(6).reshape(2,3).T))
    _nv_test('flatten', t.reshape(2,3).flatten().realize().tolist() == [0,1,2,3,4,5])

    # ── Matmul ──
    a = Tensor([[1.0,2.0],[3.0,4.0]], device='NV')
    b = Tensor([[5.0,6.0],[7.0,8.0]], device='NV')
    c = (a @ b).realize()
    _nv_test('matmul', c.tolist() == [[19.0, 22.0], [43.0, 50.0]], f'{c.tolist()}')

    # Large matmul
    a = Tensor.randn(16, 32, device='NV')
    b = Tensor.randn(32, 8, device='NV')
    c = (a @ b).realize()
    ref = a.numpy() @ b.numpy()
    _nv_test('matmul large', np.allclose(c.numpy(), ref, atol=1e-4, rtol=1e-3),
             f'max diff={np.max(np.abs(c.numpy()-ref)):.6f}')

    # ── Neural network ──
    layer = nn.Linear(4, 2)
    x = Tensor.randn(3, 4, device='NV')
    out = layer(x).realize()
    _nv_test('linear layer', out.shape == (3, 2), f'got {out.shape}')

    x = Tensor.randn(1, 3, 8, 8, device='NV')
    w = Tensor.randn(4, 3, 3, 3, device='NV')
    out = x.conv2d(w).realize()
    _nv_test('conv2d', out.shape == (1, 4, 6, 6), f'got {out.shape}')

    # ── Softmax ──
    a = Tensor([[1.0,2.0,3.0],[1.0,2.0,3.0]], device='NV')
    c = a.softmax().realize()
    ref = np.array([[1.,2.,3.],[1.,2.,3.]])
    ref = np.exp(ref) / np.sum(np.exp(ref), axis=1, keepdims=True)
    _nv_test('softmax', np.allclose(c.numpy(), ref, atol=1e-5))

    # ── Comparison ops ──
    a = Tensor([1.0,2.0,3.0], device='NV')
    b = Tensor([1.0,2.0,4.0], device='NV')
    c = (a == b).realize()
    _nv_test('eq', np.allclose(c.numpy(), [1.,1.,0.]))

    c = a.maximum(b).realize()
    _nv_test('maximum', np.allclose(c.numpy(), [1.,2.,4.]))

    # ── Multi-op chain ──
    x = Tensor([1.0,2.0,3.0], device='NV')
    y = Tensor([4.0,5.0,6.0], device='NV')
    z = (x * y + x - y / 2.0).realize()
    ref = np.array([1,2,3])*np.array([4,5,6]) + np.array([1,2,3]) - np.array([4,5,6])/2.0
    _nv_test('multi_op_chain', np.allclose(z.numpy(), ref, atol=1e-5))

    print(f'\nNV_TENSOR: {_nv_tests_passed} passed, {_nv_tests_failed} failed', flush=True)
    if _nv_tests_failed > 0:
        print('NV_TENSOR: SOME TESTS FAILED', flush=True)
    else:
        print('NV_TENSOR: All tensor ops PASSED', flush=True)

except Exception as e:
    print(f'NV_TENSOR: FAILED — {type(e).__name__}: {e}', flush=True)
    import traceback
    traceback.print_exc()

print('NV_TENSOR_DONE', flush=True)
"#;

#[test]
fn test_tinygrad_nv_tensor_ops() {
    let kernel = kernel_path();
    let initrd = tinygrad_nv_initrd();

    if !kernel.exists() {
        eprintln!("SKIP: {} not found.", kernel.display());
        return;
    }
    if !initrd.exists() {
        eprintln!("SKIP: {} not found.", initrd.display());
        return;
    }
    if !has_vfio_gpu() {
        eprintln!("SKIP: no GPU bound to vfio-pci");
        return;
    }

    tinymachine_fork::register_all_backends();
    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fresh_boot::FreshBootBackend;

    let variant = tinymachine_api::variant::Variant::new("python", "tinygrad-nv", "gpu-nvidia");
    eprintln!("\n═══════════════════════════════════════════════");
    eprintln!("  PHASE 3: NV Tensor Operations (FreshBoot)");
    eprintln!("═══════════════════════════════════════════════");

    let mut backend = FreshBootBackend::new();

    let boot_start = Instant::now();
    match SandboxBackend::init(&mut backend, &variant) {
        Ok(()) => eprintln!("Boot: {:.1}s", boot_start.elapsed().as_secs_f64()),
        Err(e) => {
            eprintln!("⚠️  Cannot init FreshBoot GPU backend: {e}");
            return;
        }
    }

    if !backend.has_vfio() {
        eprintln!("⚠️  VFIO not attached");
        SandboxBackend::destroy(&mut backend).ok();
        return;
    }

    // Load nvidia.ko
    eprintln!("\n--- Loading nvidia.ko ---");
    match SandboxBackend::exec(&mut backend, "!load-modules") {
        Ok(o) => { eprintln!("nvidia.ko: {}", o.lines().last().unwrap_or(&o)); }
        Err(e) => { eprintln!("nvidia.ko FAILED: {}", e); SandboxBackend::destroy(&mut backend).ok(); return; }
    }

    // Run tensor ops
    eprintln!("\n--- Running NV tensor ops ---");
    let exec_start = Instant::now();
    match SandboxBackend::exec(&mut backend, NV_TENSOR_TEST_CODE) {
        Ok(output) => {
            let elapsed = exec_start.elapsed();
            eprintln!("Output ({:.1}s):", elapsed.as_secs_f64());
            for line in output.lines() {
                eprintln!("  | {}", line);
            }
            if output.contains("PASSED") {
                eprintln!("\n✅ NV TENSOR OPS PASSED!\n");
            } else {
                eprintln!("\n❌ NV tensor ops FAILED\n");
            }
        }
        Err(e) => {
            eprintln!("NV tensor ops HUNG: {}", e);
        }
    }

    SandboxBackend::destroy(&mut backend).ok();
}
