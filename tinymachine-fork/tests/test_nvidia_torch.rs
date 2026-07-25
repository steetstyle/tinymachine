//! Quick test: load nvidia.ko via VFIO + import torch
//! Run: cargo test -p tinyos-fork --test freshboot_e2e test_nvidia_torch_quick -- --include-ignored --nocapture

use std::path::Path;

fn home_dir() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/root"))
}

#[ignore]
#[test]
fn test_nvidia_torch_quick() {
    use tinymachine_api::sandbox::SandboxBackend;
    use tinymachine_fork::fresh_boot::FreshBootBackend;
    use tinymachine_fork::vfio::{detect_gpu_devices, is_bound_to_vfio};

    // ── Prerequisites ──
    let kernel = home_dir().join(".tinyos/templates/kernel/vmlinux-gpu-nvidia");
    let initrd = home_dir().join(".tinyos/templates/python/v1/pytorch/initrd.gz");
    
    if !kernel.exists() {
        eprintln!("SKIP: vmlinux-gpu-nvidia not found");
        return;
    }
    if !initrd.exists() {
        eprintln!("SKIP: pytorch initrd not found at {}", initrd.display());
        return;
    }
    let devices = detect_gpu_devices();
    let has_vfio = devices.iter().any(|d| is_bound_to_vfio(&d.pci_bdf));
    if !has_vfio {
        eprintln!("SKIP: No GPU bound to vfio-pci");
        return;
    }

    tinymachine_fork::register_all_backends();
    let variant = tinymachine_api::variant::Variant::new("python", "pytorch", "gpu-nvidia");
    let mut backend = FreshBootBackend::new();
    
    // ── Boot VM ──
    eprintln!("\n=== Step 1: Boot pytorch VM with VFIO ===");
    SandboxBackend::init(&mut backend, &variant)
        .expect("init() should boot VM with VFIO passthrough");
    
    let vfio_ok = backend.has_vfio();
    eprintln!("VFIO attached: {}", vfio_ok);
    if !vfio_ok {
        eprintln!("FAIL: VFIO not attached");
        return;
    }

    // ── Test 1: Python works ──
    eprintln!("\n=== Step 2: Basic Python exec ===");
    let hello = SandboxBackend::exec(&mut backend, "print('hello from pytorch VM')")
        .expect("exec should work");
    eprintln!("OK: {}", hello.trim());

    // ── Test 2: Load nvidia.ko via !load-modules ──
    eprintln!("\n=== Step 3: Load nvidia.ko ===");
    let mod_result = SandboxBackend::exec(&mut backend, "!load-modules")
        .expect("!load-modules should execute");
    eprintln!("Module load result:\n{}", mod_result);

    // ── Test 3: Check /dev/nvidia* ──
    eprintln!("\n=== Step 4: Check NVIDIA device nodes ===");
    let dev_check = SandboxBackend::exec(&mut backend, r#"
import os, stat
nodes = ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]
for n in nodes:
    exists = os.path.exists(n)
    if exists:
        st = os.stat(n)
        is_chr = stat.S_ISCHR(st.st_mode)
        print(f"{n}: exists={exists} char={is_chr} major={os.major(st.st_rdev)} minor={os.minor(st.st_rdev)}", flush=True)
    else:
        print(f"{n}: NOT FOUND", flush=True)
print("DONE", flush=True)
"#).expect("dev check exec");
    eprintln!("Device check:\n{}", dev_check);
    let has_nvidia0 = dev_check.contains("/dev/nvidia0: exists=True");
    
    // ── Test 4: import torch + check CUDA ──
    eprintln!("\n=== Step 5: import torch ===");
    let torch_test = if has_nvidia0 {
        SandboxBackend::exec(&mut backend, r#"
import sys, os
sys.path.insert(0, '/usr/lib/python3.12/dist-packages')
print("PYVER:", sys.version, flush=True)
try:
    import torch
    print(f"torch: {torch.__version__}", flush=True)
    print(f"CUDA available: {torch.cuda.is_available()}", flush=True)
    if torch.cuda.is_available():
        print(f"CUDA devices: {torch.cuda.device_count()}", flush=True)
        print(f"CUDA device: {torch.cuda.get_device_name(0)}", flush=True)
    # Basic tensor test
    x = torch.tensor([1.0, 2.0, 3.0])
    print(f"CPU tensor: {x}", flush=True)
    if torch.cuda.is_available():
        x_cuda = x.cuda()
        print(f"CUDA tensor: {x_cuda}", flush=True)
    print("TORCH_OK", flush=True)
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"TORCH_ERR: {e}", flush=True)
"#).expect("torch exec")
    } else {
        // No nvidia.ko, test CPU-only torch
        SandboxBackend::exec(&mut backend, r#"
import sys
sys.path.insert(0, '/usr/lib/python3.12/dist-packages')
try:
    import torch
    print(f"torch: {torch.__version__}", flush=True)
    print(f"CUDA available: {torch.cuda.is_available()}", flush=True)
    x = torch.tensor([1.0, 2.0, 3.0])
    print(f"CPU tensor: {x}", flush=True)
    print("TORCH_OK", flush=True)
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"TORCH_ERR: {e}", flush=True)
"#).expect("torch exec")
    };
    eprintln!("Torch test output:\n{}", torch_test);

    // ── Cleanup ──
    SandboxBackend::destroy(&mut backend).ok();
    
    // Summary
    eprintln!("\n=== Summary ===");
    eprintln!("VFIO: {}", vfio_ok);
    eprintln!("nvidia0: {}", has_nvidia0);
    eprintln!("torch: {}", torch_test.contains("TORCH_OK"));
    eprintln!("cuda: {}", torch_test.contains("CUDA available: True"));
}
