//! Build a KVM CoW snapshot for a given variant.
//!
//! Boots Linux with the variant's initrd, runs a warm-up exec, then captures
//! the CPU + memory state into the template registry.
//!
//! Usage:
//!
//!   cargo run --bin build-snapshot -- \
//!     --kernel templates/kernel/vmlinux-base \
//!     --initrd templates/python/v1/tinygrad-cpu/initrd \
//!     --lang python \
//!     --variant tinygrad-cpu \
//!     --profile base
//!
//! Or use defaults (python:minimal):
//!
//!   cargo run --bin build-snapshot

use std::path::PathBuf;
use std::time::Instant;

use tinymachine_fork::boot::{self, BootConfig};
use tinymachine_fork::kvm::Kvm;
use tinymachine_fork::template_registry::TemplateRegistry;
use tinymachine_fork::variant::{Variant, KernelProfile, ResourceLimits, boot_memory_size_bytes};
/// Recursively search upward from CWD for `tinymachine-fork/templates/`
fn find_templates_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors() {
        let candidate = ancestor.join("tinymachine-fork").join("templates");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if ancestor.ends_with("tinymachine-fork") && ancestor.join("templates").is_dir() {
            return Some(ancestor.join("templates"));
        }
    }
    None
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .try_init();

    let templates_root = find_templates_root().expect(
        "Cannot find tinymachine-fork/templates/ directory. \
         Run this from the tinymachine project root or tinymachine-fork/ subdirectory."
    );
    eprintln!("Templates root: {}", templates_root.display());

    // Parse CLI args
    let args: Vec<String> = std::env::args().collect();
    let mut kernel_path: Option<PathBuf> = None;
    let mut initrd_path: Option<PathBuf> = None;
    let mut lang = "python".to_string();
    let mut variant_name = "minimal".to_string();
    let mut profile_name = "base".to_string();
    let mut memory_mb: Option<u64> = None;
    let mut enable_network = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--kernel" | "-k" => { i += 1; kernel_path = Some(PathBuf::from(&args[i])); }
            "--initrd" | "-i" => { i += 1; initrd_path = Some(PathBuf::from(&args[i])); }
            "--lang" | "-l" => { i += 1; lang = args[i].clone(); }
            "--variant" | "-v" => { i += 1; variant_name = args[i].clone(); }
            "--profile" | "-p" => { i += 1; profile_name = args[i].clone(); }
            "--memory-mb" | "-m" => {
                i += 1;
                memory_mb = Some(args[i].parse().expect("--memory-mb requires a number"));
            }
            "--network" => {
                enable_network = true;
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                eprintln!("Usage: build-snapshot --kernel <path> --initrd <path> [--lang python] [--variant minimal] [--profile base] [--memory-mb 512] [--network]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Build kernel paths
    let kernel = kernel_path.unwrap_or_else(|| templates_root.join("kernel").join("vmlinux-base"));
    let initrd = initrd_path.unwrap_or_else(|| {
        templates_root.join(&lang).join("v1").join(&variant_name).join("initrd")
    });

    if !kernel.exists() {
        eprintln!("ERROR: Kernel not found at: {}", kernel.display());
        std::process::exit(1);
    }
    if !initrd.exists() {
        eprintln!("ERROR: Initrd not found at: {}", initrd.display());
        std::process::exit(1);
    }

    let kernel_profile = match profile_name.as_str() {
        "base" => KernelProfile::Base,
        "gpu-vk" => KernelProfile::GpuVk,
        "gpu-vfio" => KernelProfile::GpuVfio,
        "gpu-nvidia" => KernelProfile::GpuNvidia,
        _ => {
            eprintln!("Unknown kernel profile: {profile_name} (use base/gpu-vk/gpu-vfio/gpu-nvidia)");
            std::process::exit(1);
        }
    };

    let tier = if lang == "wasm" {
        tinymachine_api::ExecutionTier::Wasm
    } else {
        tinymachine_api::ExecutionTier::KvmFork
    };

    let variant = Variant {
        lang: lang.clone(),
        name: variant_name.clone(),
        description: format!("{lang}:{variant_name}"),
        tier,
        kernel_profile,
        needs_initrd: true,
        limits: ResourceLimits::default(),
        pool_min: 3,
        pool_max: 10,
        pool_idle_timeout_secs: 60,
        kernel_version: None,
    };

    eprintln!("Kernel:       {}", kernel.display());
    eprintln!("Initrd:       {}", initrd.display());
    eprintln!("Variant:      {}/{} ({:?})", variant.lang, variant.name, variant.kernel_profile);

    // ── Step 1: Open KVM ──────────────────────────────────────────────
    eprint!("Opening KVM... ");
    let kvm = Kvm::new().expect("KVM unavailable");
    eprintln!("OK");

    // ── Step 2: Boot Linux ────────────────────────────────────────────
    eprint!("Booting Linux (kernel + initrd)... ");
    let total_start = Instant::now();

    // Use the centralised memory-size function so this stays in sync
    // with fresh_boot.rs.  Large initrd variants (tinygrad-cpu, numpy)
    // need 512 MB — see variant::boot_memory_size_bytes().
    // Use --memory-mb CLI flag to override.
    let memory_size = match memory_mb {
        Some(mb) => mb * 1024 * 1024,
        None => boot_memory_size_bytes(&variant_name),
    };
    // When --network is enabled, use a cmdline with PCI enabled
    // (no pci=off). Otherwise use the default (which includes pci=off).
    let cmdline = if enable_network {
        Some(format!(
            "console=ttyS0,115200 earlyprintk=serial,0x3f8,115200 \
             acpi=off lpj=10000000 loglevel=4 rodata=off rdinit=/init \
             iomem=relaxed random.trust_cpu=on idle=halt \
             pci=conf1 pcie_port_pm=off \
             ip=10.0.2.2::10.0.2.1:255.255.255.0::eth0:off"
        ))
    } else {
        None
    };

    let config = BootConfig {
        kernel_path: kernel,
        memory_size,
        load_addr: 0,
        initrd_path: Some(initrd),
        pvh_boot: true,
        irqchip: true,
        cmdline,
        reserved_regions: Vec::new(),
        kernel_version: String::new(),
        kernel_hash: String::new(),
        vbios_data: None,
    };

    let mut booted = unsafe {
        boot::boot_linux(&kvm, &config).expect("boot_linux() failed")
    };
    eprintln!("OK ({:.1}s)", total_start.elapsed().as_secs_f64());

    // ── Step 2b. Optional: virtio-net + TAP ──────────────────────────
    // Set up networking before run_until_ready() so the guest kernel
    // discovers the virtio-net PCI device during boot.
    let _tap = if enable_network {
        eprint!("Setting up virtio-net (TAP)... ");
        match tinymachine_fork::net::tap::TapInterface::open("tap-tiny") {
            Ok(tap) => {
                let tap_fd = tap.fd();
                let tap_name = tap.name.clone();
                let _ = std::process::Command::new("ip")
                    .args(["addr", "replace", "10.0.2.1/24", "dev", &tap_name])
                    .output();
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", &tap_name, "up"])
                    .output();
                let mmio_base = tinymachine_fork::arch::layout::VIRTIO_MMIO_ADDR as u32;
                let mut vn = Box::new(tinymachine_fork::net::virtio_net_pci::VirtioNetPci::new(booted.memory_ptr, mmio_base));
                vn.set_tap_fd(tap_fd);
                booted.virtio_net = Some(std::cell::RefCell::new(vn));
                eprintln!("OK (TAP={tap_name})");
                Some(tap)
            }
            Err(e) => {
                eprintln!("WARN (failed: {e})");
                None
            }
        }
    } else {
        None
    };

    // ── Step 3: Wait for init READY ───────────────────────────────────
    eprint!("Waiting for init READY... ");
    let ready_start = Instant::now();
    unsafe {
        booted.run_until_ready().expect("Kernel boot failed (no READY signal)");
    }
    eprintln!("OK ({:.1}s)", ready_start.elapsed().as_secs_f64());

    // ── Step 4: Capture snapshot immediately after boot ───────────────
    // No warm-up exec — the init's `fexecve` encounters an ELF interpreter
    // issue on some initrd builds. The snapshot captured directly from the
    // boot-ready state preserves the init's polling loop, and Python exec
    // works correctly on the first command after fork.
    // The Tier 3 FreshBoot test proves the initrd + kernel combo works.
    eprint!("Capturing snapshot... ");
    let snap_start = Instant::now();
    let snapshot = booted.capture_snapshot().expect("capture_snapshot() failed");
    eprintln!(
        "OK ({:.1}s, memory={} bytes)",
        snap_start.elapsed().as_secs_f64(),
        snapshot.memory.len()
    );

    // ── Step 6: Store via TemplateRegistry ──────────────────────────
    // Using the real templates root (not ~/.tinymachine/templates/)
    // This correctly writes mem + state.json + meta.json + updates registry.json
    eprint!("Storing snapshot via TemplateRegistry... ");
    let store_start = Instant::now();
    let mut registry = TemplateRegistry::open(Some(templates_root))
        .expect("TemplateRegistry::open() failed");
    registry.store_snapshot(&variant, &snapshot)
        .expect("store_snapshot() failed");
    eprintln!("OK ({:.1}s)", store_start.elapsed().as_secs_f64());

    // ── Also store at ~/.tinymachine/templates/ for backward compat ──
    let home_tinymachine = PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
    ).join(".tinymachine").join("templates");
    if home_tinymachine.exists() {
        eprint!("Also storing at {}... ", home_tinymachine.display());
        let mut home_registry = TemplateRegistry::open(Some(home_tinymachine))
            .expect("TemplateRegistry::open(home) failed");
        home_registry.store_snapshot(&variant, &snapshot)
            .expect("store_snapshot(home) failed");
        eprintln!("OK");
    } else {
        eprintln!("{} does not exist — skipping", home_tinymachine.display());
    }

    eprintln!();
    eprintln!("═══════════════════════════════════════════");
    eprintln!("Snapshot built successfully!");
    eprintln!("  Variant:   {}/{}", variant.lang, variant.name);
    eprintln!("  Profile:   {:?}", variant.kernel_profile);
    eprintln!("  Memory:    {} bytes ({:.1} MB)", snapshot.memory.len(), snapshot.memory.len() as f64 / 1_048_576.0);
    eprintln!("  Total:     {:.1}s", total_start.elapsed().as_secs_f64());
    eprintln!("═══════════════════════════════════════════");
}
