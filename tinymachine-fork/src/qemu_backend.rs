//! QEMU-backed VM Sandbox — Tier 3 with SeaBIOS + VBIOS Option ROM.
//!
//! This backend spawns `qemu-system-x86_64` with KVM acceleration, boots
//! a Linux kernel + initrd via QEMU's direct kernel boot (`-kernel`, `-initrd`),
//! and optionally passes through a VFIO GPU device with a VBIOS Option ROM
//! image (via `-device vfio-pci,romfile=...`).
//!
//! QEMU's SeaBIOS runs the VBIOS POST during boot, which initializes GPU
//! power domains (Falcon engines, PLLs, voltage regulators) that direct KVM
//! boot cannot handle. This is required for VFIO GPU variants (tinygrad-nv,
//! pytorch) that need Option ROM initialization for:
//!
//! - **Falcon engine power-on**: VBIOS powers up the Falcon microcontrollers
//!   (GSP, PGRAPH, PCOPY, CE, etc.) and releases them from reset.
//! - **GFW (Graphics Firmware Wrapper) boot**: The VBIOS POST sequence
//!   initializes the GFW FWSEC firmware on the GSP Falcon, enabling nvidia.ko's
//!   RMAPI (NVKIface) path to communicate with the GPU.
//! - **PCI config space**: VBIOS programs the PCI config space with the correct
//!   BAR sizes, expansion ROM base, and other device-specific registers that
//!   direct KVM boot cannot initialize.
//!
//! # Architecture
//!
//! - `init()`: validates paths to kernel, initrd, VBIOS, and the QEMU binary.
//! - `exec()`: spawns QEMU, captures serial output, returns stdout result.
//! - Each `exec()` creates a fresh QEMU process (no state reuse).
//! - `reset()`: no-op (cleanup handled per-exec).
//! - `destroy()`: kills any running QEMU process.
//!
//! # QEMU Configuration (matching run-vm.sh)
//!
//! - **Machine**: `q35,accel=kvm,kernel_irqchip=split` — Q35 chipset for
//!   proper PCIe topology; `kernel_irqchip=split` lets KVM handle VFIO MSI
//!   routing while QEMU handles legacy PIRQ routing.
//! - **CPU**: `host,kvm=on` — Enables all host CPU features including SVM.
//! - **SMP**: `$(nproc)` — All available cores.
//! - **VFIO**: `device vfio-pci,host=...,x-msix-relocation=bar2,romfile=...` —
//!   `x-msix-relocation=bar2` relocates the MSI-X table from BAR0 to BAR2
//!   to avoid conflicts with NVIDIA GPU register space.
//! - **Both GPU functions**: GPU display (`00.0`) + audio (`00.1`) in the
//!   same IOMMU group are both passed through.
//! - **VirtIO**: `virtio-net-pci` for network access via userspace NAT.
//! - **Kernel cmdline**: `pci=noearly acpi_irq_handling=off pcie_port_pm=off
//!   pci=realloc` for proper GPU initialization (see FreshBoot docs).
//!
//! # GFW / GSP / Falcon Initialization Flow
//!
//! 1. QEMU boots → SeaBIOS POST → PCI enumeration
//! 2. SeaBIOS detects the VBIOS Option ROM → runs VBIOS POST
//! 3. VBIOS powers on GPU → starts GSP Falcon → loads GFW FWSEC firmware
//! 4. VBIOS completes → SeaBIOS continues boot → loads Linux kernel
//! 5. Linux boots → init.c runs → loads nvidia.ko kernel module
//! 6. nvidia.ko detects GSP Falcon is already running (from VBIOS)
//! 7. nvidia.ko loads R535 GSP firmware ↔ RMAPI initializes
//! 8. NVIDIA devices /dev/nvidia0, /dev/nvidiactl, /dev/nvidia-uvm appear
//! 9. init.c writes `READY\n` to serial → TinyMachine injects code
//!
//! Without the VBIOS Option ROM, steps 3-4 don't happen, and nvidia.ko's
//! attempt to initialize the GSP Falcon fails or hangs (the "second-boot"
//! hang observed in FreshBootBackend without VBIOS).
//!
//! # Performance
//!
//! SeaBIOS POST adds ~50-100ms to boot time compared to direct KVM boot.
//! Total boot time: ~1.1s (vs ~1.0s for FreshBootBackend).
//! GPU initialization via VBIOS is included in this time.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tinymachine_api::error::{ApiError, Result};
use tinymachine_api::sandbox::SandboxBackend;
use tinymachine_api::variant::Variant;
use tracing::{info, trace, warn};

use crate::arch::paths;

// ─── Configuration ─────────────────────────────────────────────────────

/// Minimum size for a valid VBIOS ROM (512 bytes).
const MIN_VBIOS_SIZE: u64 = 512;
/// Maximum size for a VBIOS ROM (4 MB).
const MAX_VBIOS_SIZE: u64 = 4 * 1024 * 1024;
/// Default QEMU path is set by `crate::arch::paths::QEMU_BINARY`.
/// On x86_64: `/usr/bin/qemu-system-x86_64`.
/// On aarch64: `/usr/bin/qemu-system-aarch64`.
/// Boot timeout (milliseconds) — TCG is extremely slow for 262MB decompressed
/// initrd. Need 5+ minutes for full boot + tinygrad imports.
const BOOT_TIMEOUT_MS: u64 = 600_000;
/// Kernel boot cmdline suffix (tier-agnostic options).
const BASE_CMDLINE: &str =
    "console=ttyS0,115200 earlyprintk=serial,0x3f8,115200 lpj=10000000 \
     loglevel=3 rdinit=/init iomem=relaxed random.trust_cpu=on idle=halt";

// ─── DMA Mask Verification ────────────────────────────────────────────

/// Read the DMA mask bits for a PCI device from sysfs.
///
/// Returns the number of DMA address bits (e.g., 32, 64), or `None` if the
/// device is not found or the sysfs file is unreadable.
///
/// VFIO uses the device's `dma_mask` to determine the valid IOVA range for
/// DMA mappings. If this is 32 (the kernel default set by `pci_alloc_dev()`),
/// VFIO will reject DMA mappings above 4GB with `ENOMEM` (see kernel BZ 217237).
fn read_dma_mask_bits(bdf: &str) -> Option<u32> {
    // Sysfs exposes dma_mask_bits via the PCI device's sysfs entry.
    // The device tree path can be either:
    //   /sys/bus/pci/devices/<bdf>/dma_mask_bits
    // or at the full device path:
    //   /sys/devices/pci0000:00/0000:00:<bus>/0000:<bdf>/dma_mask_bits
    //
    // We try both paths.
    let path1 = Path::new("/sys/bus/pci/devices").join(bdf).join("dma_mask_bits");
    if let Ok(s) = fs::read_to_string(&path1) {
        if let Ok(val) = s.trim().parse::<u32>() {
            return Some(val);
        }
    }
    None
}

/// Path to the compiled `tinymachine_dma_fix.ko` kernel module.
///
/// This module calls `dma_set_mask(64)` on the NVIDIA GPU before vfio-pci
/// binds, fixing the dma_mask_bits=32 kernel bug (BZ 217237) that causes
/// VFIO_MAP_DMA to fail.
///
/// The module is located relative to the project source tree. At runtime,
/// the path can be overridden via the `TINYMACHINE_DMA_FIX_KO` environment variable.
const DEFAULT_DMA_FIX_KO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tools/tinyos-dma-fix/tinymachine_dma_fix.ko"
);

/// Verify the VFIO GPU has dma_mask_bits >= 64.
///
/// If the GPU reports dma_mask_bits=32 (kernel default, no driver has called
/// `dma_set_mask()`), VFIO restricts DMA mappings to 32-bit IOVA space and
/// QEMU's guest RAM mapping above 4GB fails with `VFIO_MAP_DMA: ENOMEM`.
///
/// This function:
/// 1. Reads dma_mask_bits from sysfs for the VFIO-bound GPU
/// 2. If < 64, tries to load the `tinymachine_dma_fix.ko` kernel module
/// 3. Re-checks after loading
/// 4. Returns a clear error with remediation steps if still < 64
///
/// # Arguments
///
/// * `bdf` — PCI BDF of the GPU (e.g., "0000:01:00.0")
///
/// # Errors
///
/// Returns `ApiError` if dma_mask_bits is still < 64 after all remediation
/// attempts, with instructions for the user.
fn ensure_dma_mask_64(bdf: &str) -> Result<()> {
    let current = read_dma_mask_bits(bdf);

    match current {
        Some(64) => {
            info!("QemuBackend: GPU {bdf} dma_mask_bits=64 — KVM VFIO will work");
            return Ok(());
        }
        Some(n) if n >= 48 => {
            info!(
                "QemuBackend: GPU {bdf} dma_mask_bits={n} — this may still work but \
                 64-bit is preferred for VFIO passthrough"
            );
            return Ok(());
        }
        Some(bits) => {
            warn!(
                "QemuBackend: GPU {bdf} dma_mask_bits={bits} — VFIO will reject \
                 DMA mappings above 4GB (kernel BZ 217237). Attempting fix..."
            );
        }
        None => {
            warn!(
                "QemuBackend: cannot read dma_mask_bits for GPU {bdf} from sysfs. \
                 If VFIO_MAP_DMA fails, check that the device is bound to vfio-pci."
            );
            // Don't fail here — the sysfs path might be transient. Proceed
            // and let the QEMU exec() fail naturally with a clear error.
            return Ok(());
        }
    }

    // ── Try to load the DMA fix kernel module ──
    //
    // The tinymachine_dma_fix.ko module calls dma_set_mask(64) on the GPU device.
    // This must happen BEFORE vfio-pci probes the device. If vfio-pci is
    // already bound, we need to rebind after loading.
    let ko_path = std::env::var("TINYMACHINE_DMA_FIX_KO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DMA_FIX_KO));

    if !ko_path.exists() {
        // Construct a helpful error message
        let build_cmd = format!(
            "cd {} && make",
            ko_path.parent().unwrap_or(Path::new("tools/tinyos-dma-fix"))
                .to_string_lossy()
        );
        return Err(ApiError::Config(format!(
            "GPU {bdf} has dma_mask_bits=32, which prevents KVM VFIO passthrough.\n\
             To fix this:\n\
             1. Build the DMA fix kernel module:\n\
                $ {build_cmd}\n\
             2. Load it before using vfio-pci:\n\
                $ sudo insmod {} domain=0 bus=1 slot=0 func=0\n\
             3. Rebind the GPU to vfio-pci:\n\
                $ echo \"{bdf}\" | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind\n\
                $ echo \"{bdf}\" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind\n\
             \n\
             Alternatively, set the TINYMACHINE_DMA_FIX_KO environment variable to the\n\
             path of a pre-built tinymachine_dma_fix.ko.",
            ko_path.to_string_lossy()
        )));
    }

    // Parse the BDF into module parameters
    // Format: "0000:01:00.0" → domain=0 bus=1 slot=0 func=0
    let parts: Vec<&str> = bdf.split(&[':', '.'][..]).collect();
    let (domain, bus, slot, func) = if parts.len() >= 4 {
        (
            parts[0].parse::<i32>().unwrap_or(0),
            parts[1].parse::<i32>().unwrap_or(1),
            parts[2].parse::<i32>().unwrap_or(0),
            parts[3].parse::<i32>().unwrap_or(0),
        )
    } else {
        (0, 1, 0, 0)
    };

    // Load the module with insmod. This requires root (sudo).
    // SAFETY: We spawn a subprocess to run insmod. The string arguments
    // are constructed from validated values.
    info!(
        "QemuBackend: loading {ko} with domain={domain} bus={bus} slot={slot} func={func}",
        ko = ko_path.to_string_lossy()
    );

    let status = Command::new("sudo")
        .arg("insmod")
        .arg(&ko_path)
        .arg(format!("domain={domain}"))
        .arg(format!("bus={bus}"))
        .arg(format!("slot={slot}"))
        .arg(format!("func={func}"))
        .arg("verbose=1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {
            info!("QemuBackend: tinymachine_dma_fix loaded successfully — dma_mask should now be 64");
        }
        Ok(s) => {
            // insmod failed. This can happen if:
            // - sudo requires a password (non-interactive context)
            // - Secure Boot blocks the unsigned (wrong slot) module
            // - Module was built for a different kernel version
            //
            // Don't hard-fail. The pci-hole64=64G workaround keeps all
            // GPU BAR addresses below the 39-bit IOMMU boundary, which
            // avoids VFIO_MAP_DMA errors even with dma_mask_bits=32.
            // The guest nvidia.ko driver will set the proper 64-bit
            // DMA mask during GSP-RM init.
            warn!(
                "QemuBackend: could not load tinymachine_dma_fix for GPU {bdf} \
                 (sudo insmod exited with code {}). Continuing with pci-hole64=64G \
                 workaround. Install the module at boot for optimal performance:\n\
                 $ sudo insmod {} domain={} bus={} slot={} func={}",
                s.code().unwrap_or(-1),
                ko_path.to_string_lossy(), domain, bus, slot, func,
            );
        }
        Err(e) => {
            warn!(
                "QemuBackend: failed to execute sudo insmod for DMA fix: {e}. \
                 Continuing — pci-hole64=64G workaround avoids VFIO_MAP_DMA \
                 errors even without the DMA fix."
            );
        }
    }

    // Re-check dma_mask_bits after loading
    let after = read_dma_mask_bits(bdf);
    match after {
        Some(64) => {
            info!("QemuBackend: DMA fix confirmed — GPU {bdf} now has dma_mask_bits=64");
            Ok(())
        }
        Some(bits) => {
            warn!(
                "QemuBackend: DMA fix loaded but dma_mask_bits is still {} for {bdf} — \
                 the module may have failed. Check dmesg for error messages.",
                bits
            );
            // The module loaded (insmod succeeded) but didn't change the mask.
            // This can happen if vfio-pci is already bound — the module fixed
            // the mask in the kernel, but vfio-pci cached the old mask.
            // Try rebinding the device to vfio-pci.
            info!("QemuBackend: attempting to rebind GPU {bdf} to vfio-pci to pick up new dma_mask...");
            let rebind = || -> std::result::Result<(), std::io::Error> {
                let unbind_path = format!("/sys/bus/pci/drivers/vfio-pci/unbind");
                let bind_path = format!("/sys/bus/pci/drivers/vfio-pci/bind");
                fs::write(&unbind_path, bdf)?;
                fs::write(&bind_path, bdf)?;
                Ok(())
            };
            match rebind() {
                Ok(()) => {
                    // Re-check after rebind
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    match read_dma_mask_bits(bdf) {
                        Some(64) => {
                            info!("QemuBackend: rebind successful — GPU {bdf} now has dma_mask_bits=64");
                            return Ok(());
                        }
                        Some(bits) => {
                            warn!(
                                "QemuBackend: rebind did not change dma_mask_bits (still {bits}). \
                                 Continuing anyway — TCG fallback will be used if KVM fails."
                            );
                            // Let it proceed; the DMA mapping MIGHT still work
                            // if the IOMMU aperture is small enough.
                            return Ok(());
                        }
                        None => {
                            warn!("QemuBackend: GPU {bdf} lost after rebind — device may be in bad state");
                            return Err(ApiError::Config(format!(
                                "GPU {bdf} disappeared after vfio-pci rebind. \
                                 Check that the device is still present: lspci -s {bdf}"
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "QemuBackend: could not rebind GPU {bdf} to vfio-pci: {e}. \
                         Continuing — VFIO_MAP_DMA may fail at runtime."
                    );
                    // Proceed anyway; the error will surface clearly in QEMU's output.
                    Ok(())
                }
            }
        }
        None => {
            warn!(
                "QemuBackend: cannot read dma_mask_bits for GPU {bdf} after DMA fix — \
                 device may have been unbound."
            );
            Ok(())
        }
    }
}

/// Ensure sufficient RLIMIT_MEMLOCK for VFIO DMA pinning.
///
/// VFIO needs to pin guest memory pages for DMA. The kernel enforces
/// `RLIMIT_MEMLOCK` (locked memory limit). If this is too low, VFIO_MAP_DMA
/// returns ENOMEM even if dma_mask is correct.
///
/// We try to raise the limit to unlimited. This requires `CAP_SYS_RESOURCE`
/// (typically root). If we can't raise it, we warn but continue — the user
/// can set it manually or use sudo.
fn ensure_memlock_unlimited(memory_mb: u32) {
    // SAFETY: getrlimit/setrlimit are async-signal-safe and always
    // succeed at reading the current limits, even if the process is
    // not privileged. Writing may fail with EPERM if not privileged.
    unsafe {
        let mut rlim = std::mem::zeroed::<libc::rlimit>();
        let ret = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim);
        if ret != 0 {
            warn!("QemuBackend: getrlimit(RLIMIT_MEMLOCK) failed: {}", std::io::Error::last_os_error());
            return;
        }

        let needed = (memory_mb as u64) * 1024 * 1024;  // VM memory in bytes
        let soft_kb = rlim.rlim_cur / 1024;
        let hard_kb = rlim.rlim_max / 1024;

        if rlim.rlim_cur != libc::RLIM_INFINITY && rlim.rlim_cur < needed {
            info!(
                "QemuBackend: RLIMIT_MEMLOCK soft={soft_kb}KB, needed at least {}KB for {memory_mb}MB VM. \
                 Attempting raise...",
                needed / 1024
            );
            rlim.rlim_cur = needed.max(rlim.rlim_cur);
            let ret = libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
            if ret != 0 {
                warn!(
                    "QemuBackend: setrlimit(RLIMIT_MEMLOCK, {}KB) failed: {}. \
                     VFIO DMA may fail without root. \
                     Fix: run as root, or set 'ulimit -l unlimited'.",
                    needed / 1024,
                    std::io::Error::last_os_error()
                );
            }
        } else if rlim.rlim_cur == libc::RLIM_INFINITY || rlim.rlim_cur >= needed {
            trace!(
                "QemuBackend: RLIMIT_MEMLOCK soft={soft_kb}KB hard={hard_kb}KB — sufficient \
                 (needed at least {}KB)",
                needed / 1024
            );
        }
    }
}

// ─── Backend ───────────────────────────────────────────────────────────

/// A QEMU-backed sandbox that boots a full VM with SeaBIOS + VBIOS Option ROM.
///
/// Each call to `exec()` spawns a fresh QEMU process. This is intentional:
/// it guarantees clean GPU state (FLR on QEMU exit) and avoids complex
/// snapshot management.
pub struct QemuBackend {
    /// Path to the QEMU binary.
    qemu_bin: PathBuf,
    /// Path to the kernel vmlinuz.
    kernel: PathBuf,
    /// Path to the initrd (compressed initramfs).
    initrd: PathBuf,
    /// Optional VBIOS ROM file for GPU Option ROM injection.
    vbios: Option<PathBuf>,
    /// Kernel command-line arguments.
    cmdline: String,
    /// Guest memory size in MB.
    memory_mb: u32,
    /// Whether the backend has been initialized.
    initialized: bool,
    /// Handle to a running QEMU process (set during exec).
    child: Option<Child>,
    /// The variant name (for logging).
    variant_name: String,
}

impl Default for QemuBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl QemuBackend {
    /// Create a new QemuBackend (uninitialized).
    pub fn new() -> Self {
        Self {
            qemu_bin: PathBuf::from(paths::QEMU_BINARY),
            kernel: PathBuf::new(),
            initrd: PathBuf::new(),
            vbios: None,
            cmdline: BASE_CMDLINE.to_string(),
            memory_mb: 4096,
            variant_name: String::new(),
            initialized: false,
            child: None,
        }
    }

    /// Internal exec with specified acceleration (true=KVM, false=TCG).
    fn try_exec(&mut self, code: &str, use_kvm: bool) -> Result<String> {
        let variant_name = &self.variant_name;

        // ── Build QEMU command ──────────────────────────────────────
        let mut cmd = Command::new(&self.qemu_bin);

        // ── Machine: Q35 + kernel_irqchip=split for proper MSI routing ──
        //
        // Q35 chipset: proper PCIe root complex (not PIIX3 legacy).
        // NVIDIA GPUs expect PCIe config space; Q35 provides it.
        //
        // kernel_irqchip=split: KVM handles VFIO MSI/MSI-X routing,
        // QEMU handles legacy PIRQ routing. Without this, VFIO interrupts
        // never reach the guest (see bug #2 in GPU compute saga).
        //
        // x-no-mmap=on: Skip VFIO BAR mmap. Necessary because kernel 6.17
        // VFIO refuses to create IOMMU mappings for 64-bit BARs when the GPU
        // reports dma_mask_bits=32 (pre-VBIOS state). iommufd also hits this
        // limitation. x-no-mmap avoids the issue entirely by never attempting
        // VFIO DMA mappings — guest register access traps through QEMU.
        //
        // Trade-off: trapped MMIO (~10μs/access) is 1000× slower than native
        // EPT (~10ns). This affects GPU init/~500ms and RMAPI ioctl loops
        // during kernel dispatch. GPU DMA (guest RAM <-> VRAM via PCIe) is
        // NOT affected — QEMU sets up the IOMMU translation for the guest
        // RAM region below 4GB, which doesn't trigger dma_mask_bits=32.
        if use_kvm {
            cmd.arg("-machine").arg("q35,accel=kvm,kernel_irqchip=split");
            cmd.arg("-cpu").arg("host,kvm=on");
            // ── 39-bit IOMMU workaround ──
            //
            // Intel VT-d on some mobile platforms (e.g., i9-13980HX) reports
            // DMAR Host Address Width = 39 bits (512 GB). QEMU's default
            // 64-bit PCI MMIO window extends to ~512 GB, causing GPU BAR
            // addresses to land at or above the 39-bit boundary. When VFIO
            // tries to create an IOMMU mapping for these BARs, the IOMMU
            // rejects the address with EINVAL (VFIO_MAP_DMA: Invalid argument).
            //
            // Capping the PCI hole64 window to 64 GB keeps all GPU BARs
            // (BAR1=16GB, BAR3=32MB for RTX 4080 Mobile) well below 512 GB.
            //
            // Verified fix: QEMU test with RTX 4080 Mobile on i9-13980HX
            // (see tools/vfio-gpu.sh). Without this global, VFIO_MAP_DMA
            // fails with -22 (EINVAL). With it, GPU BARs sit at ~16 GB and
            // pass through cleanly. See PLAN.md §6 for details.
            cmd.arg("-global").arg("q35-pcihost.pci-hole64-size=64G");
        } else {
            cmd.arg("-machine").arg("q35,accel=tcg");
            cmd.arg("-cpu").arg("max");
        }

        // ── SMP: all available cores ──
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        cmd.arg("-smp").arg(num_cpus.to_string());

        // ── Memory ──
        cmd.arg("-m").arg(format!("{}M", self.memory_mb));

        // ── Basic VM config ──
        cmd.arg("-no-reboot");
        cmd.arg("-nographic");
        cmd.arg("-nodefaults");
        cmd.arg("-serial").arg("stdio");
        cmd.arg("-display").arg("none");

        // ── Kernel boot ──
        cmd.arg("-kernel").arg(&self.kernel);
        cmd.arg("-initrd").arg(&self.initrd);
        cmd.arg("-append").arg(&self.cmdline);

        // ── VFIO GPU passthrough with VBIOS + MSI-X relocation ──
        if let Some(vbios_path) = &self.vbios {
            let vfio_args = Self::build_vfio_arg(vbios_path)
                .map_err(|e| ApiError::sandbox(format!("VFIO setup failed: {e}")))?;
            cmd.args(&vfio_args);

            // Disable default VGA to avoid device conflict
            cmd.arg("-vga").arg("none");
        }

        // ── VirtIO devices ──
        // Network: user-mode NAT (no host config needed)
        cmd.arg("-netdev").arg("user,id=net0");
        cmd.arg("-device").arg("virtio-net-pci,netdev=net0");

        // Storage: optional disk image at ~/.tinymachine/templates/disk.img
        let disk_img = Self::disk_image_path();
        if disk_img.exists() {
            cmd.arg("-drive")
                .arg(format!("file={},if=virtio,format=raw", disk_img.display()));
        }

        info!("QemuBackend: spawning {}", if use_kvm { "KVM" } else { "TCG" });
        trace!("QemuBackend: command: {:?}", cmd);

        // ── Security: clear host environment ─────────────────────────
        // Prevent host secrets (API keys, AWS credentials, DB URLs) from
        // leaking to the QEMU subprocess and potentially the guest kernel.
        // QEMU runs with full host network access and is a large attack
        // surface (~1M LOC). Environment isolation is minimal defense.
        cmd.env_clear();

        // ── Install seccomp filter in QEMU subprocess ───────────────
        // This runs after fork() but before exec() in the QEMU child.
        // We install a seccomp-BPF filter that allows the minimum set
        // of syscalls QEMU needs (KVM ioctl, mmap, eventfd, etc.)
        // and blocks dangerous ones (open, socket, connect, etc.).
        //
        // SAFETY: pre_exec runs in the child process after fork, before
        // exec. Only async-signal-safe functions may be called.
        // prctl() and seccomp() syscalls are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                // ── Set NO_NEW_PRIVS (required before seccomp) ──────
                let r = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if r != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // ── Build and install seccomp BPF filter ────────────
                // Allowlist for QEMU subprocess — derived from strace of
                // QEMU 8.2.2 booting a Linux guest with KVM acceleration.
                // Verified with: strace -c -o /tmp/qemu_syscall_summary.txt
                //
                // CRITICAL: ppoll(271) is QEMU's event loop — without it
                // QEMU immediately exits (no serial output produced).
                let allowlist: &[i64] = &[
                    // ── Core I/O & memory ──
                    0,    // read
                    1,    // write
                    3,    // close
                    5,    // fstat — file info (62 calls)
                    8,    // lseek
                    9,    // mmap
                    10,   // mprotect
                    11,   // munmap
                    12,   // brk
                    17,   // pread64
                    18,   // pwrite64
                    19,   // readv — scatter-gather I/O
                    20,   // writev
                    21,   // access — file existence check (13 calls, may fail)
                    25,   // mremap
                    28,   // madvise
                    32,   // dup
                    33,   // dup2
                    59,   // execve — needed to launch QEMU after pre_exec
                    63,   // uname — system info
                    72,   // fcntl
                    89,   // readlink — /proc/self/exe resolution
                    133,  // fchdir — directory operations
                    157,  // prctl — process control
                    158,  // arch_prctl — TLS, CPU features
                    217,  // getdents64 — directory listing
                    257,  // openat
                    262,  // newfstatat
                    267,  // readlinkat — modern path resolution
                    302,  // prlimit64 — resource limits (RLIMIT_STACK, NOFILE)
                    319,  // memfd_create — memory-backed fd
                    // ── Process/thread management ──
                    39,   // getpid (26 calls)
                    186,  // gettid (4 calls)
                    204,  // sched_getaffinity — CPU topology
                    218,  // set_tid_address — thread setup
                    234,  // tgkill — thread signaling (26 calls)
                    273,  // set_robust_list — robust futex
                    435,  // clone3 — thread creation (3 calls)
                    // ── Signals ──
                    13,   // rt_sigaction
                    14,   // rt_sigprocmask
                    131,  // sigaltstack
                    289,  // signalfd4 — signal fd
                    15,   // rt_sigreturn — signal handler return
                    // ── Timing ──
                    35,   // nanosleep (fallback)
                    38,   // setitimer
                    228,  // clock_gettime
                    230,  // clock_nanosleep (16 calls, QEMU uses this)
                    283,  // timerfd_create
                    // ── Synchronization ──
                    202,  // futex
                    24,   // sched_yield
                    334,  // rseq — restartable sequences
                    // ── Event loop (CRITICAL) ──
                    271,  // ppoll — QEMU main event loop (19 calls)
                    290,  // eventfd2
                    // ── Random numbers ──
                    318,  // getrandom (2 calls)
                    // ── Async I/O ──
                    425,  // io_uring_setup — QEMU uses io_uring for event loop
                    // ── KVM ──
                    16,   // ioctl — KVM, VFIO, device control
                    // ── Network ──
                    41,   // socket
                    42,   // connect
                    43,   // accept — incoming connections
                    44,   // sendto
                    45,   // recvfrom
                    46,   // sendmsg
                    47,   // recvmsg
                    49,   // bind
                    50,   // listen
                    54,   // setsockopt
                    55,   // getsockopt
                    288,  // accept4 — modern accept
                    // ── Filesystem ──
                    137,  // statfs — filesystem info
                    // ── Security (QEMU's own sandbox) ──
                    317,  // seccomp — QEMU may install its own filter
                    // ── Termination ──
                    231,  // exit_group
                ];

                const SECCOMP_DATA_NR_OFFSET: u32 = 0;
                const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

                #[repr(C)]
                struct BpfInsn { code: u16, jt: u8, jf: u8, k: u32 }
                #[repr(C)]
                struct BpfProg { len: u16, filter: *const BpfInsn }

                fn bpf_ld_abs(offset: u32) -> BpfInsn {
                    BpfInsn { code: 0x0020, jt: 0, jf: 0, k: offset }
                }
                fn bpf_jeq(k: u32, jt: u8, jf: u8) -> BpfInsn {
                    BpfInsn { code: 0x0015, jt, jf, k }
                }
                fn bpf_ret(k: u32) -> BpfInsn {
                    BpfInsn { code: 0x0006, jt: 0, jf: 0, k }
                }

                let num = allowlist.len();
                let total = 3 + 1 + num + 2; // 6 + num
                let allow_pos: u16 = (total - 1) as u16; // 0-indexed position of ALLOW (after DENY)

                let mut insns: Vec<BpfInsn> = Vec::with_capacity(total);

                // Load architecture
                insns.push(bpf_ld_abs(SECCOMP_DATA_ARCH_OFFSET));
                // Check arch == x86_64, else kill
                insns.push(bpf_jeq(crate::arch::paths::AUDIT_ARCH, 1, 0));
                insns.push(bpf_ret(0x80000000)); // SECCOMP_RET_KILL_PROCESS

                // Load syscall number
                insns.push(bpf_ld_abs(SECCOMP_DATA_NR_OFFSET));

                // Allowlist checks
                for (i, &sysno) in allowlist.iter().enumerate() {
                    let cur: u16 = 4 + i as u16;
                    let jt = (allow_pos - cur - 1) as u8;
                    insns.push(bpf_jeq(sysno as u32, jt, 1));
                }

                // DENY: return EACCES
                let errno_eacces = 13u32; // EACCES
                insns.push(bpf_ret(0x00050000 | errno_eacces));
                // ALLOW
                insns.push(bpf_ret(0x7fff0000));

                let prog = BpfProg { len: insns.len() as u16, filter: insns.as_ptr() };

                let ret = libc::syscall(
                    317i64, // SYS_seccomp
                    1i64,   // SECCOMP_SET_MODE_FILTER
                    0i64,   // flags
                    &prog as *const BpfProg,
                );
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        // ── Spawn QEMU ──────────────────────────────────────────────
        let child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ApiError::sandbox(format!("Failed to spawn QEMU: {e}"))
            })?;

        // Store in self for cleanup via reset()/Drop()
        // We store early so Drop/reset can clean up if we error later.
        self.child = Some(child);
        // ── Note: stderr kept on child for post-mortem diagnostics ──
        // We don't take stderr here — if the process dies early we'll
        // read it at the end. stdout is taken below for the serial reader.
        let child = self.child.as_mut().unwrap();

        let stdout = child.stdout.take()
            .ok_or_else(|| ApiError::sandbox("Failed to capture QEMU stdout"))?;

        let reader = BufReader::new(stdout);

        // ── Wait for boot + output ──────────────────────────────────
        let deadline = Instant::now() + Duration::from_millis(BOOT_TIMEOUT_MS);
        let mut output_lines: Vec<String> = Vec::new();

        // The initramfs init script polls for commands on ttyS0.
        // When it sees READY, we inject the code, then wait for output.

        let mut found_ready = false;

        for line_result in reader.lines() {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ApiError::ResourceLimit(format!(
                    "QEMU boot timed out after {}ms for variant {variant_name}",
                    BOOT_TIMEOUT_MS
                )));
            }

            match line_result {
                Ok(line) => {
                    trace!("QemuBackend: [{}] {}", variant_name, line);

                    output_lines.push(line.clone());

                    // Check for READY signal from init (boot complete)
                    if !found_ready && line.contains("READY") {
                        found_ready = true;
                        info!("QemuBackend: guest READY, injecting code");

                        if let Some(stdin) = child.stdin.as_mut() {
                            // Build the full Python code:
                            //   1. Module loading preamble (GPU variants only)
                            //   2. User's code
                            //
                            // The init.c's qemu_serial_loop reads a SINGLE LINE from
                            // the serial port. So we wrap the entire multi-line code
                            // in exec(__import__("base64").b64decode(...).decode())
                            // which is a single line and immune to quoting issues.
                            let preamble = if self.vbios.is_some() {
                                // TEMP: preamble disabled for debug. Module loading
                                // is tested from user code directly.
                                String::new()
                            } else {
                                String::new()
                            };
                            let full_code = format!("{}{}", preamble, code);
                            // Base64-encode to make it a single safe line
                            use base64::Engine as _;
                            let b64 = base64::engine::general_purpose::STANDARD
                                .encode(full_code.as_bytes());
                            let one_liner = format!(
                                "exec(__import__('base64').b64decode('{}').decode())",
                                b64
                            );
                            writeln!(stdin, "{}", one_liner)
                                .map_err(|e| ApiError::sandbox(
                                    format!("Failed to write code to QEMU serial: {e}")
                                ))?;
                            stdin.flush().ok();
                        } else {
                            warn!("QemuBackend: no stdin pipe to QEMU");
                        }
                    }

                    // Check for DONE marker — the init protocol outputs the
                    // Python result followed by "\nDONE\n".
                    if line.trim() == "DONE" {
                        // Single-line protocol:
                        //   READY\n
                        //   [code echo (1 line from serial line discipline)]\n
                        //   [python output]\n
                        //   DONE\n
                        // Extract output between the code echo and DONE.
                        //
                        // With base64 one-liner, the echoed line is very long
                        // (the base64 string). Some serial line disciplines may
                        // not echo it. So we use a heuristic: skip READY and 1
                        // echo line, then collect everything until DONE.
                        let result_text: Vec<String> = output_lines
                            .iter()
                            .skip_while(|l| !l.trim().starts_with("READY"))
                            .skip(2) // skip READY line and code echo line
                            .take_while(|l| l.trim() != "DONE")
                            .filter(|l| !l.trim().is_empty())
                            .cloned()
                            .collect();
                        let result = result_text.join("\n");
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(result);
                    }

                    if line.contains("shutdown") || line.contains("Power down") {
                        break;
                    }
                }
                Err(e) => {
                    warn!("QemuBackend: error reading QEMU output: {e}");
                    break;
                }
            }
        }

        let _ = child.kill();
        let _ = child.wait();

        if output_lines.is_empty() {
            // QEMU produced no serial output. Check if the process exited
            // with an error (e.g. VFIO_MAP_DMA on kernel 6.17). Read stderr.
            let mut stderr_buf = Vec::new();
            if let Some(stderr) = self.child.as_mut().and_then(|c| c.stderr.as_mut()) {
                let _ = stderr.read_to_end(&mut stderr_buf);
            }
            let stderr_str = String::from_utf8_lossy(&stderr_buf);
            if !stderr_str.is_empty() {
                if stderr_str.contains("VFIO_MAP_DMA") {
                    return Err(ApiError::sandbox(format!(
                        "KVM VFIO DMA mapping failed: x-no-mmap=on should prevent this. \
                         Stderr: {}",
                        stderr_str.lines().next().unwrap_or("(empty)")
                    )));
                }
                return Err(ApiError::sandbox(format!(
                    "QEMU exited early: {stderr_str}"
                )));
            }
            Err(ApiError::sandbox(format!(
                "QEMU produced no output for variant {variant_name}"
            )))
        } else {
            Ok(output_lines.join("\n"))
        }
    }

    /// Find the QEMU binary. Checks PATH and common install locations.
    fn find_qemu() -> Result<PathBuf> {
        let candidates = [
            paths::QEMU_BINARY,
            paths::QEMU_ALT_BINARIES[0],
            paths::QEMU_ALT_BINARIES[1],
            "/usr/libexec/qemu-kvm",
        ];
        for candidate in &candidates {
            let p = Path::new(candidate);
            // Try running --version to verify it's a working QEMU
            if p.exists() || !p.is_absolute() {
                if let Ok(output) = Command::new(candidate)
                    .arg("--version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .and_then(|mut c| c.wait())
                {
                    if output.success() {
                        return Ok(PathBuf::from(candidate));
                    }
                }
            }
            if p.is_absolute() && p.exists() {
                return Ok(p.to_path_buf());
            }
        }
        Err(ApiError::Config(format!(
            "QEMU binary not found. Install {} (Debian/Ubuntu: apt install {})",
            paths::QEMU_BINARY,
            paths::QEMU_PACKAGE_NAME,
        )))
    }

    /// Find the VBIOS ROM file. Searches:
    /// 1. `tools/vbios/` relative to the current directory
    /// 2. `~/.tinymachine/vbios/`
    fn find_vbios(name: &str) -> Option<PathBuf> {
        let candidates = {
            let mut v: Vec<PathBuf> = Vec::new();
            // tools/vbios/ relative to current dir
            v.push(PathBuf::from("tools").join("vbios").join(name));
            // ~/.tinymachine/vbios/
            if let Ok(home) = std::env::var("HOME") {
                v.push(PathBuf::from(home).join(".tinymachine").join("vbios").join(name));
            }
            v
        };

        for p in &candidates {
            if p.exists() {
                if let Ok(meta) = p.metadata() {
                    let len = meta.len();
                    if (MIN_VBIOS_SIZE..=MAX_VBIOS_SIZE).contains(&len) {
                        return Some(p.clone());
                    }
                    warn!(
                        "QemuBackend: VBIOS at {:?} has unexpected size {} (expected {}-{})",
                        p, len, MIN_VBIOS_SIZE, MAX_VBIOS_SIZE
                    );
                }
            }
        }
        None
    }

    /// Build the VFIO device argument (-device vfio-pci,...).
    ///
    /// Detects the VFIO GPU by scanning IOMMU groups. Adds `x-msix-relocation=bar2`
    /// to relocate the MSI-X table from BAR0 (where NVIDIA GPUs place it) to BAR2,
    /// avoiding conflicts with GPU register access.
    ///
    /// Also detects the GPU's audio function (same device, function .1) which
    /// shares the same IOMMU group — both must be passed through together.
    fn build_vfio_arg(vbios_path: &Path) -> Result<Vec<String>> {
        // Detect GPU bound to vfio-pci
        let devices = crate::vfio::detect_gpu_devices();
        let gpu = devices
            .iter()
            .find(|d| crate::vfio::is_bound_to_vfio(&d.pci_bdf))
            .ok_or_else(|| {
                ApiError::Config(
                    "No VFIO-bound GPU found. Ensure the GPU is bound to vfio-pci \
                     and the IOMMU is enabled (iommu=pt intel_iommu=on \
                     or amd_iommu=on on kernel cmdline).".into()
                )
            })?;

        let dev_id = &gpu.pci_bdf; // e.g. "0000:01:00.0"
        let romfile = vbios_path.to_string_lossy();
        let mut args: Vec<String> = Vec::new();

        // ── Primary GPU device ──
        //
        // Strategy: KVM + native VFIO BAR mmap (no x-no-mmap=on).
        // x-no-mmap=on is INTENTIONALLY OMITTED — GPU variants use the
        // FreshBootBackend (direct KVM, no QEMU) which pre-assigns BAR
        // addresses via KVM EPT and avoids VFIO_MAP_DMA entirely.
        // QemuBackend is only used when FreshBootBackend is unavailable.
        // x-msix-relocation=bar2: Relocate the MSI-X table to BAR2.
        // NVIDIA Ada/Ampere GPUs embed MSI-X table in BAR0 at offset 0x1800.
        // This conflicts with the GPU's register space — the Linux VFIO
        // driver can't map BAR0 as a single mmap region. Relocating to BAR2
        // (which is usually unused or small) resolves the conflict.
        //
        // romfile=...: VBIOS Option ROM image. SeaBIOS runs this during
        // POST to initialize GPU power domains (Falcon engines, GSP, PLLs).
        // Without this, nvidia.ko's GFW/GSP init hangs on Ampere/Ada GPUs.
        let gpu_arg = format!(
            "vfio-pci,host={},x-msix-relocation=bar2,romfile={}",
            dev_id, romfile
        );
        args.push("-device".into());
        args.push(gpu_arg);

        // ── GPU audio function (same device, function .1) ──
        //
        // NVIDIA GPUs have an HD Audio controller at function 1 (e.g.,
        // 0000:01:00.1). This shares the IOMMU group with the display
        // function — if it's bound to a different driver (snd_hda_intel),
        // VFIO group attach fails with EBUSY.
        //
        // We check if the audio function exists and is bound to vfio-pci.
        let audio_bdf = Self::audio_bdf(dev_id);
        if let Some(ref audio) = audio_bdf {
            if crate::vfio::is_bound_to_vfio(audio) {
                info!("QemuBackend: passing through audio function at {}", audio);
                let audio_arg = format!("vfio-pci,host={}", audio);
                args.push("-device".into());
                args.push(audio_arg);
            } else {
                warn!(
                    "QemuBackend: audio function {} exists but is NOT bound to vfio-pci. \
                     VFIO group may be incomplete. \
                     Run: sudo sh -c 'echo {} > /sys/bus/pci/drivers/snd_hda_intel/unbind' \
                     then bind to vfio-pci.",
                    audio, audio
                );
            }
        }

        Ok(args)
    }

    /// Derive the audio function BDF from the GPU's primary BDF.
    ///
    /// GPU primary functions are at `domain:bus:device.0` (e.g., 0000:01:00.0).
    /// The audio function is at `domain:bus:device.1` (e.g., 0000:01:00.1).
    fn audio_bdf(gpu_bdf: &str) -> Option<String> {
        // Parse "0000:01:00.0" → domain="0000", bus="01", dev="00", func="0"
        let parts: Vec<&str> = gpu_bdf.split(&[':', '.'][..]).collect();
        if parts.len() >= 4 {
            let domain = parts[0];
            let bus = parts[1];
            let device = parts[2];
            // Function 1 (audio)
            Some(format!("{}:{}:{}.1", domain, bus, device))
        } else {
            None
        }
    }

    /// Path to the optional QEMU disk image.
    fn disk_image_path() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".tinymachine").join("templates").join("disk.img")
        } else {
            PathBuf::from("/tmp/tinymachine-disk.img")
        }
    }
}

// ─── SandboxBackend trait implementation ────────────────────────────

impl SandboxBackend for QemuBackend {
    fn init(&mut self, api_variant: &Variant) -> Result<()> {
        let variant_name = format!("{}/{}", api_variant.lang, api_variant.variant);
        self.variant_name = variant_name.clone();

        info!("QemuBackend: initializing for variant {variant_name}");

        // 1. Find QEMU binary
        self.qemu_bin = Self::find_qemu()?;
        info!("QemuBackend: using QEMU at {:?}", self.qemu_bin);

        // 2. Convert API variant to fork variant for path resolution
        let fork_variant = crate::variant::Variant::from_api(api_variant)
            .ok_or_else(|| ApiError::Unsupported(format!(
                "Unsupported variant: {variant_name}"
            )))?;

        // 3. Find kernel and initrd
        //
        // QEMU needs a bzImage (bootable kernel with standard boot header),
        // not a raw vmlinux ELF. The build-kernel.sh produces vmlinux-<profile>
        // at ~/.tinymachine/templates/kernel/. We look for bzImage-<profile> first,
        // then fall back to vmlinux-<profile>.
        let kernel_vmlinux = crate::fresh_boot::FreshBootBackend::find_kernel_path(&fork_variant)
            .map_err(|e| ApiError::Config(format!("Kernel not found: {e}")))?;
        // Determine profile name from vmlinux path: "vmlinux-{profile}" → "bzImage-{profile}"
        let kernel_path = Path::new(&kernel_vmlinux);
        if let Some(filename) = kernel_path.file_name().and_then(|f| f.to_str()) {
            if let Some(profile) = filename.strip_prefix("vmlinux-") {
                let bzimage_name = format!("bzImage-{profile}");
                let bzimage_path = kernel_path.with_file_name(&bzimage_name);
                if bzimage_path.exists() {
                    self.kernel = bzimage_path.to_string_lossy().to_string().into();
                    info!("QemuBackend: using bzImage at {:?}", self.kernel);
                } else {
                    // Fall back to vmlinux (direct KVM boot protocol)
                    self.kernel = kernel_vmlinux.into();
                    warn!("QemuBackend: no bzImage found, falling back to vmlinux (may not work with QEMU -kernel)");
                }
            } else {
                self.kernel = kernel_vmlinux.into();
            }
        } else {
            self.kernel = kernel_vmlinux.into();
        }
        let initrd_path_str = crate::fresh_boot::FreshBootBackend::find_initrd_path(&fork_variant)
            .map_err(|e| ApiError::Config(format!("Initrd lookup failed: {e}")))?;
        self.initrd = initrd_path_str
            .ok_or_else(|| ApiError::Config("Initrd not found for variant".into()))?
            .into();

        info!(
            "QemuBackend: kernel={:?} initrd={:?}",
            self.kernel, self.initrd
        );

        // 4. Find VBIOS for GPU variants
        if api_variant.requires_gpu() {
            // Build expected VBIOS filename from variant
            let vbios_name = "Asus.RTX4080Mobile.12288.221219.rom";
            self.vbios = Self::find_vbios(vbios_name);
            match &self.vbios {
                Some(path) => {
                    let size = std::fs::metadata(path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    info!("QemuBackend: VBIOS found at {:?} ({} bytes)", path, size);
                    if !(MIN_VBIOS_SIZE..=MAX_VBIOS_SIZE).contains(&size) {
                        warn!(
                            "QemuBackend: VBIOS size {} looks suspicious (expected {}..{})",
                            size, MIN_VBIOS_SIZE, MAX_VBIOS_SIZE
                        );
                    }
                }
                None => {
                    warn!(
                        "QemuBackend: no VBIOS found for {variant_name}. \
                         GPU Option ROM will not be injected. "
                    );
                }
            }
        }

        // 5. Configure memory for the variant
        self.memory_mb = match api_variant.variant.as_str() {
            "pytorch" => 4096,
            "tinygrad-nv" => 768,
            _ => 512,
        };

        // 6. Build kernel cmdline
        if api_variant.requires_gpu() {
            // GPU variants: enable PCI (no pci=off).
            // pci=noearly: skip early PCI probe (prevents SMI hang on
            //   some laptops with VFIO passthrough).
            // acpi_irq_handling=off: prevent ACPI from touching GPU IRQs.
            // pci=realloc: force reallocation of 64-bit prefetchable BARs
            //   (BAR1=16GB VRAM) into the 64-bit MMIO window.
            // pcie_port_pm=off: prevent GPU D3cold (PCIe port power mgmt).
            // tinyos.qemu=1: init.c uses QEMU serial protocol (FreshBoot
            //   uses shared-memory protocol, so no tinyos.qemu there).
            // NO pci=nomsi: MSI is required for virtio and GPU MSI routing.
            self.cmdline = format!(
                "{base} pci=noearly acpi_irq_handling=off pcie_port_pm=off tinyos.qemu=1",
                base = BASE_CMDLINE
            );
        } else {
            // CPU-only: pci=off for faster boot
            self.cmdline = format!("{base} tinyos.qemu=1", base = BASE_CMDLINE);
        }

        // 7. Verify VFIO DMA prerequisites (GPU variants only)
        //
        // KVM VFIO passthrough requires:
        //   a) dma_mask_bits >= 64 on the GPU device (kernel BZ 217237 fix)
        //   b) Sufficient RLIMIT_MEMLOCK for VFIO DMA pinning
        //
        // We check both here and attempt automatic remediation before QEMU
        // is launched. This avoids the need for a slow TCG fallback.
        if api_variant.requires_gpu() && self.vbios.is_some() {
            // Find the GPU's BDF from vfio-pci binding
            let devices = crate::vfio::detect_gpu_devices();
            if let Some(gpu) = devices.iter().find(|d| crate::vfio::is_bound_to_vfio(&d.pci_bdf)) {
                let bdf = &gpu.pci_bdf;

                // (a) Fix dma_mask_bits if needed
                if let Err(e) = ensure_dma_mask_64(bdf) {
                    warn!(
                        "QemuBackend: DMA mask check failed for {bdf} — KVM VFIO may fail: {e}"
                    );
                    // Don't hard-fail here; the user may have already addressed
                    // the issue through other means (e.g., kernel boot parameter).
                    // The error will manifest as VFIO_MAP_DMA in QEMU.
                }

                // (b) Ensure RLIMIT_MEMLOCK is sufficient
                ensure_memlock_unlimited(self.memory_mb);
            } else {
                warn!(
                    "QemuBackend: no GPU bound to vfio-pci found for GPU variant {variant_name}. \
                     VFIO passthrough will not work. \
                     Bind the GPU to vfio-pci first."
                );
            }
        }

        self.initialized = true;
        info!("QemuBackend: initialized for {variant_name} ({memory}MB, vbios={vbios})",
            memory = self.memory_mb,
            vbios = self.vbios.as_ref().map(|_| "yes").unwrap_or("no")
        );
        Ok(())
    }

    fn exec(&mut self, code: &str) -> Result<String> {
        if !self.initialized {
            return Err(ApiError::sandbox("QemuBackend not initialized; call init() first"));
        }

        let variant_name = &self.variant_name;
        info!("QemuBackend: executing code for {variant_name}");

        // Always use KVM. No TCG fallback.
        //
        // Two mitigations prevent VFIO_MAP_DMA failures:
        //
        // 1. pci-hole64-size=64G (see try_exec): Caps the QEMU 64-bit PCI
        //    MMIO window to 64 GB, keeping all GPU BAR addresses below the
        //    39-bit IOMMU boundary. This avoids VFIO_MAP_DMA: Invalid argument
        //    on Intel mobile platforms with 39-bit Host Address Width.
        //
        // 2. tinymachine_dma_fix.ko (see ensure_dma_mask_64): Sets dma_mask=64
        //    on the VFIO-bound GPU to fix kernel BZ 217237. Loading this
        //    module requires sudo. If unavailable, pci-hole64=64G still
        //    avoids VFIO_MAP_DMA for BAR addresses.
        //
        // If VFIO_MAP_DMA still fails, it means:
        // - The IOMMU aperture is smaller than 39 bits (unlikely on x86_64)
        // - RLIMIT_MEMLOCK is insufficient
        self.try_exec(code, true)
    }

    fn reset(&mut self) -> Result<()> {
        // Kill any running QEMU process
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Each exec() creates a fresh QEMU, so reset is a no-op beyond cleanup.
        Ok(())
    }

    fn destroy(&mut self) -> Result<()> {
        self.reset()?;
        self.initialized = false;
        Ok(())
    }
}

impl Drop for QemuBackend {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
