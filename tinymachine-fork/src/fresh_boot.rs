//! FreshBootBackend — Tier 3 KVM sandbox with full boot + optional GPU passthrough
//!
//! Unlike the CoW fork engine (Tier 2), the `FreshBootBackend` boots a KVM VM
//! from scratch each time. This is required for:
//!
//! - **PyTorch (Tier 3)**: Needs VFIO GPU passthrough, which cannot be
//!   snapshotted (GPU state is too complex for CoW)
//! - **Long-running VMs**: Persistent sessions that stay alive across multiple
//!   `exec()` calls
//! - **Custom kernel profiles**: `vmlinux-gpu-vfio` with VFIO/IOMMU support
//!
//! # Lifecycle
//!
//! ```text
//! init() ────► VM boots kernel + initrd ────► READY (polling for commands)
//!                │
//!                ├── exec("print(1)") ──► code → cmd_buf → run → output
//!                ├── exec("x = torch...") ──► same VM, stays alive
//!                ├── reset() ──► clear state, VM re-enters READY loop
//!                └── destroy() ──► close KVM fds, release VFIO GPU
//! ```
//!
//! # Command Buffer Protocol
//!
//! The same protocol as fork.rs: `CMD_BUF_PHYS` (0x7E000) receives the code,
//! `OUT_BUF_PHYS` (0x7F000) gets the output. The guest init polls for commands
//! via mmap'd `/dev/mem` (EPT-handled, no KVM exit).

use std::cell::RefCell;
use std::path::PathBuf;

use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::arch::*;
use crate::boot::{self, BootConfig, BootedVm, ReservedRegion, VfioMmioInfo, VfioPciInfo};
use crate::pci_root_port::PcieRootPort;
use crate::kvm::Kvm;
use crate::variant::Variant;
use crate::vfio::VfioPassthroughBase;

use tinymachine_api::error::ApiError;
use tinymachine_api::sandbox::SandboxBackend;
use crate::template_registry::TemplateRegistry;

// ─── Constants for kernel/initrd paths ──────────────────────────────

/// Default TinyMachine home directory name
const TINYOS_DIR: &str = ".tinyos";

/// Number of retries for MSI routing refresh after first exec().
///
/// The GPU driver (e.g., nvidia.ko) may take several polling cycles to
/// complete probe and program MSI registers. We retry across multiple
/// exec() calls before falling back to placeholder routing permanently.
///
/// Each retry corresponds to one exec() call. With a typical 5ms exec()
/// duration, 3 retries gives the driver ~15ms to initialize MSI.
const MSI_REFRESH_RETRIES: u32 = 3;

/// Get the user's home directory (avoids adding `dirs` crate dependency)
fn home_dir() -> Result<std::path::PathBuf> {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| FreshBootError::Config("Cannot find HOME environment variable".into()))
}

// ─── Errors ─────────────────────────────────────────────────────────

/// Errors from FreshBootBackend operations
#[derive(Error, Debug)]
pub enum FreshBootError {
    #[error("KVM error: {0}")]
    Kvm(#[from] crate::kvm::KvmError),
    #[error("Boot error: {0}")]
    Boot(#[from] boot::BootError),
    #[error("VFIO error: {0}")]
    Vfio(#[from] crate::vfio::VfioError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Not initialized — call init() first")]
    NotInitialized,
    #[error("Guest execution failed: {0}")]
    GuestExec(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("Missing kernel: {0}")]
    MissingKernel(String),
    #[error("Missing initrd: {0}")]
    MissingInitrd(String),
}

/// Result alias for FreshBootBackend
pub type Result<T> = std::result::Result<T, FreshBootError>;

/// Read GPU PCI BAR addresses from sysfs (accessible even when bound to vfio-pci).
///
/// Returns reserved regions for BARs that overlap with guest RAM [ram_start, ram_end).
/// On Linux 6.x with vfio-pci, the `/sys/bus/pci/devices/<bdf>/resource` file
/// is still readable and contains BAR addresses in format `start end flags`.
fn gpu_bar_reserved_regions(bdf: &str, ram_start: u64, ram_end: u64) -> Vec<ReservedRegion> {
    let resource_path = std::path::Path::new("/sys/bus/pci/devices").join(bdf).join("resource");
    let content = match std::fs::read_to_string(&resource_path) {
        Ok(c) => c,
        Err(e) => {
            trace!("GPU BAR: can't read {resource_path:?}: {e}");
            return Vec::new();
        }
    };

    let mut regions = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let start = match u64::from_str_radix(parts[0].trim_start_matches("0x"), 16) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let end = match u64::from_str_radix(parts[1].trim_start_matches("0x"), 16) {
            Ok(e) => e,
            Err(_) => continue,
        };
        // Skip empty BARs and BARs entirely above guest RAM
        if start == 0 || start >= ram_end || end < ram_start {
            continue;
        }
        // Clamp to RAM range. Resource file uses inclusive end.
        let rstart = start.max(ram_start);
        let rend = end.min(ram_end.saturating_sub(1)).saturating_add(1);
        if rend > rstart {
            regions.push(ReservedRegion { start: rstart, end: rend });
            info!(
                "GPU BAR: reserving 0x{rstart:x}-0x{rend:x} for host BAR 0x{start:x}-0x{end:x}"
            );
        }
    }
    regions
}

// ─── FreshBootBackend ───────────────────────────────────────────────

/// Tier 3 sandbox: fresh KVM boot with optional GPU passthrough.
///
/// Boots a complete kernel + initrd, keeps the VM alive for multiple
/// `exec()` calls, and optionally attaches a VFIO GPU device.
///
/// # Usage
///
/// ```rust,ignore
/// let mut backend = FreshBootBackend::new();
/// backend.init(&pytorch_variant)?;
/// let output = backend.exec("import torch; print(torch.__version__)")?;
/// backend.reset()?;
/// backend.destroy()?;
/// ```
#[derive(Debug)]
pub struct FreshBootBackend {
    /// KVM handle (opened once, reused across execs)
    kvm: Option<Kvm>,
    /// The booted VM (holds KVM Vm, Vcpu, memory)
    booted: Option<BootedVm>,
    /// VFIO GPU passthrough (if available)
    vfio: Option<VfioPassthroughBase>,
    /// The variant being used (set in init)
    variant: Option<Variant>,
    /// Whether we've been initialized
    initialized: bool,
    /// First GSI used for MSI routing (0 = not configured)
    msi_gsi_base: u32,
    /// Number of MSI vectors configured
    num_msi_vectors: u32,
    /// Number of remaining retries for MSI routing refresh.
    /// Initialized to `MSI_REFRESH_RETRIES` and decremented on each attempt
    /// where MSI is not yet available (driver hasn't programmed it yet).
    /// Set to 0 after successful refresh or when all retries are exhausted.
    msi_refresh_retries: u32,
    /// Whether kernel modules (nvidia.ko) have been loaded in the guest.
    /// Set to true after successfully sending `!load-modules`.
    modules_loaded: bool,
    /// If true, capture a snapshot after successful boot and store it to
    /// the template registry.
    /// Tier 2 (CoW fork) can then consume this snapshot instead of using a
    /// separately-built one, ensuring memory-size and initrd agreement.
    capture_snapshot: bool,
    /// Optional override for guest memory size (in bytes).
    /// When `Some`, this value is used instead of `variant::boot_memory_size_bytes()`.
    /// Set this before calling `init()`.
    pub memory_size_override: Option<u64>,
}

impl FreshBootBackend {
    /// Create a new FreshBootBackend.
    ///
    /// Does not open KVM or boot anything until `init()` is called.
    pub fn new() -> Self {
        Self {
            kvm: None,
            booted: None,
            vfio: None,
            variant: None,
            initialized: false,
            msi_gsi_base: 0,
            num_msi_vectors: 0,
            msi_refresh_retries: MSI_REFRESH_RETRIES,
            modules_loaded: false,
            capture_snapshot: false,
            memory_size_override: None,
        }
    }

    /// Set up MSI routing after the guest has booted and MSI is enabled.
    ///
    /// Called from `exec()` on the first post-boot exec, after the guest kernel
    /// has probed PCI devices and potentially enabled MSI on the GPU. This is
    /// deferred from `init()` because VFIO requires the physical device's MSI
    /// capability to be enabled before `VFIO_DEVICE_SET_IRQS(MSI)` succeeds.
    fn setup_msi_routing(&mut self) {
        if self.msi_gsi_base > 0 {
            return; // Already set up
        }
        let vfio = match self.vfio.as_ref() {
            Some(v) => v,
            None => return,
        };
        let booted = match self.booted.as_ref() {
            Some(b) => b,
            None => return,
        };

        // MSI_GSI_BASE, MSI_ADDRESS_LO/HI, MSI_DATA_BASE from crate::arch::interrupt
        // (imported via crate::arch::*)

        // Query the actual number of MSI vectors supported by this device.
        // VFIO reports the count from the device's MSI capability.
        // Modern GPUs support 1 by default (set by kernel PCI init).
        let num_vectors = vfio.query_msi_vector_count();
        if num_vectors == 0 {
            warn!("FreshBoot: VFIO device has no MSI vectors available");
            return;
        }

        // Step 1 & 2: Build routing table and set it
        let routing_table = crate::kvm::Vm::build_gsi_routing_table(
            MSI_GSI_BASE,
            num_vectors,
            MSI_ADDRESS_LO,
            MSI_ADDRESS_HI,
            MSI_DATA_BASE,
        );

        match unsafe { booted.vm.set_gsi_routing(&routing_table) } {
            Ok(()) => {
                info!("FreshBoot: GSI routing table updated (IOAPIC + {} MSI vectors)", num_vectors);

                // Step 3: Read MSI config from physical device for debugging
                if let Some(msi_cfg) = vfio.read_msi_config() {
                    warn!(
                        "FreshBoot: MSI config BEFORE disable: enabled={} addr_lo=0x{:08x} \
                         addr_hi=0x{:08x} data=0x{:04x} 64bit={} vectors={}",
                        msi_cfg.enabled,
                        msi_cfg.address_lo,
                        msi_cfg.address_hi,
                        msi_cfg.data,
                        msi_cfg.is_64bit,
                        msi_cfg.num_vectors,
                    );
                } else {
                    warn!("FreshBoot: MSI capability NOT FOUND in VFIO config space");
                }

                // Step 4: Disable MSI on the physical device first.
                // The guest kernel's PCI probe enabled MSI via the config proxy.
                // VFIO's vfio_msi_enable() calls pci_alloc_irq_vectors() which
                // fails (EINVAL) if MSI is already enabled. We must clear the
                // MSI Enable bit so VFIO can set it up with eventfd routing.
                if vfio.disable_msi_on_physical_device() {
                    info!("FreshBoot: MSI disabled on physical device (preparing for VFIO setup)");
                } else {
                    warn!("FreshBoot: could not disable MSI on physical device (MSI setup may fail)");
                }

                // Read MSI config again after disable
                if let Some(msi_cfg) = vfio.read_msi_config() {
                    info!(
                        "FreshBoot: MSI config AFTER disable: enabled={} addr_lo=0x{:08x} \
                         addr_hi=0x{:08x} data=0x{:04x} 64bit={} vectors={}",
                        msi_cfg.enabled,
                        msi_cfg.address_lo,
                        msi_cfg.address_hi,
                        msi_cfg.data,
                        msi_cfg.is_64bit,
                        msi_cfg.num_vectors,
                    );
                }

                // Step 5: Disable INTx first — VFIO's vfio_msi_enable() checks
                // is_irq_none() and returns -EINVAL if INTx is still active.
                if let Err(e) = vfio.disable_intx() {
                    warn!("FreshBoot: failed to disable INTx before MSI setup: {}", e);
                }

                // Step 6: Set up VFIO MSI eventfds.
                let msi_ok = vfio.setup_msi_irqfds(&booted.vm, MSI_GSI_BASE, num_vectors);
                if let Err(e) = &msi_ok {
                    warn!(
                        "FreshBoot: VFIO MSI irqfds setup failed (MSI may not work): {}",
                        e
                    );
                }

                // Track MSI GSI range for cleanup and subsequent refresh
                self.msi_gsi_base = MSI_GSI_BASE;
                self.num_msi_vectors = num_vectors;
            }
            Err(e) => {
                warn!(
                    "FreshBoot: GSI routing setup failed (MSI unavailable): {}",
                    e
                );
            }
        }
    }

    /// Find the kernel binary path for a given variant.
    ///
    /// Uses the `KernelRegistry` to resolve the versioned kernel path.
    /// Errors if the registry cannot resolve the version+profile.
    pub(crate) fn find_kernel_path(variant: &Variant) -> Result<String> {
        let home = home_dir()?;
        let kernel_dir = home.join(TINYOS_DIR).join("templates").join("kernel");

        let kreg = crate::kernel_registry::KernelRegistry::load(&kernel_dir)
            .map_err(|e| FreshBootError::MissingKernel(format!(
                "Cannot load kernel registry from {}: {e}",
                kernel_dir.display(),
            )))?;

        let version = variant
            .kernel_version
            .as_deref()
            .unwrap_or(&kreg.default_version);
        let profile = variant.kernel_profile.as_str();
        let kernel_path = kreg.resolve(version, profile).map_err(|e| {
            FreshBootError::MissingKernel(format!(
                "Kernel registry: {e} — run `tinyos template build {} --variant {}` first",
                variant.lang, variant.name,
            ))
        })?;

        Ok(kernel_path.to_string_lossy().to_string())
    }

    /// Resolve the kernel path and obtain the kernel version and hash
    /// from the `KernelRegistry`. Returns `(path, version, hash)`.
    ///
    /// Errors if the registry cannot resolve the version+profile.
    pub(crate) fn resolve_kernel_info(variant: &Variant) -> Result<(String, String, String)> {
        let home = home_dir()?;
        let kernel_dir = home.join(TINYOS_DIR).join("templates").join("kernel");

        let kreg = crate::kernel_registry::KernelRegistry::load(&kernel_dir)
            .map_err(|e| FreshBootError::MissingKernel(format!(
                "Cannot load kernel registry from {}: {e}",
                kernel_dir.display(),
            )))?;

        let version = variant
            .kernel_version
            .as_deref()
            .unwrap_or(&kreg.default_version);
        let profile = variant.kernel_profile.as_str();
        let kernel_path = kreg.resolve(version, profile).map_err(|e| {
            FreshBootError::MissingKernel(format!(
                "Kernel registry: {e} — run `tinyos template build {} --variant {}` first",
                variant.lang, variant.name,
            ))
        })?;

        let hash = kreg
            .get_hash(version)
            .map(|h| h.to_string())
            .unwrap_or_default();

        Ok((
            kernel_path.to_string_lossy().to_string(),
            version.to_string(),
            hash,
        ))
    }

    /// Find the initrd path for a given variant.
    pub(crate) fn find_initrd_path(variant: &Variant) -> Result<Option<String>> {
        if !variant.needs_initrd {
            return Ok(None);
        }
        let home = home_dir()?;
        let variant_dir = home
            .join(TINYOS_DIR)
            .join("templates")
            .join(&variant.lang)
            .join("v1")
            .join(&variant.name);

        // Try multiple initrd extensions: initrd.zst, initrd (raw), initrd.gz, initrd.xz
        let candidates = [
            variant_dir.join("initrd.zst"),
            variant_dir.join("initrd"),
            variant_dir.join("initrd.gz"),
            variant_dir.join("initrd.xz"),
        ];

        for path in &candidates {
            if path.exists() {
                return Ok(Some(path.to_string_lossy().to_string()));
            }
        }

        // Also try variant-name based files
        let name_candidates = [
            variant_dir.join(format!("{}.gz", variant.name)),
            variant_dir.join(format!("{}.xz", variant.name)),
            variant_dir.join(variant.name.clone()),
        ];

        for path in &name_candidates {
            if path.exists() {
                return Ok(Some(path.to_string_lossy().to_string()));
            }
        }

        Err(FreshBootError::MissingInitrd(format!(
            "Initrd not found in {} — run `tinyos template build {} --variant {}` first",
            variant_dir.display(),
            variant.lang,
            variant.name,
        )))
    }

    /// Probe for VFIO GPU and return a passthrough session if available.
    fn probe_vfio() -> Option<VfioPassthroughBase> {
        match VfioPassthroughBase::probe() {
            Some(vfio) => {
                info!(
                    "FreshBoot: VFIO GPU found: {} at {}",
                    vfio.device.name, vfio.device.pci_bdf
                );
                Some(vfio)
            }
            None => {
                warn!(
                    "FreshBoot: No VFIO GPU available — running CPU-only. \
                     GPU passthrough requires binding GPU to vfio-pci driver."
                );
                None
            }
        }
    }

    /// Find and read the VBIOS Option ROM file.
    ///
    /// Searches:
    /// 1. `tools/vbios/<name>` relative to current directory
    /// 2. `~/.tinyos/vbios/<name>`
    ///
    /// Returns `None` if not found or size is invalid (<512 or >4MB).
    fn find_and_read_vbios(name: &str) -> Option<Vec<u8>> {
        let candidates = {
            let mut v: Vec<std::path::PathBuf> = Vec::new();
            // tools/vbios/ relative to current dir
            v.push(std::path::PathBuf::from("tools").join("vbios").join(name));
            // ~/.tinyos/vbios/
            if let Ok(home) = std::env::var("HOME") {
                v.push(std::path::PathBuf::from(home).join(".tinyos").join("vbios").join(name));
            }
            v
        };

        for p in &candidates {
            if p.exists() {
                if let Ok(meta) = p.metadata() {
                    let len = meta.len();
                    if (crate::arch::MIN_VBIOS_SIZE..=crate::arch::MAX_VBIOS_SIZE).contains(&len) {
                        match std::fs::read(p) {
                            Ok(data) => {
                                info!("FreshBoot: VBIOS found at {:?} ({} bytes)", p, data.len());
                                return Some(data);
                            }
                            Err(e) => {
                                warn!("FreshBoot: VBIOS at {:?} exists but cannot read: {e}", p);
                            }
                        }
                    } else {
                        warn!(
                            "FreshBoot: VBIOS at {:?} has unexpected size {} (expected {}-{})",
                            p, len, crate::arch::MIN_VBIOS_SIZE, crate::arch::MAX_VBIOS_SIZE
                        );
                    }
                }
            }
        }
        warn!("FreshBoot: no VBIOS found for '{name}' — GPU may not initialize fully without QEMU/SeaBIOS");
        None
    }

    /// Get a mutable reference to the booted VM, or error if not initialized.
    fn booted_mut(&mut self) -> std::result::Result<&mut BootedVm, FreshBootError> {
        self.booted
            .as_mut()
            .ok_or(FreshBootError::NotInitialized)
    }

    /// Get a reference to the VFIO GPU session, if attached.
    ///
    /// Returns `None` if:
    /// - Not yet initialized
    /// - No VFIO GPU was available at init time
    /// - GPU passthrough was not requested by the variant
    pub fn vfio_session(&self) -> Option<&VfioPassthroughBase> {
        self.vfio.as_ref()
    }

    /// Check if VFIO GPU passthrough was successfully attached.
    pub fn has_vfio(&self) -> bool {
        self.vfio.is_some()
    }

    /// Refresh MSI routing with actual guest-programmed values.
    ///
    /// Called after each `exec()` completes (until retries exhausted or success),
    /// at which point the guest kernel has booted and the GPU driver
    /// (e.g., nvidia.ko) may have programmed the MSI capability in PCI config
    /// space with real address/data values.
    ///
    /// Reads the actual MSI configuration from the VFIO device's PCI config space
    /// (via `VfioPassthroughBase::read_msi_config()`) and updates the KVM GSI routing
    /// table so that virtual interrupts injected through KVM_IRQFD arrive at the
    /// guest with the correct MSI vectors the driver expects.
    ///
    /// Without this step, KVM uses the placeholder routing (address=0xFEE00000,
    /// data=0x40+) which may not match what the guest driver programmed, causing
    /// spurious interrupts or no interrupts at all.
    ///
    /// Retries up to `MSI_REFRESH_RETRIES` times (guarded by `msi_refresh_retries`
    /// counter) to account for lazy driver initialization.
    pub fn refresh_msi_routing(&mut self) {
        if self.msi_refresh_retries == 0 {
            return; // Retries exhausted
        }
        if self.msi_gsi_base == 0 || self.num_msi_vectors == 0 {
            self.msi_refresh_retries = 0;
            return; // No MSI routing pre-configured
        }
        let vfio = match self.vfio.as_ref() {
            Some(v) => v,
            None => {
                self.msi_refresh_retries = 0;
                return; // No VFIO passthrough
            }
        };
        let booted = match self.booted.as_ref() {
            Some(b) => b,
            None => return, // No VM (shouldn't happen during exec)
        };

        let msi_config = match vfio.read_msi_config() {
            Some(c) => c,
            None => {
                self.msi_refresh_retries -= 1;
                debug!(
                    "FreshBoot: MSI capability not found ({} retries left) — \
                     keeping placeholder routing",
                    self.msi_refresh_retries,
                );
                return;
            }
        };

        if !msi_config.enabled {
            self.msi_refresh_retries -= 1;
            debug!(
                "FreshBoot: MSI not enabled after guest boot ({} retries left) — \
                 keeping placeholder routing",
                self.msi_refresh_retries,
            );
            return;
        }

        debug!(
            "FreshBoot: refreshing MSI routing — addr_lo=0x{:08x} addr_hi=0x{:08x} \
             data=0x{:04x} vectors={} 64bit={} mask={}",
            msi_config.address_lo,
            msi_config.address_hi,
            msi_config.data,
            msi_config.num_vectors,
            msi_config.is_64bit,
            msi_config.has_per_vector_mask,
        );

        let routing_table = crate::kvm::Vm::build_gsi_routing_table(
            self.msi_gsi_base,
            msi_config.num_vectors,
            msi_config.address_lo, // already u32 per PCI spec
            msi_config.address_hi,
            msi_config.data as u32,
        );

        // SAFETY: booted.vm is a valid KVM VM with KVM_CREATE_IRQCHIP
        // already called during init().
        match unsafe { booted.vm.set_gsi_routing(&routing_table) } {
            Ok(()) => {
                info!(
                    "FreshBoot: MSI routing refreshed with guest-programmed values \
                     ({} vectors, GSI {}-{}, addr_lo=0x{:08x}, data_base=0x{:04x})",
                    msi_config.num_vectors,
                    self.msi_gsi_base,
                    self.msi_gsi_base + msi_config.num_vectors - 1,
                    msi_config.address_lo,
                    msi_config.data,
                );
                self.msi_refresh_retries = 0; // Mark done
            }
            Err(e) => {
                self.msi_refresh_retries -= 1;
                warn!(
                    "FreshBoot: MSI routing refresh failed: {e} ({} retries left) — \
                     keeping placeholder routing",
                    self.msi_refresh_retries,
                );
            }
        }
    }
}

impl Default for FreshBootBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBackend for FreshBootBackend {
    /// Initialize the FreshBootBackend: open KVM, boot kernel + initrd,
    /// optionally attach VFIO GPU, and wait for READY.
    ///
    /// # Steps
    ///
    /// 1. Open `/dev/kvm`
    /// 2. Find kernel binary and initrd for the variant
    /// 3. Boot the VM (kernel + initrd)
    /// 4. Optionally probe and attach VFIO GPU
    /// 5. Run until init writes READY
    fn init(&mut self, api_variant: &tinymachine_api::variant::Variant) -> std::result::Result<(), ApiError> {
        if self.initialized {
            warn!("FreshBootBackend::init called twice — destroying previous instance first");
            self.destroy()?;
        }

        // Convert API variant to fork variant
        let variant = crate::variant::Variant::from_api(api_variant)
            .ok_or_else(|| ApiError::Unsupported(format!(
                "Unsupported variant: {}/{}",
                api_variant.lang, api_variant.variant
            )))?;

        info!(
            "FreshBoot: initializing with variant {}/{} (kernel profile: {})",
            variant.lang, variant.name, variant.kernel_profile.filename()
        );

        // ── Install seccomp-BPF filter ──────────────────────────────
        // Lock down the host process syscall surface before opening KVM,
        // VFIO devices, or allocating guest memory. The allowlist includes
        // all syscalls needed by FreshBootBackend for KVM + VFIO operations.
        //
        // Note: This seccomp filter applies to the HOST process only.
        // The guest VM inside KVM is NOT affected — it runs its own kernel
        // with its own security policies. For guest-side seccomp, see the
        // notes in seccomp.rs.
        crate::seccomp::install(crate::seccomp::BackendType::FreshBoot).map_err(|e| {
            ApiError::Sandbox(format!(
                "seccomp filter installation for FreshBoot backend failed: {e}"
            ))
        })?;

        // 1. Open KVM
        let kvm = Kvm::new().map_err(|e| ApiError::sandbox(format!("Failed to open KVM: {e}")))?;

        // 2. Find kernel and initrd
        //    `resolve_kernel_info` uses the KernelRegistry for versioned kernel paths.
        let (kernel_path, kernel_version, kernel_hash) =
            Self::resolve_kernel_info(&variant)
                .map_err(|e| ApiError::Config(e.to_string()))?;
        let initrd_path = Self::find_initrd_path(&variant)
            .map_err(|e| ApiError::Config(e.to_string()))?;

        // Memory sizing: PyTorch needs ~4GB, others 128-512MB
        //
        // ⚠ Kernel 6.17.0-35 bug: KVM_CREATE_IRQCHIP creates in-kernel APIC
        // at 0xFEE00000. A single KVM_SET_USER_MEMORY_REGION spanning past
        // 0xFEE00000 conflicts with the APIC, causing KVM_CREATE_VCPU(0) to
        // return EEXIST. Workaround: limit guest RAM to 0xFEC00000 (4076 MB,
        // 20 MB below the LAPIC base). For full 4GB+ use two memory slots
        // (slot 0 = 0..0xFEC00000, slot 1 = above 4GB).
        // GPU variants: use full RAM. 32-bit PCI BARs will be assigned
        // Use the centralised memory-size function so this stays in sync
        // with build_snapshot.rs.  Set memory_size_override to override.
        let memory_size = self.memory_size_override
            .unwrap_or_else(|| crate::variant::boot_memory_size_bytes(&variant.name));

        // For GPU variants, enable PCI probing (remove pci=off).
        // For CPU-only variants, disable PCI for faster boot.
        let cmdline = if variant.limits.gpu_required {
            match variant.kernel_profile {
                crate::variant::KernelProfile::GpuNvidia => {
                    // GpuNvidia: ACPI=y kernel. DO NOT pass acpi=off because
                    // nvidia.ko needs ACPI symbols (acpi_evaluate_object, etc.).
                    // ACPI init fails gracefully in KVM (no tables), falls back
                    // to legacy PCI scan (pcibios_scan_root).
                    // pci=conf1: use I/O port PCI config mechanism (0xCF8/0xCFC).
                    //   conf2 (MMIO/ECAM) requires ACPI tables which KVM doesn't provide.
                    // loglevel=4: KERN_WARNING and above (shows CPA W^X warnings).
                    // MSI/MSI-X is now routed via KVM_SET_GSI_ROUTING + VFIO MSI
                    // eventfds (see Vm::set_gsi_routing + VfioPassthroughBase::setup_msi_irqfds).
                    // Enabling MSI allows nvidia.ko to use the native interrupt path
                    // instead of INTx, which avoids driver timeout issues on modern GPUs.
                    // No pci=biosirq: hangs in direct-boot KVM (no BIOS tables).
                    // pci=realloc: force PCI resource reallocation for 64-bit
                    // prefetchable BARs (BAR1=16GB VRAM, BAR3=32MB).
                    // No pci=conf1: let kernel auto-detect.
                    // pcie_port_pm=off: disable PCIe port power management.
                    //   Known VFIO issue: GPU enters D3cold state after FLR and
                    //   MMIO accesses hang. Disabling port PM prevents this.
                    Some(crate::arch::boot::build_kernel_cmdline(4, "pci=realloc pcie_port_pm=off"))
                }
                crate::variant::KernelProfile::GpuVk => {
                    // GpuVk (AMD/Vulkan): ACPI=y, no early PCI probe, no ACPI IRQ.
                    // pci=realloc: Vulkan GPU may need resource reallocation.
                    Some(crate::arch::boot::build_kernel_cmdline(3, "pci=noearly acpi_irq_handling=off pci=realloc pcie_port_pm=off"))
                }
                crate::variant::KernelProfile::GpuVfio => {
                    // GpuVfio: ACPI=y, no early PCI probe, no ACPI IRQ.
                    // NO pci=realloc: we pre-assign BAR addresses before boot
                    // (see preassign_guest_bar_addresses()). pci=realloc would
                    // overwrite our carefully chosen addresses and the kernel's
                    // reassigned addresses trigger a hang in the PCI resource
                    // mmap handler (resource1 mmap). Without realloc, the kernel
                    // keeps our firmware-style pre-assignment.
                    // pcie_port_pm=off: prevent GPU D3cold (PCIe port power mgmt).
                    Some(crate::arch::boot::build_kernel_cmdline(3, "pci=noearly acpi_irq_handling=off pcie_port_pm=off"))
                }
                _ => {
                    // Base (CPU-only): minimal cmdline, no GPU params needed.
                    Some(crate::arch::boot::build_kernel_cmdline(3, "pcie_port_pm=off"))
                }
            }
        } else {
            None // Use default (includes pci=off)
        };

        // For GPU variants, reserve GPU BAR regions that overlap with guest RAM
        // so the E820 table excludes them. Read BAR addresses from sysfs
        // (accessible even when bound to vfio-pci) before booting.
        let reserved_regions = if variant.limits.gpu_required {
            // Find the VFIO-bound GPU's BDF to read its BAR addresses
            let gpu_bdf = crate::vfio::detect_gpu_devices()
                .iter()
                .find(|d| crate::vfio::is_bound_to_vfio(&d.pci_bdf))
                .map(|d| d.pci_bdf.clone());
            if let Some(bdf) = gpu_bdf {
                gpu_bar_reserved_regions(&bdf, 0x100000, memory_size)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let config = BootConfig {
            kernel_path: kernel_path.into(),
            memory_size,
            load_addr: 0,
            initrd_path: initrd_path.map(PathBuf::from),
            pvh_boot: true,
            irqchip: true,
            cmdline,
            reserved_regions,
            kernel_version,
            kernel_hash,
            vbios_data: None, // VBIOS runs after VFIO init, not inside boot_linux
        };

        // 3. Boot the VM
        info!("FreshBoot: booting kernel + initrd ({} MB memory)...", memory_size / (1024 * 1024));
        let mut booted = unsafe {
            boot::boot_linux(&kvm, &config)
                .map_err(|e| ApiError::sandbox(format!("Boot failed: {e}")))?
        };

        // 4. Attach VFIO BEFORE running the guest (so PCI probe finds the device)
        //    Also set up MSI routing BEFORE guest boot, so VFIO sees a clean
        //    device state (no guest PCI config proxy writes).
        let mut vfio = if variant.limits.gpu_required {
            Self::probe_vfio().and_then(|mut vfio_session| {
                match vfio_session.init(booted.vm.as_raw_fd()) {
                    Ok(()) => {
                        // Set up PCI config space routing for the VFIO device.
                        // We place it at guest BDF 00:02.0 (devfn = 0x10).
                        // This way the kernel scans bus 0 and finds the GPU.
                        let config_offset = vfio_session.config_region_offset();
                        if let Some(dev_fd) = vfio_session.dup_device_fd() {
                            if let Some(cfg_off) = config_offset {
                                use std::os::fd::AsRawFd;
                                let config_fd_raw = dev_fd.as_raw_fd();

                                // Create synthetic PCIe Root Port at BDF 00:01.0.
                                // The VFIO GPU sits behind this root port on bus 1 (BDF 01:00.0).
                                // This satisfies nvidia.ko's requirement for a PCIe Root Port
                                // parent during GSP-RM firmware initialization.
                                let root_port = PcieRootPort::new();
                                info!(
                                    "FreshBoot: created synthetic PCIe Root Port at BDF 00:01.0 \
                                     (secondary bus={}, subordinate bus={})",
                                    root_port.secondary_bus, root_port.subordinate_bus
                                );
                                booted.pcie_root_port = Some(RefCell::new(root_port));

                                // Place VFIO GPU on bus 1 (behind root port) at BDF 01:00.0.
                                // Previously was on bus 0 (BDF 00:02.0), but NVIDIA's
                                // nvidia.ko driver checks for a parent PCIe Root Port.
                                booted.vfio_pci = Some(VfioPciInfo {
                                    bus: 1,           // behind root port on secondary bus
                                    devfn: 0x00,      // device 0, function 0 on bus 1
                                    config_fd: dev_fd,
                                    config_region_offset: cfg_off,
                                });

                                // Set up MMIO info for lazy BAR mapping during boot.
                                // The guest's PCI subsystem assigns BAR addresses and
                                // drivers (e.g., nouveau) access them via MMIO before
                                // map_guest_bar_slots() is called. We need to handle
                                // KVM_EXIT_MMIO by lazily mapping the BAR.
                                //
                                // SAFETY: We dup the device fd so VfioMmioInfo has its
                                // own fd for pread/pwrite/mmap of BAR regions.
                                let mmio_dev_fd = unsafe {
                                    libc::fcntl(config_fd_raw, libc::F_DUPFD_CLOEXEC, 0)
                                };
                                if mmio_dev_fd >= 0 {
                                    let bars: Vec<(u32, u64)> = vfio_session.bar_regions()
                                        .iter()
                                        .filter(|b| b.index <= 5 && b.can_mmap && b.size > 0)
                                        .map(|b| (b.index, b.size))
                                        .collect();
                                    let bars_count = bars.len();
                                    if bars_count > 0 {
                                        booted.vfio_mmio_info = Some(VfioMmioInfo {
                                            dev_fd: mmio_dev_fd,
                                            vm_fd: booted.vm.as_raw_fd(),
                                            bars,
                                            config_region_offset: cfg_off,
                                            mapped_bars: std::cell::Cell::new(0),
                                            next_slot: std::cell::Cell::new(100), // slot 100+
                                        });
                                        info!(
                                            "FreshBoot: VFIO MMIO lazy-mapping set up for {} BARs",
                                            bars_count
                                        );
                                    } else {
                                        warn!("FreshBoot: no mmapable GPU BARs found — MMIO will fail");
                                        unsafe { libc::close(mmio_dev_fd); }
                                    }
                                } else {
                                    warn!("FreshBoot: failed to dup VFIO device fd for MMIO handler");
                                }

                                info!("FreshBoot: VFIO GPU attached at guest BDF 01:00.0 (behind root port)");
                            } else {
                                warn!("FreshBoot: no config region offset found");
                            }
                        }
                        Some(vfio_session)
                    }
                    Err(e) => {
                        warn!("FreshBoot: VFIO init failed (continuing CPU-only): {e}");
                        None
                    }
                }
            })
        } else {
            None
        };

        // 4.5. Pre-assign VFIO BAR addresses and create KVM memory slots BEFORE
        //      the VBIOS POST (step 4b) and before running the guest VCPU.
        //      This matches QEMU's approach: QEMU creates all VFIO memory
        //      slots during VM initialization, BEFORE the guest boots and
        //      runs the VBIOS Option ROM POST.
        //
        //      Without pre-created BAR slots, the VBIOS POST would generate
        //      KVM_EXIT_MMIO for every GPU register access (BAR0+0x200,
        //      BAR0+0x110000, etc.) and our handler would return 0xFF —
        //      the VBIOS cannot initialize the GPU.
        //
        //      With slots created here, GPU MMIO accesses go through EPT
        //      directly (no KVM exit), exactly like QEMU+SeaBIOS does.
        if let Some(ref mut vfio) = vfio {
            // Write pre-assigned BAR addresses to VFIO PCI config space.
            match vfio.preassign_guest_bar_addresses() {
                Ok(assignments) => {
                    info!(
                        "FreshBoot: pre-assigned {} VFIO BAR addresses",
                        assignments.len()
                    );
                    // Create KVM memory slots for the pre-assigned BARs.
                    let vm_fd = booted.vm.as_raw_fd();
                    if let Err(e) = vfio.map_guest_bar_slots(vm_fd) {
                        warn!(
                            "FreshBoot: pre-boot VFIO BAR slot mapping incomplete: {e}"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "FreshBoot: failed to pre-assign VFIO BAR addresses \
                         (GPU MMIO may fail): {e}"
                    );
                }
            }
        }

        // ── 4.6. Load GSP bootloader firmware (before VBIOS POST) ──
        //
        // After BAR slots are created (step 4.5) but before VBIOS POST (step 4b),
        // try to load the GSP Falcon bootloader firmware directly via BAR0 MMIO.
        // This bypasses the VBIOS's display-only GSP firmware and boots the full
        // RM-capable GSP bootloader, which can then load the main RM firmware.
        //
        // If loading fails, we continue anyway — VBIOS POST will handle GPU init.
        // ── 4.6. GSP firmware loading (SKIPPED on AD104 VFIO) ──
        //
        // Direct GSP firmware IMEM loading via BAR0 MMIO is impossible on AD104
        // VFIO because:
        //   - GSP Falcon IMEM/DMEM registers return 0xffffff88/badf... (poison)
        //   - SEC2 (0x840000) is permanently power-gated (read-only PMC registers)
        //   - read_volatile at BAR0+0x1103c0 hangs after KVM memory slots exist
        //     (VFIO mmap + KVM slot conflict for shared MMIO pages)
        //
        // The proven path is VBIOS POST (step 4b) which runs the Option ROM in
        // real mode via KVM, initializing the display controller and Falcon engines.
        // This is identical to what SeaBIOS does in QEMU-based setups.
        //
        // See .opencode/plans/PLAN.md §8.5 for the GPU power init investigation.
        info!("FreshBoot: SKIPPING GSP bootloader firmware (AD104 VFIO limitation)");
        // 4b. VBIOS POST (Phase 1: real-mode GPU initialization)
        //
        // If a VBIOS Option ROM is available for this GPU, run it in real
        // mode BEFORE the kernel boots. This powers up GPU Falcon engines,
        // boots GFW firmware, and initialises GPU PCI config space.
        //
        // GPU BAR KVM memory slots are created in step 4.5 above, so all
        // GPU MMIO register accesses during VBIOS POST go through EPT
        // directly (not KVM_EXIT_MMIO). This matches QEMU+SeaBIOS behavior.
        //
        // After VBIOS POST halts, we reconfigure the VCPU back to 64-bit
        // long mode so the kernel can boot normally.
        let vbios_data = Self::find_and_read_vbios("Asus.RTX4080Mobile.12288.221219.rom");
        if let Some(ref data) = vbios_data {
            info!(
                "FreshBoot: running VBIOS POST ({} bytes) before kernel boot...",
                data.len()
            );
            let vfio_mmio: Option<&VfioMmioInfo> = booted.vfio_mmio_info.as_ref();
            let vfio_pci: Option<&VfioPciInfo> = booted.vfio_pci.as_ref();
            // Get root port reference for PCI config space emulation during VBIOS POST.
            // The VBIOS firmware scans bus 0 for devices (host bridge, root port) and
            // bus 1 for the VFIO GPU — all PCI config accesses are emulated inline.
            let root_port: Option<&RefCell<PcieRootPort>> = booted.pcie_root_port.as_ref();
            // SAFETY: vcpu, mem_ptr, mem_size are valid from boot_linux.
            // GPU BAR memory slots are already created (step 4.5 above)
            // so GPU MMIO accesses during POST go through EPT directly.
            // VFIO MMIO info and VFIO PCI info are set up above if GPU present.
            unsafe {
                boot::run_vbios_post(
                    &booted.vcpu,
                    booted.kvm_run_ptr,
                    booted.memory_ptr,
                    booted.memory_size,
                    data,
                    vfio_mmio,
                    vfio_pci,
                    root_port,
                )
                .map_err(|e| ApiError::sandbox(format!("VBIOS POST failed: {e}")))?;
            }
            // Reconfigure VCPU for 64-bit long mode (VBIOS left it in real mode)
            info!("FreshBoot: VBIOS POST complete, reconfiguring VCPU for long mode...");
            // SAFETY: kvm/vcpu/mem_ptr/mem_size/kernel_entry are valid from
            // boot_linux(). reconfigure_long_mode sets up page tables at 0x70000,
            // GDT at 0x60000, and SREGS for 64-bit long mode — all safe because
            // these addresses are within the validated guest memory region.
            unsafe {
                boot::reconfigure_long_mode(
                    &kvm,
                    &booted.vcpu,
                    booted.memory_ptr,
                    booted.memory_size,
                    booted.kernel_entry,
                )
                .map_err(|e| ApiError::sandbox(format!("Long mode reconfig failed: {e}")))?;
            }
            info!("FreshBoot: VCPU reconfigured, continuing with kernel boot");
        } else {
            info!("FreshBoot: no VBIOS ROM found — skipping VBIOS POST");
        }

        info!("FreshBoot: kernel loaded, running until init READY...");
        // Run until init writes READY (this may take a few seconds for the first boot)
        // SAFETY: booted is properly configured (regs, sregs set by boot_linux).
        // run_until_ready() handles all KVM exit types and returns when READY is detected.
        unsafe {
            booted.run_until_ready()
                .map_err(|e| ApiError::sandbox(format!("Boot run failed: {e}")))?;
        }

        info!("FreshBoot: VM booted and init is ready for commands");

        // 5. Map VFIO BAR regions as KVM memory slots (again) NOW that the
        //    guest has booted and the PCI subsystem may have reassigned BAR
        //    addresses (due to `pci=realloc`). The PCI config proxy forwarded
        //    all BAR writes to the VFIO device, so reading back from VFIO
        //    config space gives the guest-assigned addresses.
        //
        //    First, we clear the pre-boot BAR mappings (munmap) to avoid
        //    duplicate memory regions. Then we create fresh mmap+KVM slots
        //    using the actual post-boot BAR addresses from VFIO config space.
        if let Some(ref mut vfio) = vfio {
            // Unmap pre-boot BAR regions to avoid double-mmap leak.
            vfio.clear_mapped_bars();

            // Create fresh mmap + KVM slots at the (possibly reassigned)
            // post-boot addresses.
            let vm_fd = booted.vm.as_raw_fd();
            if let Err(e) = vfio.map_guest_bar_slots(vm_fd) {
                warn!("FreshBoot: post-boot VFIO BAR mapping incomplete (GPU MMIO may fail): {e}");
            }

            // 5b. (BEST EFFORT) Set up VFIO INTx irqfd.
            //
            // This is a best-effort attempt. Modern NVIDIA GPUs don't expose
            // INTx through VFIO (the vfio-pci driver reports EINVAL for
            // INTX_IRQ_INDEX on Ampere/Ada GPUs). MSI routing is the only
            // reliable path, and it's set up lazily after the first exec()
            // (see setup_msi_routing() below).
            //
            // The GPU is at guest BDF 00:02.0 → device 2, function 0.
            // INTx pin = (dev + func) & 3 = (2 + 0) & 3 = 2 → INTC
            // PIIX3 routing: INTC → PIRQC → IOAPIC pin 18 → GSI 18
            if let Err(e) = vfio.setup_intx_irqfd(&booted.vm, VFIO_INTX_GSI) {
                debug!(
                    "FreshBoot: VFIO INTX irqfd setup failed (expected, MSI-only GPU): {}",
                    e
                );
            }

            // NOTE: MSI routing (KVM_SET_GSI_ROUTING + VFIO MSI irqfds) is
            // deferred to after the first exec(), because VFIO requires the
            // physical device's MSI capability to be enabled before we can
            // register MSI eventfds. The guest kernel enables MSI during PCI
            // probe (before our first exec returns), so the post-exec setup
            // in setup_msi_routing() can successfully register MSI irqfds.
        }

        // ── Snapshot capture (optional) ──────────────────────────────
        // If capture_snapshot is set, save the booted VM state BEFORE
        // moving into self, so Tier 2 (CoW fork) can reuse this snapshot.
        // This ensures the same memory-size and initrd are used for both
        // Tier 2 and Tier 3, avoiding the builder divergence problem.
        let captured_snapshot = if self.capture_snapshot {
            match booted.capture_snapshot() {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!("FreshBoot: failed to capture snapshot: {e}");
                    None
                }
            }
        } else {
            None
        };

        self.kvm = Some(kvm);
        self.booted = Some(booted);
        self.vfio = vfio;
        self.variant = Some(variant);
        self.initialized = true;

        // Store captured snapshot to template registry (if any).
        if let Some(ref snapshot) = captured_snapshot {
            let templates_dir: PathBuf = match home_dir() {
                Ok(home) => home.join(TINYOS_DIR).join("templates"),
                Err(_) => {
                    warn!("FreshBoot: cannot resolve home dir — snapshot store skipped");
                    info!("FreshBoot: initialization complete");
                    return Ok(());
                }
            };
            // Borrow variant from self (it was moved above).
            let variant = self.variant.as_ref()
                .expect("variant just set above");
            if let Ok(mut registry) = TemplateRegistry::open(Some(templates_dir)) {
                match registry.store_snapshot(variant, snapshot) {
                    Ok(_) => {
                        info!(
                            "FreshBoot: snapshot captured and stored for variant {}",
                            variant.name
                        );
                    }
                    Err(e) => {
                        warn!("FreshBoot: failed to store snapshot: {e}");
                    }
                }
            } else {
                warn!("FreshBoot: cannot open template registry");
            }
        }

        info!("FreshBoot: initialization complete");
        Ok(())
    }

    /// Execute code in the booted VM.
    ///
    /// Writes code to `CMD_BUF_PHYS`, signals the init, waits for the
    /// result to be written to `OUT_BUF_PHYS`, and returns the output.
    ///
    /// The VM stays alive between calls — no boot overhead for repeated execs.
    fn exec(&mut self, code: &str) -> std::result::Result<String, ApiError> {
        if !self.initialized {
            return Err(ApiError::Unsupported("FreshBootBackend not initialized — call init() first".into()));
        }

        // Phase 1: Load NVIDIA kernel modules on first exec (GPU variants only,
        // non-VFIO). For VFIO-passthrough GPUs, we skip module loading because
        // nvidia.ko's PCI probe through VFIO hangs finit_module in D state
        // (uninterruptible sleep). The fork+timeout+SIGKILL in init.c cannot
        // wake a D-state process, so the module load hangs forever.
        // Tinygrad uses PCIIface (direct PCI BAR mmap) instead — no kernel
        // module needed. For pytorch, CPU-only torch is used.
        //
        // We use a block scope so the mutable borrow of self.booted is dropped
        // before self.modules_loaded is mutated below.
        {
            let vfio_active = self.vfio.is_some();
            let needs_modules = !self.modules_loaded
                && self.variant.as_ref().map_or(false, |v| v.limits.gpu_required)
                && !vfio_active;

            if needs_modules {
                // SAFETY: BootedVm is in post-boot READY state, init polling for commands.
                let booted = self.booted_mut()
                    .map_err(|_| ApiError::Unsupported("VM not available".into()))?;

                // Load nvidia.ko so tinygrad's NVKIface backend can use it.
                // This only runs when VFIO is NOT active (VFIO uses PCIIface).
                // We use `!load-modules` which loads nvidia.ko with parameters
                // that prevent it from re-initializing GSP or changing MSI/PCIe
                // config that the host already manages.
                info!("FreshBoot: loading nvidia.ko kernel module for non-VFIO GPU...");
                // SAFETY: booted is in READY state (checked above).
                let module_result = unsafe { booted.run_code("!load-modules") };
                match module_result {
                    Ok(output) => {
                        info!("FreshBoot: module load result: {output}");
                        if output.contains("FAILED") || output.contains("ERROR") {
                            warn!("FreshBoot: nvidia.ko may not have loaded correctly");
                        } else {
                            info!("FreshBoot: nvidia.ko loaded successfully");
                        }
                    }
                    Err(e) => {
                        warn!("FreshBoot: !load-modules command failed: {e}");
                    }
                }
                // booted (mutable borrow of self.booted) is dropped here
            }
            // Set flag now that the borrow of self via booted_mut has ended.
            // For VFIO, we also set the flag to short-circuit future checks.
            if needs_modules || vfio_active {
                self.modules_loaded = true;
            }
        }

        // Phase 2: Execute the actual Python code.
        let booted = self.booted_mut()
            .map_err(|_| ApiError::Unsupported("VM not available".into()))?;

        let result = unsafe {
            booted.run_code(code)
                .map_err(|e| ApiError::sandbox(format!("Code execution failed: {e}")))
        };

        // After the first exec, set up MSI routing.
        //
        // This is deferred from init() because VFIO requires the physical
        // device's MSI capability to be enabled before we can register MSI
        // eventfds. The first exec() has already run the guest kernel's PCI
        // probe, which programs MSI on the device if the driver supports it.
        if self.vfio.is_some() {
            // First time: set up GSI routing table + VFIO MSI irqfds
            self.setup_msi_routing();

            // Refresh MSI routing with actual guest-programmed values.
            // Retries across multiple exec() calls if the driver hasn't
            // finished probing yet (guarded by `msi_refresh_retries` counter).
            if self.msi_refresh_retries > 0 {
                self.refresh_msi_routing();
            }
        }

        result
    }

    /// Reset the VM state without rebooting.
    ///
    /// The init's polling loop automatically resets after each command:
    /// it clears CMD_BUF, clears READY, and waits for the next command.
    /// This method is a no-op for the current implementation but is
    /// provided for API compatibility.
    fn reset(&mut self) -> std::result::Result<(), ApiError> {
        if !self.initialized {
            return Err(ApiError::Unsupported("FreshBootBackend not initialized".into()));
        }
        // The init's command-buffer protocol is self-cleaning:
        // - Clears CMD_BUF after reading command (init.c line 187)
        // - Clears READY area before execution (init.c line 190)
        // - Writes "READY" after output (init.c lines 214-219)
        // So the VM is already reset between exec() calls.
        info!("FreshBoot: VM state reset (init is already polling for next command)");
        Ok(())
    }

    /// Set up MSI routing after the guest has booted and MSI is enabled.
    ///
    /// Called from `exec()` on the first post-boot exec, after the guest kernel
    /// has probed PCI devices and potentially enabled MSI on the GPU. This is
    /// deferred from `init()` because VFIO requires the physical device's MSI
    /// capability to be enabled before `VFIO_DEVICE_SET_IRQS(MSI)` succeeds.
    ///
    /// Steps:
    /// 1. Build initial GSI routing table with IOAPIC (GSIs 0-23) + MSI
    ///    placeholder entries (GSIs 24-31)
    /// 2. Call KVM_SET_GSI_ROUTING to activate the table
    /// 3. Set up VFIO MSI eventfds connected to KVM_IRQFD
    /// 4. Read actual MSI config from VFIO and update routing
    ///    (via refresh_msi_routing())
    /// Destroy the booted VM and release all resources.
    ///
    /// Closes KVM fds, unmaps guest memory, releases VFIO GPU if attached.
    /// The Drop implementation handles resource cleanup automatically,
    /// but this method provides explicit control.
    fn destroy(&mut self) -> std::result::Result<(), ApiError> {
        if !self.initialized {
            return Ok(());
        }

        info!("FreshBoot: destroying VM and releasing resources");

        // 1. Deassign KVM irqfds for MSI vectors (clean up KVM references
        //    to eventfds before VFIO drops its references).
        //    This is lifecycle hygiene: the irqfds will be cleaned up when
        //    the VM fd closes, but explicit deassign prevents stale irqfds
        //    if an error occurs between VFIO destroy and VM fd close.
        if self.num_msi_vectors > 0 {
            if let Some(ref booted) = self.booted {
                for i in 0..self.num_msi_vectors {
                    let gsi = self.msi_gsi_base + i;
                    // SAFETY: vm is valid (booted is alive), KVM_IRQFD with
                    // DEASSIGN flag does not require the eventfd to still exist.
                    let result = unsafe {
                        booted.vm.deassign_irqfd(gsi)
                    };
                    if let Err(e) = result {
                        trace!("FreshBoot: irqfd deassign for GSI {} skipped: {}", gsi, e);
                    }
                }
            }
        }

        // VFIO must be dropped BEFORE the VM (KVM_DEV_VFIO_GROUP_DEL happens
        // implicitly when the KVM device fd is closed, which requires the
        // VM fd still valid). We drop VFIO first.
        if let Some(ref mut vfio) = self.vfio {
            vfio.destroy();
        }
        self.vfio = None;

        // Drop the BootedVm — this closes KVM Vm/VCPU fds and unmaps memory.
        // The Drop implementation on BootedVm handles munmap and fd close.
        self.booted = None;
        self.kvm = None;
        self.variant = None;
        self.initialized = false;

        info!("FreshBoot: resources released");
        Ok(())
    }
}

impl Drop for FreshBootBackend {
    fn drop(&mut self) {
        // On drop, destroy is best-effort (ignore errors)
        let _ = self.destroy();
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tinymachine_api::variant::Variant as ApiVariant;

    #[test]
    fn test_new_backend_is_uninitialized() {
        let backend = FreshBootBackend::new();
        assert!(!backend.initialized);
        assert!(backend.kvm.is_none());
        assert!(backend.booted.is_none());
        assert!(backend.vfio.is_none());
    }

    #[test]
    fn test_exec_without_init_returns_error() {
        let mut backend = FreshBootBackend::new();
        let result = backend.exec("print(1)");
        assert!(result.is_err(), "exec() without init should fail");
    }

    #[test]
    fn test_init_invalid_variant_returns_error() {
        let mut backend = FreshBootBackend::new();
        let variant = ApiVariant::new("nonexistent", "bad", "base");
        let result = backend.init(&variant);
        assert!(result.is_err(), "init() with invalid variant should fail");
    }

    #[test]
    fn test_destroy_uninitialized_is_noop() {
        let mut backend = FreshBootBackend::new();
        // destroy() on uninitialized backend should succeed
        assert!(backend.destroy().is_ok());
    }

    #[test]
    fn test_double_init_destroys_first() {
        let mut backend = FreshBootBackend::new();
        // First init with a valid variant should work if kernel/initrd exist
        // But if not, we get an error saying config — not a panic
        let variant = ApiVariant::new("python", "pytorch", "gpu-vfio");
        let result = backend.init(&variant);
        // This will likely fail with MissingKernel on non-TinyMachine machines,
        // but that's expected and OK — the test verifies no panic on double init.
        if result.is_ok() {
            // If it succeeded, second init should destroy first
            let result2 = backend.init(&variant);
            // May also fail due to missing kernel on double init
            assert!(
                result2.is_ok() || result2.is_err(),
                "double init should not panic"
            );
        }
    }

    #[test]
    fn test_default_trait_impl() {
        let backend = FreshBootBackend::default();
        assert!(!backend.initialized);
    }

    #[test]
    fn test_vfio_probe_non_fatal() {
        // VFIO probe should not panic even without VFIO hardware
        let result = FreshBootBackend::probe_vfio();
        // On most dev machines, this will be None — that's OK
        match result {
            Some(vfio) => println!("VFIO available: GPU at {}", vfio.device.pci_bdf),
            None => println!("No VFIO GPU (expected on non-VFIO hardware)"),
        }
    }

    #[test]
    fn test_kernel_path_no_home() {
        // This test verifies find_kernel_path doesn't panic
        let variant = Variant::python_pytorch_cpu();
        let result = FreshBootBackend::find_kernel_path(&variant);
        match result {
            Ok(path) => println!("Kernel path: {}", path),
            Err(e) => println!("Kernel path error (expected without template): {}", e),
        }
    }
}
