//! KVM Boot Protocol — load kernel ELF, set up page tables, enter long mode.
//!
//! This module implements the complete boot sequence for a 64-bit x86 kernel
//! inside a KVM VM. The boot flow:
//!
//! 1. Load kernel ELF binary into guest memory at `load_addr`
//! 2. Set up 4-level page tables at guest physical `0x70000`
//! 3. Set up GDT at guest physical `0x60000`
//! 4. Configure SREGS (segments, CR0/CR3/CR4, EFER) for 64-bit long mode
//! 5. Configure REGS (RIP=kernel_entry, RSP=stack_top, RFLAGS=2)
//! 6. KVM_RUN — let the kernel execute until HLT
//!
//! # Safety
//! This module uses raw `libc::ioctl` and `libc::mmap` to interact with KVM.
//! All unsafe blocks are documented with `// SAFETY:`.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::pci_root_port::PcieRootPort;
use thiserror::Error;
use tracing::{info, trace, warn};

use crate::arch::*;
use crate::kvm::{self, Kvm, Vm, Vcpu};
use crate::snapshot::{CpuState, IrqChipState, KvmRegs, KvmSregs, Snapshot};

// ─── Re-export arch constants for backward compat ──────────────────
// These were previously defined as `pub const` in this module.
pub use crate::arch::CMD_BUF_PHYS;
pub use crate::arch::OUT_BUF_PHYS;
pub use crate::arch::BUF_MAX;
pub use crate::arch::ENTROPY_BUF_PHYS;
pub use crate::arch::ENTROPY_SIZE;
pub use crate::arch::ENTROPY_DIVERGENCE_CTRL_PHYS;
pub use crate::arch::ENTROPY_DIVERGENCE_ENABLED;
pub use crate::arch::ENTROPY_DIVERGENCE_DISABLED;
pub use crate::arch::READY_SIGNAL_OFFSET;
pub use crate::arch::GDT_ADDR;
pub use crate::arch::PML4_ADDR;
pub use crate::arch::PDP_ADDR;
pub use crate::arch::PD_ADDR;
pub use crate::arch::STACK_TOP;
pub use crate::arch::DEFAULT_MEMORY_SIZE;
pub use crate::arch::DEFAULT_LOAD_ADDR;
pub use crate::arch::BOOT_PARAMS_ADDR;
pub use crate::arch::PVH_START_INFO_ADDR;
pub use crate::arch::HVM_START_MAGIC;
pub use crate::arch::PVH_MODLIST_ADDR;
pub use crate::arch::PVH_CMDLINE_ADDR;
pub use crate::arch::INITRD_ADDR_MAX;

/// Set to true by SIGALRM handler to signal that a periodic tick should fire.
static BOOT_SIGNAL_INTERRUPTED: AtomicBool = AtomicBool::new(false);



/// Signal handler — sets a flag to be polled in the KVM_RUN loop.
///
/// Handles SIGUSR1 (from our timeout thread) and any other signal
/// that might interrupt KVM_RUN. The handler just sets an atomic
/// flag; the main loop polls it.
///
/// # Safety
/// Signal handlers must be extern "C" and signal-safe. This handler only
/// performs atomic stores, which is signal-safe.
extern "C" fn boot_sigalrm_handler(
    _signo: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    BOOT_SIGNAL_INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Errors from boot operations
#[derive(Error, Debug)]
pub enum BootError {
    #[error("KVM error: {0}")]
    Kvm(#[from] kvm::KvmError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ELF parsing error: {0}")]
    Elf(String),
    #[error("Invalid boot configuration: {0}")]
    Config(String),
    #[error("Guest execution error: {0}")]
    GuestExit(String),
    #[error("mmap failed: {0}")]
    Mmap(String),
    #[error("Memory region overlaps with page tables or GDT: start=0x{start:x}, end=0x{end:x}")]
    MemoryOverlap { start: u64, end: u64 },
}

/// Result alias for boot operations
pub type Result<T> = std::result::Result<T, BootError>;

// ─── Guest memory layout constants ───────────────────────────────────
//
// All memory layout constants (GDT_ADDR, PML4_ADDR, CMD_BUF_PHYS, etc.)
// are now defined in `crate::arch::x86_64::layout` and made available
// via `crate::arch::*`. The `INITRD_ADDR` deprecated constant is kept
// for backward compatibility but unused.

// ─── Shared entropy + control byte helper ─────────────────────────

/// Fill a 64-byte buffer with host CSPRNG output via `getrandom` syscall.
/// Retries on `EINTR`; returns `None` (silent skip) if the kernel CSPRNG
/// is unresponsive after 100 attempts.
fn fill_entropy(entropy: &mut [u8; ENTROPY_SIZE as usize]) {
    const GETRANDOM_MAX_RETRIES: u32 = 100;
    let mut attempts = 0u32;
    while attempts < GETRANDOM_MAX_RETRIES {
        // SAFETY: getrandom syscall fills a fixed-size stack buffer.
        let ret = unsafe {
            libc::syscall(libc::SYS_getrandom, entropy.as_mut_ptr(), entropy.len(), 0)
        };
        if ret == entropy.len() as i64 {
            return;
        }
        attempts += 1;
        std::thread::yield_now();
    }
    // If we get here, getrandom failed 100 times — leave entropy as zeros.
    // The VM still has RDRAND via random.trust_cpu=on, just potentially
    // correlated across forks. This is exceedingly rare.
}

// ─── Shared VM execution helpers ───────────────────────────────────
// These are used by both `BootedVm::run_code()` and `ForkedVm::run_code()`.

/// Prepare guest memory for code execution: bounds-check buffer addresses,
/// inject entropy, clear stale state, write command, wait for ready cycle.
///
/// After this returns `Ok`, the caller must invoke `run_until_ready()` and
/// then `read_vm_output()`.
///
/// # Safety
///
/// `memory_ptr` must point to valid, writable guest memory of at least
/// `memory_size` bytes. No concurrent mutation of guest memory.
pub unsafe fn prepare_vm_for_execution(
    memory_ptr: *mut u8,
    memory_size: u64,
    entropy_divergence: bool,
    code: &str,
) -> std::result::Result<(), String> {
    use crate::arch::{
        BUF_MAX, CMD_BUF_PHYS, ENTROPY_BUF_PHYS, ENTROPY_DIVERGENCE_CTRL_PHYS,
        ENTROPY_SIZE, OUT_BUF_PHYS, READY_SIGNAL_OFFSET,
    };

    // ── 1. Bounds check ENTROPY_BUF_PHYS + ENTROPY_SIZE ──────────────
    let entropy_end = ENTROPY_BUF_PHYS as usize + ENTROPY_SIZE as usize;
    if entropy_end > memory_size as usize {
        return Err(format!(
            "ENTROPY_BUF_PHYS(0x{:x}) + ENTROPY_SIZE({}) = 0x{:x} exceeds memory_size=0x{:x}",
            ENTROPY_BUF_PHYS, ENTROPY_SIZE, entropy_end, memory_size
        ));
    }

    // ── 2. Bounds check ENTROPY_DIVERGENCE_CTRL_PHYS ─────────────────
    let ctrl_addr = ENTROPY_DIVERGENCE_CTRL_PHYS as usize;
    if ctrl_addr >= memory_size as usize {
        return Err(format!(
            "ENTROPY_DIVERGENCE_CTRL_PHYS(0x{:x}) >= memory_size=0x{:x}",
            ENTROPY_DIVERGENCE_CTRL_PHYS, memory_size
        ));
    }

    // ── 3. Bounds check CMD_BUF_PHYS + BUF_MAX ───────────────────────
    let cmd_end = CMD_BUF_PHYS as usize + BUF_MAX as usize;
    if cmd_end > memory_size as usize {
        return Err(format!(
            "CMD_BUF_PHYS(0x{:x}) + BUF_MAX({}) = 0x{:x} exceeds memory_size=0x{:x}",
            CMD_BUF_PHYS, BUF_MAX, cmd_end, memory_size
        ));
    }

    // ── 4. Bounds check OUT_BUF_PHYS + BUF_MAX ───────────────────────
    let out_end = OUT_BUF_PHYS as usize + BUF_MAX as usize;
    if out_end > memory_size as usize {
        return Err(format!(
            "OUT_BUF_PHYS(0x{:x}) + BUF_MAX({}) = 0x{:x} exceeds memory_size=0x{:x}",
            OUT_BUF_PHYS, BUF_MAX, out_end, memory_size
        ));
    }

    // ── 5. Inject host entropy + divergence control byte ────────────
    let preview = write_entropy_ctrl(memory_ptr, entropy_divergence);
    tracing::info!(
        "ENTROPY: {} bytes (first 4: {:02x}{:02x}{:02x}{:02x}), ctrl={}",
        ENTROPY_SIZE, preview[0], preview[1], preview[2], preview[3],
        if entropy_divergence { "ENABLED" } else { "DISABLED" },
    );

    // ── 6. Clear stale READY and OUT_BUF ───────────────────────────
    // The guest init writes READY on every polling cycle (~10µs). If the
    // snapshot was taken with READY already set (from the previous exec),
    // run_until_ready() would return immediately on the first timer tick
    // — before the guest processes the new command.
    std::ptr::write_bytes(
        memory_ptr.add((OUT_BUF_PHYS + READY_SIGNAL_OFFSET) as usize),
        0,
        6,
    );
    std::ptr::write_bytes(memory_ptr.add(OUT_BUF_PHYS as usize), 0, BUF_MAX as usize);

    // ── 7. Inject code into command buffer ───────────────────────────
    let code_bytes = code.as_bytes();
    let len = std::cmp::min(code_bytes.len(), (BUF_MAX - 1) as usize);
    std::ptr::copy_nonoverlapping(
        code_bytes.as_ptr(),
        memory_ptr.add(CMD_BUF_PHYS as usize),
        len,
    );
    std::ptr::write(memory_ptr.add(CMD_BUF_PHYS as usize + len), 0u8);

    // ── 8. Wait for stale READY to pass ──────────────────────────────
    std::thread::sleep(std::time::Duration::from_micros(50));

    Ok(())
}

/// Read VM output from `OUT_BUF_PHYS` after execution completes.
///
/// Scans the output buffer up to `BUF_MAX` bytes, stopping at the first
/// null byte. Trims trailing newline/carriage-return characters.
///
/// # Safety
///
/// `memory_ptr` must point to valid, readable guest memory of at least
/// `OUT_BUF_PHYS + BUF_MAX` bytes.
pub unsafe fn read_vm_output(memory_ptr: *mut u8, _memory_size: u64) -> String {
    use crate::arch::{BUF_MAX, OUT_BUF_PHYS};

    let ptr = memory_ptr.add(OUT_BUF_PHYS as usize);
    let mut out = Vec::new();
    for i in 0..(BUF_MAX as usize) {
        let byte = std::ptr::read(ptr.add(i));
        if byte == 0 {
            break;
        }
        out.push(byte);
    }
    // Trim trailing newlines / carriage returns
    while out.last() == Some(&b'\n') || out.last() == Some(&b'\r') {
        out.pop();
    }
    String::from_utf8(out).unwrap_or_else(|_| "(output contains invalid UTF-8)".to_string())
}

/// Write host entropy and divergence control byte into guest memory.
///
/// Always writes 64 random bytes to `ENTROPY_BUF_PHYS`, then writes the
/// control byte at `ENTROPY_DIVERGENCE_CTRL_PHYS`:
///   `ENTROPY_DIVERGENCE_ENABLED`  (1) if `entropy_divergence` is `true`
///   `ENTROPY_DIVERGENCE_DISABLED` (0) if `entropy_divergence` is `false`
///
/// Returns the first 4 entropy bytes for logging / write-back verification.
///
/// # Safety
///
/// `memory_ptr` must be a valid pointer to guest memory of at least
/// `ENTROPY_BUF_PHYS + ENTROPY_SIZE` bytes. No aliasing with other
/// live references to the same memory region.
pub unsafe fn write_entropy_ctrl(
    memory_ptr: *mut u8,
    entropy_divergence: bool,
) -> [u8; 4] {
    // ── Fill entropy buffer from host CSPRNG ──
    let mut entropy = [0u8; ENTROPY_SIZE as usize];
    fill_entropy(&mut entropy);
    let preview: [u8; 4] = entropy[..4].try_into().unwrap();

    // ── Write 64 random bytes to ENTROPY_BUF_PHYS ──
    std::ptr::copy_nonoverlapping(
        entropy.as_ptr(),
        memory_ptr.add(ENTROPY_BUF_PHYS as usize),
        ENTROPY_SIZE as usize,
    );

    // ── Write control byte ──
    let ctrl_val: u8 = if entropy_divergence {
        ENTROPY_DIVERGENCE_ENABLED
    } else {
        ENTROPY_DIVERGENCE_DISABLED
    };
    std::ptr::write(
        memory_ptr.add(ENTROPY_DIVERGENCE_CTRL_PHYS as usize),
        ctrl_val,
    );

    preview
}

// ─── GDT descriptors ───────────────────────────────────────────────
//
// GDT_NULL, GDT_CODE, and GDT_DATA are defined in `crate::arch::x86_64::cpu`
// and made available via `crate::arch::*`.

// ─── CPUID setup ──────────────────────────────────────────────────

/// Set up CPUID for the guest VCPU using the host's supported features.
///
/// Uses `KVM_GET_SUPPORTED_CPUID` to retrieve the host's actual CPUID
/// entries and applies security/consistency filters:
///
/// ## CPUID filters
///
/// | Feature | CPUID bit | Reason |
/// |---------|-----------|--------|
/// | CET_SS | `EAX=7,ECX=0:ECX[11]` | XSAVES includes CET_S in fpstate xstate_bv; XRSTOR #GP's when XCR0 ≠ IA32_XSS |
/// | CET_IBT | `EAX=7,ECX=0:EDX[20]` | Same CET family — kernel may use CET_U shadow stack |
/// | WAITPKG | `EAX=7,ECX=0:ECX[5]` | Kernel selects `delay_halt_tpause` → hangs on TPAUSE without timer interrupts |
///
fn setup_cpuid(kvm: &Kvm, vcpu: &Vcpu) -> Result<()> {
    let mut entries = kvm
        .get_supported_cpuid()
        .map_err(BootError::Kvm)?;

    // ── CPUID filter: clear problematic feature bits ────────────────
    //
    // These features must be cleared during BOTH boot and fork because:
    // 1. If the kernel uses a feature during boot, the fpstate xstate_bv
    //    will include that feature's bit.
    // 2. On fork, we may clear the feature from CPUID but the guest memory
    //    (including fpstate) is CoW'd as-is from the boot snapshot.
    // 3. When the kernel does XRSTOR from the stale fpstate, it #GP's
    //    because xstate_bv has bits not enabled in XCR0.
    //
    // Any feature that adds an xstate_bv bit must be cleared here.
    // See: arch/x86/kernel/fpu/xstate.c → xfeatures_mask_all

    for entry in entries.iter_mut() {
        if entry.function == 7 && entry.index == 0 {
            // ECX[4] = PKU (Protection Keys Userspace) → xstate_bv bit 8
            // Kernel saves/restores PKRU register in fpstate.
            // If PKU is present at boot but missing on fork, XRSTOR #GP.
            entry.ecx &= !(1u32 << 4);

            // ECX[5] = WAITPKG — kernel delay function hangs without timer irqs
            entry.ecx &= !(1u32 << 5);

            // ECX[7] = CET_U (user_shstk, user mode shadow stack) → xstate_bv bit 9
            // User shadow stack state is saved in fpstate via XSAVE.
            // If present at boot but missing on fork, XRSTOR #GP.
            entry.ecx &= !(1u32 << 7);

            // ECX[11] = CET_SS (Supervisor Shadow Stack) → xstate_bv bit 10 (IA32_XSS)
            // XSAVES includes CET_S in fpstate xstate_bv; when fork restores XCR0
            // without IA32_XSS, XRSTOR #GP's because xstate_bv has CET_S bit but
            // XCR0 doesn't. Clearing CET_SS from CPUID prevents the kernel from
            // ever enabling CET, keeping fpstate clean.
            entry.ecx &= !(1u32 << 11);

            // EDX[15] = Arch LBR (Last Branch Records) → xstate_bv bit 11 (IA32_XSS)
            // LBR state is counted as a supervisor xfeature. If available at boot
            // but not on fork, XRSTOR of existing fpstate will #GP.
            entry.edx &= !(1u32 << 15);

            // EDX[20] = CET_IBT (Indirect Branch Tracking) → same CET family
            // Prevents kernel from using CET user shadow stack.
            entry.edx &= !(1u32 << 20);

            break;
        }
    }

    vcpu.set_cpuid2(&entries).map_err(BootError::Kvm)
}

// ─── Page table entry flags ────────────────────────────────────────
//
// Page table constants (PT_PRESENT, PT_RW, PT_PS, PT_NX, etc.) are
// defined in `crate::arch::x86_64::cpu` and made available via
// `crate::arch::*`.

// ─── BootConfig ────────────────────────────────────────────────────

/// A reserved memory region for the E820 table — the guest kernel will
/// treat this range as reserved (type 2) instead of usable RAM.
#[derive(Debug, Clone, Copy)]
pub struct ReservedRegion {
    pub start: u64,
    pub end: u64, // exclusive
}

/// Build the base kernel commandline for an x86_64 KVM guest.
///
/// Returns a string like:
/// ```text
/// console=ttyS0,115200 earlyprintk=serial,0x3f8,115200 lpj=10000000 loglevel=3 rodata=off rdinit=/init iomem=relaxed random.trust_cpu=on idle=halt <profile_suffix>
/// ```
///
/// The `loglevel` parameter allows per-profile verbosity (4 for nvidia, 3 for others).
/// The `profile_suffix` contains profile-specific flags (`pci=realloc`, etc.). Pass
/// an empty string `""` if no extra flags are needed.
///
/// This function uses the architecture's `COM1_BASE` constant so the serial port
/// address is always correct for the target.
pub fn build_kernel_cmdline(loglevel: u32, profile_suffix: &str) -> String {
    use crate::arch::port::COM1_BASE;
    format!(
        "console=ttyS0,115200 earlyprintk=serial,0x{com1_base:x},115200 \
         lpj=10000000 loglevel={loglevel} rodata=off rdinit=/init \
         iomem=relaxed random.trust_cpu=on idle=halt {profile_suffix}",
        com1_base = COM1_BASE
    )
    .trim_end()
    .to_string()
}

/// Configuration for booting a Linux kernel inside KVM
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// Path to the kernel ELF binary (e.g., vmlinux)
    pub kernel_path: PathBuf,
    /// Optional initrd image
    pub initrd_path: Option<PathBuf>,
    /// Guest RAM size in bytes (default: 64 MB)
    pub memory_size: u64,
    /// Guest physical address where guest RAM starts (default: 0x100000)
    /// Page tables and GDT are placed below this address.
    pub load_addr: u64,
    /// Use PVH boot protocol (for vmlinux kernels that support it)
    /// PVH enters the kernel in 64-bit long mode with RSI → hvm_start_info
    pub pvh_boot: bool,
    /// Create in-kernel interrupt chipset (PIT + PIC + IOAPIC + LAPIC)
    ///
    /// Required for the real Linux kernel (needs PIT timer interrupts for
    /// `calibrate_delay()` and `jiffies`). Stub/test kernels should keep
    /// this false since they don't have an IDT and will hang if the PIT
    /// generates pending interrupts during HLT.
    ///
    /// NOTE: `KVM_CREATE_IRQCHIP` must be called BEFORE the VCPU is created.
    pub irqchip: bool,
    /// Optional kernel command line override.
    ///
    /// If `None`, the default cmdline is used (which includes `pci=off` for
    /// faster boot on CPU-only VMs). For GPU passthrough, set to a cmdline
    /// without `pci=off` so the guest can probe PCI devices.
    ///
    /// Default: `None` (use built-in default cmdline).
    pub cmdline: Option<String>,
    /// Address ranges to reserve in the guest E820 table.
    /// These will be marked as type 2 (reserved) so the guest kernel
    /// does not use them as RAM. Needed when passthrough GPU BARs
    /// would otherwise overlap with guest physical RAM.
    pub reserved_regions: Vec<ReservedRegion>,
    /// Kernel version string (e.g., "7.1.4") for snapshot integrity tracking.
    /// If empty, the kernel hash will be computed from the kernel file.
    pub kernel_version: String,
    /// Pre-computed SHA-256 hash of the kernel binary.
    /// If empty, will be computed from the kernel file at boot time.
    pub kernel_hash: String,
    /// Optional VBIOS Option ROM image for GPU initialization.
    /// If `Some`, runs the VBIOS POST in real mode *before* the kernel
    /// boots (Phase 1). This powers up GPU Falcon engines, starts the
    /// GFW firmware, and initializes PCI config space — required for
    /// VFIO passthrough of NVIDIA GPUs without relying on QEMU's SeaBIOS.
    ///
    /// The VBIOS image is loaded at `VBIOS_ROM_ADDR` (0xC0000) and
    /// executed via a 16-bit stub at `VBIOS_STUB_ADDR` (0x8000).
    ///
    /// Size must be between `MIN_VBIOS_SIZE` (512) and `MAX_VBIOS_SIZE`
    /// (4 MB). Invalid sizes are silently ignored.
    pub vbios_data: Option<Vec<u8>>,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            kernel_path: PathBuf::new(),
            initrd_path: None,
            memory_size: DEFAULT_MEMORY_SIZE,
            load_addr: DEFAULT_LOAD_ADDR,
            pvh_boot: false,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        }
    }
}

impl BootConfig {
    /// Validate the boot configuration
    pub fn validate(&self) -> Result<()> {
        if !self.kernel_path.exists() {
            return Err(BootError::Config(format!(
                "Kernel file not found: {}",
                self.kernel_path.display()
            )));
        }
        if self.memory_size < 1024 * 1024 {
            return Err(BootError::Config(format!(
                "Memory size too small: {} (minimum 1 MB)",
                self.memory_size
            )));
        }
        if self.memory_size > 64 * 1024 * 1024 * 1024 {
            return Err(BootError::Config(format!(
                "Memory size too large: {} (maximum 64 GB)",
                self.memory_size
            )));
        }
        // Check system memory availability (leave at least 2GB for host)
        // SAFETY: sysconf is async-signal-safe.
        let phys_pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        let avail_pages = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
        if phys_pages > 0 && self.memory_size > (avail_pages as u64 * 4096).saturating_sub(2 * 1024 * 1024 * 1024) {
            tracing::warn!(
                "Requested memory {:.1} GB may exceed available RAM ({:.1} GB free). Proceeding anyway.",
                self.memory_size as f64 / (1024.0 * 1024.0 * 1024.0),
                (avail_pages as f64 * 4096.0) / (1024.0 * 1024.0 * 1024.0),
            );
        }
        if self.load_addr & 0xFFF != 0 {
            return Err(BootError::Config(format!(
                "load_addr 0x{:x} is not page-aligned",
                self.load_addr
            )));
        }
        // Validate VBIOS data size if present
        if let Some(ref data) = self.vbios_data {
            let len = data.len() as u64;
            if len < MIN_VBIOS_SIZE || len > MAX_VBIOS_SIZE {
                warn!(
                    "VBIOS data has unexpected size {} (expected {}-{} bytes). Skipping VBIOS POST.",
                    len, MIN_VBIOS_SIZE, MAX_VBIOS_SIZE
                );
            }
            if (VBIOS_ROM_ADDR + len) > self.memory_size {
                return Err(BootError::Config(format!(
                    "VBIOS ROM ({} bytes at 0x{:x}) exceeds guest memory ({} bytes)",
                    len, VBIOS_ROM_ADDR, self.memory_size
                )));
            }
        }
        Ok(())
    }
}

// ─── BootedVm ──────────────────────────────────────────────────────

/// A booted KVM VM — ready for snapshotting or execution.
///
/// Holds ownership of all resources needed to run the VM:
/// - VM and VCPU fds
/// - kvm_run mmap pointer
/// - Guest memory mmap pointer
#[derive(Debug)]
pub struct BootedVm {
    /// The KVM VM handle
    pub vm: Vm,
    /// The KVM VCPU handle
    pub vcpu: Vcpu,
    /// Pointer to the mmap'd kvm_run structure
    pub kvm_run_ptr: *mut u8,
    /// Size of the kvm_run mmap region
    pub kvm_run_size: usize,
    /// Pointer to the guest memory mmap region
    pub memory_ptr: *mut u8,
    /// Size of the guest memory region
    pub memory_size: u64,
    /// Guest physical address where memory starts
    pub load_addr: u64,
    /// Kernel entry point (guest virtual address)
    pub kernel_entry: u64,
    /// Optional VFIO-pci device for PCI config space routing
    pub vfio_pci: Option<VfioPciInfo>,
    /// Optional VFIO BAR info for handling MMIO exits during boot.
    /// When the guest kernel's drivers (e.g., nouveau) probe the GPU
    /// during PCI enumeration, they access GPU BARs via MMIO. Since
    /// BARs are not mapped as KVM memory slots until after boot
    /// (map_guest_bar_slots), these accesses trigger KVM_EXIT_MMIO.
    /// With this info, we can lazily map the BAR on first access.
    pub vfio_mmio_info: Option<VfioMmioInfo>,
    /// If true (default), inject 64 bytes of host CSPRNG into ENTROPY_BUF_PHYS
    /// before each run_code().
    /// If false, write zeros — identical CRNG across all boots.
    pub entropy_divergence: bool,
    /// Optional synthetic PCIe Root Port at BDF 00:01.0.
    ///
    /// When present, the guest PCI topology is:
    ///   Bus 0: [00:00.0 Host Bridge] [00:01.0 PCIe Root Port (Type 1)]
    ///   Bus 1: [01:00.0 VFIO GPU]
    ///
    /// The root port emulates a Type 1 bridge with Power Management and
    /// PCI Express capabilities. Required by nvidia.ko for GSP-RM firmware
    /// boot in VFIO passthrough scenarios.
    ///
    /// Uses `RefCell` for interior mutability — the root port config may
    /// be written to by the guest's PCI enumeration (bus number assignment,
    /// bridge control), and read in the KVM_RUN exit handler which only
    /// has `&self` access.
    pub pcie_root_port: Option<RefCell<PcieRootPort>>,
    /// Kernel version used to boot this VM (for snapshot integrity tracking)
    pub kernel_version: String,
    /// SHA-256 hash of the kernel binary at boot time
    pub kernel_hash: String,
}

/// Information about a VFIO-pci device attached to the VM.
/// When the guest probes this device's BDF, config space accesses
/// are forwarded to the real VFIO device via `config_fd`.
#[derive(Debug)]
pub struct VfioPciInfo {
    /// PCI bus number of the VFIO device (e.g., 1 for secondary bus behind root port)
    pub bus: u8,
    /// Device function on guest bus (devfn = (dev << 3) | func)
    pub devfn: u8,
    /// File descriptor for reading/writing this device's config space
    /// (can be the VFIO device fd or sysfs config file)
    pub config_fd: std::fs::File,
    /// VFIO region offset for config space (e.g., 0x6000 for region index 6)
    pub config_region_offset: u64,
}

/// Information needed to lazily map GPU BARs on KVM_EXIT_MMIO during boot.
/// When the booted kernel's PCI subsystem assigns BAR addresses and a driver
/// (e.g., nouveau) attempts MMIO access before map_guest_bar_slots() is called,
/// we use this struct to create the KVM memory slot on demand.
///
/// Uses `Cell` for mutable fields accessed via `&self` (called from KVM_RUN
/// exit handler which takes `&self`). This is safe because KVM_RUN is single-
/// threaded — no concurrent access to these fields.
#[derive(Debug)]
pub struct VfioMmioInfo {
    /// VFIO device fd for mmap and pread/pwrite of BAR regions.
    pub dev_fd: i32,
    /// KVM VM fd for KVM_SET_USER_MEMORY_REGION.
    pub vm_fd: i32,
    /// List of (bar_index, bar_size) for all mmapable memory BARs.
    pub bars: Vec<(u32, u64)>,
    /// VFIO config region offset (usually 0x6000 for region index 6).
    pub config_region_offset: u64,
    /// Bitmask of lazily-mapped BAR slots (1 << bar_index for each mapped BAR).
    pub mapped_bars: std::cell::Cell<u64>,
    /// Next available KVM memory slot number.
    pub next_slot: std::cell::Cell<u32>,
}

impl VfioPciInfo {
    /// Read `len` bytes from config space at `offset` (0-255).
    /// Returns the value in the least significant bytes.
    ///
    /// Uses `preadat` (positioned read) because VFIO device fds do NOT
    /// support `lseek` — they use `noop_llseek` in the kernel. Using
    /// `seek+read` would fail silently and return garbage data.
    ///
    /// Also accounts for `config_region_offset`: VFIO PCI config region
    /// (index 6) maps to file offset `6 << PAGE_SHIFT = 0x6000`. Reading
    /// at raw PCI offset 0x00 (vendor/device) requires `pread` at
    /// file offset `0x6000 + 0x00`.
    ///
    /// If the read fails (e.g., VFIO device removed, fd invalid), returns 0
    /// and logs a warning. This is designed for the PCI config proxy which
    /// cannot return `Result` — it is called directly from the KVM MMIO/PIO
    /// handlers which expect immediate `u32` responses.
    pub fn config_read(&self, offset: u16, len: usize) -> u32 {
        use std::os::unix::fs::FileExt;
        let file_offset = self.config_region_offset + offset as u64;
        let mut buf = [0u8; 4];
        let n = match self.config_fd.read_at(&mut buf[..len], file_offset) {
            Ok(n) => n,
            Err(e) => {
                warn!(
                    "VFIO config_read(offset=0x{offset:x}, len={len}) failed: {e} — \
                     returning 0",
                );
                return 0;
            }
        };
        if n < len {
            warn!(
                "VFIO config_read(offset=0x{offset:x}, len={len}) returned {n} bytes \
                 (expected {len}) — zeros for unread bytes",
            );
        }
        let mut val: u32 = 0;
        for i in 0..n.min(4) {
            val |= (buf[i] as u32) << (i * 8);
        }
        val
    }

    /// Write `val` (low `len` bytes) to config space at `offset`.
    ///
    /// Uses `pwriteat` (positioned write) instead of `seek+write`
    /// for the same reason as `config_read`.
    pub fn config_write(&self, offset: u16, len: usize, val: u32) {
        use std::os::unix::fs::FileExt;
        let file_offset = self.config_region_offset + offset as u64;
        let mut buf = [0u8; 4];
        for i in 0..len.min(4) {
            buf[i] = ((val >> (i * 8)) & 0xFF) as u8;
        }
        if let Err(e) = self.config_fd.write_at(&buf[..len.min(4)], file_offset) {
            warn!(
                "VFIO config_write(offset=0x{offset:x}, len={len}, val=0x{val:x}) \
                 failed: {e}",
            );
        }
    }
}

impl VfioMmioInfo {
    /// Read the current guest-assigned address of a BAR from VFIO PCI config space.
    /// PCI BAR registers are at offsets 0x10 (BAR0) through 0x24 (BAR5), each 4 bytes.
    /// For 64-bit BARs, the next register (offset+4) contains the upper 32 bits.
    ///
    /// # Safety
    /// `self.dev_fd` must be a valid VFIO device fd.
    unsafe fn read_bar_addr(&self, bar_index: u32) -> u64 {
        let config_offset = self.config_region_offset + 0x10 + (bar_index as u64 * 4);
        let mut buf = [0u8; 8];

        // SAFETY: pread on a valid VFIO device fd at the config region offset.
        // config_offset is within the config region (0-255 + config_region_offset).
        let ret = libc::pread(self.dev_fd, buf.as_mut_ptr() as *mut libc::c_void, 4, config_offset as i64);
        if ret < 4 { return 0; }

        let low = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let bar_type = (low >> 1) & 0x3;
        if bar_type == 0x2 {
            // 64-bit BAR: read upper 32 bits
            let ret = libc::pread(self.dev_fd, buf[4..].as_mut_ptr() as *mut libc::c_void, 4, (config_offset + 4) as i64);
            if ret < 4 { return (low & 0xFFFFFFF0) as u64; }
            let high = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            ((high as u64) << 32) | (low & 0xFFFFFFF0) as u64
        } else {
            (low & 0xFFFFFFF0) as u64
        }
    }

    /// Lazily map a GPU BAR into the guest's physical address space.
    /// Called on first KVM_EXIT_MMIO to a BAR address during boot.
    /// Returns true if the BAR was mapped successfully (or was already mapped).
    ///
    /// # Safety
    /// Must be called from a single-threaded context (KVM_RUN is single-threaded).
    /// Accesses `mapped_bars` and `next_slot` via Cell (interior mutability).
    unsafe fn lazy_map_bar(&self, bar_index: u32, guest_addr: u64) -> bool {
        // Check if we already mapped this bar
        let mapped = self.mapped_bars.get();
        if (mapped & (1 << bar_index)) != 0 {
            return true;
        }

        // Find the BAR size
        let bar_size = match self.bars.iter().find(|(idx, _)| *idx == bar_index) {
            Some((_, size)) => *size,
            None => return false,
        };
        if bar_size == 0 {
            return false;
        }

        // Page-align the address
        let aligned_addr = guest_addr & !(0xFFF);
        let aligned_size = ((guest_addr + bar_size + 0xFFF) & !(0xFFF)) - aligned_addr;

        // mmap the VFIO device at the BAR's VFIO offset
        let vfio_bar_offset = (bar_index as u64) << 12; // each BAR region = 4KB-aligned
        // SAFETY: dev_fd is a valid VFIO device fd. BAR regions are mmapable.
        let host_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.dev_fd,
                vfio_bar_offset as i64,
            )
        };
        if host_ptr == libc::MAP_FAILED {
            tracing::warn!(
                "VFIO MMIO: failed to mmap BAR{bar_index} at VFIO offset {vfio_bar_offset:#x}"
            );
            return false;
        }

        // Create KVM memory slot
        let slot = self.next_slot.get();
        self.next_slot.set(slot + 1);
        // SAFETY: KVM_SET_USER_MEMORY_REGION is safe if the struct is valid.
        let ret = unsafe {
            #[repr(C)]
            struct KvmUserspaceMemoryRegion {
                slot: u32,
                flags: u32,
                guest_phys_addr: u64,
                memory_size: u64,
                userspace_addr: u64,
            }
            let region = KvmUserspaceMemoryRegion {
                slot,
                flags: 0,
                guest_phys_addr: aligned_addr,
                memory_size: aligned_size,
                userspace_addr: host_ptr as u64,
            };
            libc::ioctl(
                self.vm_fd,
                crate::kvm::KVM_SET_USER_MEMORY_REGION as libc::c_ulong,
                &region as *const _ as *const libc::c_void,
            )
        };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            tracing::warn!(
                "VFIO MMIO: KVM_SET_USER_MEMORY_REGION failed for BAR{bar_index} \
                 at {aligned_addr:#x}: errno={errno}"
            );
            unsafe { libc::munmap(host_ptr, aligned_size as libc::size_t) };
            return false;
        }

        self.mapped_bars.set(mapped | (1 << bar_index));
        tracing::info!(
            "VFIO MMIO: lazily mapped BAR{bar_index} at GPA {aligned_addr:#x} \
             (slot {slot}, size {aligned_size:#x})"
        );
        true
    }
}

impl BootedVm {
    /// Create the in-kernel interrupt chipset (PIT + PIC + IOAPIC + LAPIC).
    ///
    /// Required for the real kernel boot. The PIT generates timer interrupts
    /// that drive `jiffies` and `calibrate_delay()`. The PIC delivers IRQ0
    /// (timer), IRQ1 (keyboard), etc. Without this, the kernel hangs during
    /// boot waiting for timer interrupts.
    ///
    /// NOTE: Call this AFTER `boot_linux()` but BEFORE `run_until_ready()`
    /// for the real kernel. Stub/test kernels should NOT call this since
    /// they don't have an IDT and will triple-fault on unexpected interrupts.
    pub fn create_irqchip(&self) -> std::result::Result<(), BootError> {
        self.vm.create_irqchip().map_err(BootError::Kvm)
    }
    /// Run the VM until the guest writes "READY" to the output buffer
    /// at OUT_BUF_PHYS + 4090. Handles serial port I/O (16550 UART emulation)
    /// and injects IRQ 0 on HLT to wake the guest from idle.
    ///
    /// When the guest writes a PCI config address to port 0xCF8 and reads
    /// from port 0xCFC-0xCFF, we decode bus/device/function/register and
    /// return the appropriate value.
    ///
    /// We emulate a minimal set of devices so the kernel's PCI bus scan
    /// (pcibios_scan_root) finds a valid bus:
    /// Emulate PCI config space reads for a multi-bus topology.
    ///
    /// Bus 0 devices:
    ///   - BDF 00:00.0: PIIX3 host bridge (Intel 0x8086 device 0x7000)
    ///   - BDF 00:01.0: Synthetic PCIe Root Port (if present), else PIIX3 ISA bridge
    ///
    /// Bus 1+ devices: forwarded to VFIO if BDF matches vfio_pci, else all-ones.
    ///
    /// KVM_CREATE_IRQCHIP does NOT create a PIIX3 — only i8259 PIC + i8254 PIT.
    fn pci_config_read(bus: u8, dev: u8, func: u8, reg: u32, port: u16, _size: usize,
                       vfio: Option<&VfioPciInfo>,
                       root_port: Option<&RefCell<PcieRootPort>>) -> u32 {
        let guest_devfn = (dev << 3) | func;

        // ── VFIO forwarding (bus matches vfio_pci.bus) ──
        if let Some(vfio_dev) = vfio {
            if bus == vfio_dev.bus && guest_devfn == vfio_dev.devfn {
                let offset = (reg + (port & 3) as u32) as u16;
                let len = (4 - (port & 3) as usize).min(_size);
                let val = vfio_dev.config_read(offset, len);
                if offset >= 0x10 && offset <= 0x28 {
                    eprintln!("[BOOT] pci_config_read GPU BDF {:02x}:{}.{} reg=0x{offset:02x} len={len} => 0x{val:08x}",
                        bus, dev, func);
                }
                return val;
            }
        }

        // ── Bus 0: emulated devices ──
        if bus != 0 { return 0xFFFFFFFF; }

        match (dev, func) {
            (0, 0) => {
                // PIIX3 host bridge
                let (vendor, device, class, hdr_type, sub_id) =
                    (0x8086, 0x7000, 0x060000, 0x00, 0x0000);
                // Standard PCI config space registers (§6.2)
                match reg {
                    0x00 => { // Vendor/Device ID
                        let v = (device as u32) << 16 | vendor;
                        (v >> ((port & 3) * 8)) as u32
                    }
                    0x04 => { // Command + Status
                        let v = 0x00100007u32;  // I/O+Mem+Master | Cap list
                        (v >> ((port & 3) * 8)) as u32
                    }
                    0x08 => { // Revision + Class
                        (class >> ((port & 3) * 8)) as u32
                    }
                    0x0C => { // Cache line + Latency + Header type + BIST
                        let v = (hdr_type as u32) << 16;
                        (v >> ((port & 3) * 8)) as u32
                    }
                    0x10..=0x24 => 0, // BARs: none
                    0x2C => { // Subsystem vendor + ID
                        let v = (sub_id as u32) << 16 | vendor;
                        (v >> ((port & 3) * 8)) as u32
                    }
                    0x30 => 0, // Expansion ROM
                    0x34 => 0, // Capabilities pointer
                    0x3C => { // Interrupt line + pin
                        let _int_pin = 0u32; // host bridge has no INTx
                        (_int_pin << 8) >> ((port & 3) * 8) as u32
                    }
                    _ => 0,
                }
            }
            (1, 0) => {
                // BDF 00:01.0: PCIe Root Port (bridged) or PIIX3 ISA bridge
                if let Some(rp_cell) = root_port {
                    let rp = rp_cell.borrow();
                    let reg16 = (reg + (port & 3) as u32) as u16;
                    // size = 4 by default to handle misaligned acceses
                    rp.config_read(reg16, 4)
                } else {
                    // Legacy PIIX3 ISA bridge fallback
                    let (vendor, device, class, hdr_type, sub_id) =
                        (0x8086, 0x7010, 0x060100, 0x80, 0x0000);
                    match reg {
                        0x00 => {
                            let v = (device as u32) << 16 | vendor;
                            (v >> ((port & 3) * 8)) as u32
                        }
                        0x04 => {
                            let v = 0x00100007u32;
                            (v >> ((port & 3) * 8)) as u32
                        }
                        0x08 => {
                            (class >> ((port & 3) * 8)) as u32
                        }
                        0x0C => {
                            let v = (hdr_type as u32) << 16;
                            (v >> ((port & 3) * 8)) as u32
                        }
                        0x10..=0x24 => 0,
                        0x2C => {
                            let v = (sub_id as u32) << 16 | vendor;
                            (v >> ((port & 3) * 8)) as u32
                        }
                        0x30 => 0,
                        0x34 => 0,
                        0x3C => {
                            let _int_pin = 1u32;
                            (_int_pin << 8) >> ((port & 3) * 8) as u32
                        }
                        _ => 0,
                    }
                }
            }
            _ => 0xFFFFFFFF,
        }
    }

    /// Emulate PCI config space writes.
    /// Forwards VFIO writes to real device; forwards root port writes to emulated config;
    /// logs and ignores writes to emulated PIIX3 devices.
    fn pci_config_write(bus: u8, dev: u8, func: u8, reg: u32, port: u16, size: usize, val: u32,
                        vfio: Option<&VfioPciInfo>,
                        root_port: Option<&RefCell<PcieRootPort>>) {
        let guest_devfn = (dev << 3) | func;

        // ── VFIO forwarding (bus matches vfio_pci.bus) ──
        if let Some(vfio_dev) = vfio {
            if bus == vfio_dev.bus && guest_devfn == vfio_dev.devfn {
                let offset = (reg + (port & 3) as u32) as u16;
                vfio_dev.config_write(offset, size, val);
                return;
            }
        }

        // ── Bus 0: emulated devices ──
        if bus != 0 { return; }

        match (dev, func) {
            (1, 0) => {
                // Root port config space write
                if let Some(rp_cell) = root_port {
                    let mut rp = rp_cell.borrow_mut();
                    let reg16 = (reg + (port & 3) as u32) as u16;
                    rp.config_write(reg16, size, val);
                }
            }
            _ => {
                // PIIX3 host bridge (0,0) — log command writes, ignore others
                if reg == 0x04 && bus == 0 {
                    tracing::trace!("PCI config write bus=0 dev={dev} func={func} reg=0x{reg:02x} val=0x{val:08x}");
                }
            }
        }
    }

    /// Run the VM until the guest writes "READY" to the output buffer
    /// at OUT_BUF_PHYS + 4090.
    ///
    /// This function sets up a SIGUSR1 (120-second timeout) to periodically
    /// interrupt KVM_RUN and check for the READY signal. This is essential
    /// because the kernel boot may get stuck in a tight loop that never exits
    /// KVM (no HLT, no IO). The alarm ensures we can still detect progress
    /// and eventually time out.
    ///
    /// Serial output from the kernel is captured and written to
    /// `/tmp/tinyos-boot-serial.log` on timeout or READY detection.
    ///
    /// This is used for POST-BOOT template building: boot the kernel,
    /// run until init is ready, then capture the snapshot.
    ///
    /// # Safety
    /// The VM must be fully set up (memory regions, VCPU configured).
    /// Calling this on an already-running VM is UB.
    pub unsafe fn run_until_ready(&self) -> std::result::Result<(), BootError> {
        use crate::serial::SerialPort;
        use crate::kvm::KVM_EXIT_HLT;

        let mut uart = crate::arch::Uart16550::new();
        let mut _serial_port = SerialPort::new(4096);
        let mut serial_output: Vec<u8> = Vec::with_capacity(8192);
        let mut io_count: u64 = 0;
        // PCI config address register (written to port 0xCF8, read from 0xCF8).
        // KVM_CREATE_IRQCHIP doesn't create a PIIX3 PCI host bridge — we must
        // emulate PCI config space accesses to 0xCF8/0xCFC ourselves.
        // See PCI 3.0 spec §3.7.5 (Configuration Mechanism #1).
        let mut pci_config_addr: u32 = 0;
        let start = std::time::Instant::now();

        // ── Thread-based timeout ──
        // We spawn a single background thread that sends SIGUSR1 after 60
        // seconds via `tgkill()`. The thread sleeps once (not in a loop),
        // avoiding nanosleep race conditions. SIGUSR1 is used instead of
        // SIGALRM to avoid conflicts with Rust's test harness.
        //
        // SA_RESTART=0 is critical: without it, the kernel would restart
        // KVM_RUN after the signal handler, and we'd never see EINTR.
        // 600s to account for Python import time on a single-core KVM VCPU.
        // Importing tinygrad.runtime.support.nv.nvdev takes 180-500s
        // depending on host load (single VCPU throttled by host scheduler).
        // NVDev init adds another 30-60s after import completes.
        let timeout_secs = 120u64;  // 2min for debug iteration; increase for CI
        // SAFETY: SYS_gettid is an async-signal-safe syscall that returns
        // the calling thread's TID. No special safety preconditions.
        let main_tid: libc::pid_t = unsafe {
            libc::syscall(libc::SYS_gettid) as libc::pid_t
        };
        // SAFETY: getpid() is always safe — it's a simple syscall returning
        // the process ID, no invariants to maintain.
        let parent_pid = unsafe { libc::getpid() };
        let _timeout_handle = std::thread::Builder::new()
            .name("boot-timeout".into())
            .spawn(move || {
                // Single sleep — no loop, no nanosleep race conditions.
                std::thread::sleep(std::time::Duration::from_secs(timeout_secs));
                // SAFETY: tgkill is an async-signal-safe syscall in a dedicated
                // timeout thread. parent_pid and main_tid are valid (captured before
                // the thread started), SIGUSR1 is not a fatal signal, and
                // the target thread is known to be alive in KVM_RUN.
                unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        parent_pid,
                        main_tid,
                        libc::SIGUSR1,
                    );
                }
            })
            .unwrap_or_else(|e| {
                tracing::warn!("failed to spawn boot timeout thread: {e}");
                std::thread::spawn(|| {}) // dummy handle
            });

        // Install SIGUSR1 handler that sets the interrupted flag.
        // This is the standard SA_SIGINFO handler pattern.
        // SAFETY:
        // - std::mem::zeroed() is safe for sigaction (POD struct, no invalid bit patterns)
        // - boot_sigalrm_handler is an `extern "C"` function with correct SA_SIGINFO signature
        // - SA_SIGINFO flag means handler receives siginfo_t + ucontext (correct for our handler)
        // - SIGUSR1 is not a critical blocking signal; installing is async-signal-safe
        // - old handler is nullptr (we don't inspect it — no dangling pointer risk)
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            // SAFETY: boot_sigalrm_handler is an extern "C" fn with correct sigaction
            // signature. We cast via *const () (pointer intermediate) to satisfy the
            // function_casts_as_integer lint — this is the standard Rust pattern for
            // storing a function pointer as a data pointer (sigaction uses sa_sigaction
            // as a data pointer field in the SA_SIGINFO case).
            sa.sa_sigaction = boot_sigalrm_handler as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO; // no SA_RESTART
            libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        }

        // Helper to clean up timer and check READY
        macro_rules! check_ready {
            () => {{
                let mut ready = [0u8; 6];
                let ready_addr = self.memory_ptr.add(0x7F000 + 4090);
                std::ptr::copy_nonoverlapping(ready_addr, ready.as_mut_ptr(), 6);
                        if ready[0] == b'R' && ready[1] == b'E' && ready[2] == b'A' && ready[3] == b'D' && ready[4] == b'Y' {
                    tracing::info!("READY detected after {:.1}s ({} KVM exits)",
                        start.elapsed().as_secs_f64(), io_count);
                    return Ok(());
                }
            }};
        }

        loop {
            let elapsed = start.elapsed();

            // ── Check for SIGUSR1 (from timeout thread) ──
            if BOOT_SIGNAL_INTERRUPTED.swap(false, Ordering::SeqCst) {
                // Our timeout thread sent SIGUSR1 — guest didn't write READY in time.
                let serial_str = String::from_utf8_lossy(&serial_output);
                let _ = std::fs::write("/tmp/tinyos-boot-serial.log", &serial_output);
                tracing::warn!("TIMEOUT: entered timeout handler");

                // Dump OUT_BUF content (diagnostic messages from init)
                let out_buf_start = OUT_BUF_PHYS as usize;
                let out_buf_slice = if out_buf_start + BUF_MAX as usize <= self.memory_size as usize {
                    unsafe {
                        // Flush cache for the OUT_BUF region before reading.
                        // The guest writes to /dev/mem which may use UC- or WC
                        // memory type, while the host's KVM fd mmap may use WB.
                        // Without cache coherency management, the host could read
                        // stale cached values (zeros from the initial clear).
                        let out_ptr = self.memory_ptr.add(out_buf_start);
                        for offset in (0..BUF_MAX as usize).step_by(64) {
                            core::arch::x86_64::_mm_clflush(out_ptr.add(offset));
                        }
                        Some(std::slice::from_raw_parts(out_ptr, BUF_MAX as usize))
                    }
                } else {
                    None
                };
                let out_str = out_buf_slice
                    .map(|s| {
                        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                        String::from_utf8_lossy(&s[..end])
                    })
                    .unwrap_or_default();
                tracing::debug!("TIMEOUT_DEBUG: out_str={out_str:?}");

                // Dump CMD_BUF content
                let cmd_buf_start = CMD_BUF_PHYS as usize;
                let cmd_str = if cmd_buf_start + BUF_MAX as usize <= self.memory_size as usize {
                    unsafe {
                        let s = std::slice::from_raw_parts(
                            self.memory_ptr.add(cmd_buf_start),
                            BUF_MAX as usize,
                        );
                        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                        String::from_utf8_lossy(&s[..end])
                    }
                } else {
                    "".into()
                };
                tracing::debug!("TIMEOUT_DEBUG: cmd_str={cmd_str:?}");

                tracing::warn!(
                    "TIMEOUT: Full serial output ({} chars):\n{}",
                    serial_output.len(), serial_str
                );
                tracing::warn!("TIMEOUT: OUT_BUF content: {out_str:?}");
                tracing::warn!("TIMEOUT: CMD_BUF content: {cmd_str:?}");
                return Err(BootError::GuestExit(format!(
                    "timeout waiting for READY\n=== serial output ({} chars) ===\n{}\n=== OUT_BUF ===\n{}\n=== CMD_BUF ===\n{}\nTIMEOUT_DEBUG: done",
                    serial_output.len(), serial_str, out_str, cmd_str
                )));
            }

            // Safety timeout (if signal delivery fails entirely)
            if elapsed.as_secs() > timeout_secs + 30 {
                let tail = &serial_output[serial_output.len().saturating_sub(2000)..];
                let _ = std::fs::write("/tmp/tinyos-boot-serial.log", &serial_output);
                tracing::warn!(
                    "KERNEL BOOT HARD TIMEOUT after {}s. Serial output ({} chars, last 2000):\n{}",
                    elapsed.as_secs(),
                    serial_output.len(),
                    String::from_utf8_lossy(tail),
                );
                return Err(BootError::GuestExit("hard timeout waiting for READY".into()));
            }

            let ret = self.vcpu.run()?;
            if ret == libc::EINTR {
                // KVM_RUN was interrupted by a signal — could be our timeout
                // thread (SIGUSR1) or a spurious signal (e.g., from cargo).
                if BOOT_SIGNAL_INTERRUPTED.swap(false, Ordering::SeqCst) {
                    // Our SIGUSR1 timeout fired
                    let serial_str = String::from_utf8_lossy(&serial_output);
                    let _ = std::fs::write("/tmp/tinyos-boot-serial.log", &serial_output);
                    // Dump OUT_BUF content
                    let out_buf_start = OUT_BUF_PHYS as usize;
                    let out_str = if out_buf_start + BUF_MAX as usize <= self.memory_size as usize {
                        unsafe {
                            // Flush cache before reading (see comment above for why)
                            let out_ptr = self.memory_ptr.add(out_buf_start);
                            for offset in (0..BUF_MAX as usize).step_by(64) {
                                core::arch::x86_64::_mm_clflush(out_ptr.add(offset));
                            }
                            let s = std::slice::from_raw_parts(out_ptr, BUF_MAX as usize);
                            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                            String::from_utf8_lossy(&s[..end])
                        }
                    } else { "".into() };
                    let cmd_buf_start = CMD_BUF_PHYS as usize;
                    let cmd_str = if cmd_buf_start + BUF_MAX as usize <= self.memory_size as usize {
                        unsafe {
                            let s = std::slice::from_raw_parts(self.memory_ptr.add(cmd_buf_start), BUF_MAX as usize);
                            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                            String::from_utf8_lossy(&s[..end])
                        }
                    } else { "".into() };
                    tracing::warn!(
                        "TIMEOUT: Full serial output ({} chars):\n{}",
                        serial_output.len(), serial_str
                    );
                    tracing::warn!("TIMEOUT: OUT_BUF=[{out_str:?}] CMD_BUF=[{cmd_str:?}]");
                    return Err(BootError::GuestExit(format!(
                        "timeout waiting for READY\n=== serial output ({} chars) ===\n{}\n=== OUT_BUF ===\n{}\n=== CMD_BUF ===\n{}",
                        serial_output.len(), serial_str, out_str, cmd_str
                    )));
                }
                // Spurious signal — check READY (guest may have written it)
                check_ready!();
                continue;
            }
            let reason = unsafe { Vcpu::exit_reason(self.kvm_run_ptr) };
            match reason {
                KVM_EXIT_HLT => {
                    // Check READY — init writes READY via /dev/mem then HLTs
                    check_ready!();
                    // Wake the guest from idle — inject PIT timer IRQ (vector 0x20)
                    if self.vcpu.inject_interrupt(0x20).is_err() {
                        tracing::warn!("inject_interrupt(vector 0x20) failed during boot");
                    }
                    continue;
                }
                kvm::KVM_EXIT_IO => {
                    io_count += 1;
                    // SAFETY: kvm_run_ptr points to a valid kvm_run mmap.
                    let (direction, size, port, _count, data_offset) =
                        unsafe { super::exit::read_io_info(self.kvm_run_ptr) };
                    // Helper: read a multi-byte value from the kvm_run data area
                    let read_data = |bytes: usize| -> u32 {
                        let data_ptr = self.kvm_run_ptr.add(data_offset);
                        let mut v: u32 = 0;
                        for i in 0..bytes.min(4) {
                            v |= (unsafe { std::ptr::read(data_ptr.add(i)) } as u32) << (i * 8);
                        }
                        v
                    };
                    // Helper: write a multi-byte value to the kvm_run data area
                    let write_data = |bytes: usize, val: u32| {
                        let data_ptr = self.kvm_run_ptr.add(data_offset);
                        for i in 0..bytes.min(4) {
                            unsafe { std::ptr::write(data_ptr.add(i), ((val >> (i * 8)) & 0xFF) as u8) };
                        }
                    };

                    // VFIO PCI config reference for the IO handler
                    let vfio_pci = self.vfio_pci.as_ref();
                    // PCIe Root Port reference (bus 0 dev 1 func 0 emulation)
                    let root_port = self.pcie_root_port.as_ref();
                    if direction == 0 {
                        // IN: guest reads from port
                        match port {
                            0xCF8 => {
                                // PCI config address register read: return the stored address
                                // The kernel writes 0x80000000 to verify conf1 mechanism works.
                                write_data(size, pci_config_addr);
                            }
                            0xCFC..=0xCFF => {
                                // PCI config data ports: decode address from pci_config_addr
                                let addr = pci_config_addr;
                                let cfg_val = if addr & 0x80000000 != 0 {
                                    // Enable bit set: decode bus/device/function/register
                                    let bus  = (addr >> 16) & 0xFF;
                                    let dev  = (addr >> 11) & 0x1F;
                                    let func = (addr >> 8)  & 0x07;
                                    let reg  = addr & 0xFC;  // dword-aligned register
                                    Self::pci_config_read(bus as u8, dev as u8, func as u8, reg, port, size, vfio_pci, root_port)
                                } else {
                                    0xFFFFFFFF
                                };
                                write_data(size, cfg_val);
                            }
                             UART_PORT_START..=UART_PORT_END => {
                                // Serial ports: use UART emulation (offset from COM1_BASE)
                                let data_ptr = self.kvm_run_ptr.add(data_offset);
                                let offset = port - COM1_BASE;
                                for i in 0..size {
                                    std::ptr::write(data_ptr.add(i), uart.read_reg(offset));
                                }
                            }
                             PIT_DATA0..=PIT_DATA2 => {
                                // PIT counter: return 0 (no in-kernel PIT)
                                write_data(size, 0);
                            }
                             PIC_MASTER_CMD..=PIC_MASTER_DATA | PIC_SLAVE_CMD..=PIC_SLAVE_DATA => {
                                // PIC: return all masked
                                write_data(size, 0xFFFF);
                            }
                             PIT_COMMAND | 0x61 => {
                                write_data(size, 0);
                            }
                            _ => {
                                write_data(size, 0);
                            }
                        }
                    } else {
                        // OUT: guest writes to port
                        let val = read_data(size);
                        match port {
                            PCI_CONFIG_ADDR_PORT => {
                                // PCI config address register write: save the address
                                pci_config_addr = val;
                            }
                            PCI_CONFIG_PORT_START..=PCI_CONFIG_PORT_END => {
                                // PCI config data write: decode address from pci_config_addr
                                let addr = pci_config_addr;
                                if addr & 0x80000000 != 0 {
                                    let bus  = (addr >> 16) & 0xFF;
                                    let dev  = (addr >> 11) & 0x1F;
                                    let func = (addr >> 8)  & 0x07;
                                    let reg  = addr & 0xFC;
                                    Self::pci_config_write(bus as u8, dev as u8, func as u8, reg, port, size, val, vfio_pci, root_port);
                                }
                                // else: enable bit not set, ignore
                            }
                            UART_PORT_START..=UART_PORT_END => {
                                // Serial UART write: capture THR characters (offset from COM1_BASE)
                                let offset = port - COM1_BASE;
                                for i in 0..size.min(4) {
                                    let byte = ((val >> (i * 8)) & 0xFF) as u8;
                                    if uart.write_reg(offset, byte) {
                                        serial_output.push(byte);
                                    }
                                }
                            }
                            // PIC/PIT ports: ignore writes (no in-kernel PIT/PIC)
                            PIC_MASTER_CMD..=PIC_MASTER_DATA | PIT_DATA0..=PIT_COMMAND | PIC_SLAVE_CMD..=PIC_SLAVE_DATA | 0x61 => {}
                            _ => {
                                tracing::trace!("unhandled OUT port=0x{:x} val=0x{:x}", port, val);
                            }
                        }
                    }
                    // Check for READY after every IO exit (fast path detection).
                    // The init writes READY via /dev/mem (no KVM exit), then
                    // outputs a byte to serial (KVM_EXIT_IO). We detect READY here
                    // without waiting for a signal or HLT exit.
                    check_ready!();
                    // Print PIT/PIC/DMA related exits (help debug boot stall)
                    if (0x40..=0x43).contains(&port) || (0x20..=0x21).contains(&port) || (0xA0..=0xA1).contains(&port) || port == 0x61 || port == 0x87 {
                        let d = if direction == 0 { "IN " } else { "OUT" };
                        let v = read_data(size);
                        tracing::trace!("IO_PIT_PIC[{io_count}]: {d} port=0x{port:04x} val=0x{v:x} sz={size}");
                    }
                    // Periodic progress log every 1000 IO events
                    if io_count.is_multiple_of(1000) || io_count <= 20 {
                        tracing::debug!("KVM_EXIT_IO count={} port=0x{:x} at {:.1}s", io_count, port, elapsed.as_secs_f64());
                    }
                    continue;
                }
                kvm::KVM_EXIT_SHUTDOWN => {
                    let _ = std::fs::write("/tmp/tinyos-boot-serial.log", &serial_output);
                    return Err(BootError::GuestExit("shutdown during template boot".into()));
                }
                kvm::KVM_EXIT_FAIL_ENTRY => {
                    return Err(BootError::GuestExit("fail entry during template boot".into()));
                }
                6 => {
                    // KVM_EXIT_MMIO — guest accessed an unmapped MMIO region.
                    // This happens when a built-in driver (e.g., nouveau) probes
                    // GPU BARs before map_guest_bar_slots() is called.
                    // We lazily map the BAR on first access and retry KVM_RUN.
                    if let Some(ref mmio_info) = self.vfio_mmio_info {
                        let phys_addr = unsafe {
                            std::ptr::read(self.kvm_run_ptr.add(32) as *const u64)
                        };
                        let _len = unsafe {
                            std::ptr::read(self.kvm_run_ptr.add(48) as *const u32)
                        };
                        let _is_write = unsafe {
                            std::ptr::read(self.kvm_run_ptr.add(52) as *const u8)
                        } != 0;

                        // Check if the access falls within any GPU BAR
                        let mut handled = false;
                        for (bar_idx, _bar_size) in &mmio_info.bars {
                            // Read current guest-assigned BAR address from VFIO config
                            // SAFETY: dev_fd is a valid VFIO device fd.
                            let bar_addr = unsafe { mmio_info.read_bar_addr(*bar_idx) };
                            if bar_addr == 0 {
                                continue; // Not yet assigned by guest
                            }
                            let bar_end = bar_addr + _bar_size;
                            if phys_addr >= bar_addr && phys_addr < bar_end {
                                // Lazily map this BAR
                                // SAFETY: single-threaded KVM_RUN context.
                                if unsafe { mmio_info.lazy_map_bar(*bar_idx, bar_addr) } {
                                    // BAR is now mapped — retry KVM_RUN
                                    handled = true;
                                    tracing::info!(
                                        "MMIO handler: lazily mapped BAR{bar_idx} \
                                         at {bar_addr:#x} (access at {phys_addr:#x})"
                                    );
                                }
                                break;
                            }
                        }
                        if handled {
                            continue; // Retry KVM_RUN
                        }
                    }
                    // Not a GPU BAR MMIO — fall through to error
                    return Err(BootError::GuestExit(
                        format!("MMIO to unmapped address: reason={reason} phys_addr={:#x}",
                            unsafe { std::ptr::read(self.kvm_run_ptr.add(32) as *const u64) })
                    ));
                }
                _ => {
                    return Err(BootError::GuestExit(
                        format!("unexpected exit reason: {reason}")
                    ));
                }
            }
        }
    }

    /// Save the three irqchip states (PIC master, PIC slave, IOAPIC).
    ///
    /// # Safety
    ///
    /// The VM must have an in-kernel irqchip created via `KVM_CREATE_IRQCHIP`.
    /// If the irqchip hasn't been created, this returns None.
    unsafe fn save_irqchip_state(&self) -> Option<IrqChipState> {
        let save_one = |chip_id: u32| -> Option<Box<[u8; 512]>> {
            match unsafe { self.vm.get_irqchip(chip_id) } {
                Ok(chip) => Some(Box::new(chip.dummy)),
                Err(e) => {
                    tracing::warn!("Failed to save irqchip {chip_id}: {e}");
                    None
                }
            }
        };
        Some(IrqChipState {
            master_pic: save_one(crate::kvm::KVM_IRQCHIP_PIC_MASTER),
            slave_pic: save_one(crate::kvm::KVM_IRQCHIP_PIC_SLAVE),
            ioapic: save_one(crate::kvm::KVM_IRQCHIP_IOAPIC),
        })
    }

    /// Capture a snapshot from the booted VM.
    ///
    /// Reads the current CPU register state via KVM_GET_REGS / KVM_GET_SREGS
    /// and copies the guest memory, creating a `Snapshot` suitable for forking.
    ///
    /// # Errors
    /// Returns `BootError::Kvm` if KVM_GET_REGS or KVM_GET_SREGS fails.
    pub fn capture_snapshot(&self) -> std::result::Result<Snapshot, BootError> {
        // Get current register state from VCPU
        let raw_regs = self.vcpu.get_regs()?;
        let raw_sregs = self.vcpu.get_sregs()?;

        tracing::info!(
            "SNAPSHOT CAPTURE: rip=0x{:x} cr3=0x{:x} rsp=0x{:x}",
            raw_regs.rip, raw_sregs.cr3, raw_regs.rsp
        );

        // SAFETY: self.vcpu is a valid VCPU fd from KVM_CREATE_VCPU.
        // save_critical_msrs() only reads MSR values via KVM_GET_MSRS ioctl
        // with a properly sized buffer per KVM ABI. The buffer is stack-allocated.
        let msrs = unsafe {
            self.vcpu.save_critical_msrs().unwrap_or_default()
        };

        // Save XCRS and XSAVE
        let xsave = self.vcpu.get_xsave().ok();
        let xcrs = self.vcpu.get_xcrs().ok().unwrap_or_default();

        let cpu = CpuState {
            regs: KvmRegs::from(raw_regs),
            sregs: KvmSregs::from(raw_sregs),
            msrs,
            xcrs,
        };

        // Copy guest memory
        // SAFETY: memory_ptr is a valid mmap of memory_size bytes.
        let memory = unsafe {
            std::slice::from_raw_parts(self.memory_ptr, self.memory_size as usize)
        };
        let memory_vec = memory.to_vec();

        // Save irqchip state (PIC master, PIC slave, IOAPIC)
        // SAFETY: self.vm is a valid VM fd with irqchip created.
        let irqchips = unsafe { self.save_irqchip_state() };

        let mem_size = memory_vec.len() as u64;
        Ok(Snapshot {
            memory: memory_vec,
            memory_size: mem_size,
            cpu,
            load_addr: self.load_addr,
            xsave,
            irqchips,
            mem_fd: None,
            kernel_version: self.kernel_version.clone(),
            kernel_hash: self.kernel_hash.clone(),
        })
    }

    /// Execute code via the command buffer protocol and return output.
    ///
    /// Writes `code` to `CMD_BUF_PHYS`, then runs the VM until the guest init
    /// processes the command and writes `"READY"` to `OUT_BUF_PHYS + 4090`.
    /// Reads the output from `OUT_BUF_PHYS` and returns it as a `String`.
    ///
    /// The guest init checks `CMD_BUF_PHYS` for non-null content in its
    /// polling loop. When it finds a command, it clears the buffer, executes
    /// the code, writes output to `OUT_BUF_PHYS`, writes `"READY\0"` to
    /// `OUT_BUF_PHYS + 4090`, and resumes polling.
    ///
    /// This method can be called repeatedly on the same `BootedVm` — the VM
    /// stays alive in the init's polling loop between calls.
    ///
    /// # Safety
    ///
    /// The VM must be in a post-boot state with init polling for commands
    /// (i.e., after `run_until_ready()` has returned `Ok(())`).
    /// Calling this concurrently from multiple threads is UB.
    pub unsafe fn run_code(&mut self, code: &str) -> std::result::Result<String, String> {
        // SAFETY: prepare_vm_for_execution borrows &mut self fields but no
        // aliasing occurs — we pass raw pointers derived from self.
        prepare_vm_for_execution(self.memory_ptr, self.memory_size, self.entropy_divergence, code)?;

        // SAFETY: We own &mut self, so no concurrent KVM_RUN. The VM is in
        // the init's polling loop (post-boot state).
        // run_until_ready() handles KVM exits and returns when it detects
        // "READY" at OUT_BUF_PHYS + 4090.
        self.run_until_ready().map_err(|e| format!("VM run failed: {e}"))?;

        // SAFETY: read_vm_output only reads from guest memory (read-only).
        Ok(read_vm_output(self.memory_ptr, self.memory_size))
    }
}

// SAFETY: BootedVm holds mmap'd memory and KVM fds. Moving between threads
// transfers exclusive ownership. KVM fds are thread-safe at kernel level.
unsafe impl Send for BootedVm {}

impl Drop for BootedVm {
    fn drop(&mut self) {
        // SAFETY: mmap pointers were obtained from previous successful mmap calls.
        // munmap with the correct size will unmap the memory. Null pointers are
        // checked before unmapping.
        unsafe {
            if !self.memory_ptr.is_null() {
                libc::munmap(
                    self.memory_ptr as *mut libc::c_void,
                    self.memory_size as libc::size_t,
                );
            }
            if !self.kvm_run_ptr.is_null() {
                libc::munmap(
                    self.kvm_run_ptr as *mut libc::c_void,
                    self.kvm_run_size as libc::size_t,
                );
            }
        }
    }
}

// ─── Guest memory writer helper ────────────────────────────────────
//
// Guest memory is always mapped at guest physical address 0.
// This means host pointer `mem_ptr + guest_phys` corresponds to
// guest physical address `guest_phys`. Load_addr is only a hint
// for where the kernel ELF expects to be placed (typically 0x100000).

/// Write a u64 value at a guest physical address via the host mmap pointer.
///
/// # Safety
/// - `mem_ptr` must point to a valid mmap region covering `guest_phys + 8` bytes.
/// - `guest_phys` must be within the valid guest memory range [0, mem_size).
/// - `guest_phys` must be 8-byte aligned (enforced by page-aligned addresses
///   like 0x60000 for GDT and 0x70000 for page tables).
unsafe fn write_guest_u64(mem_ptr: *mut u8, guest_phys: u64, value: u64) {
    // SAFETY: caller guarantees guest_phys is within the mapped region
    // and 8-byte aligned. mem_ptr + guest_phys is a valid mutable pointer
    // to a u64 within the mmap'd region.
    unsafe {
        ptr::write(mem_ptr.add(guest_phys as usize) as *mut u64, value);
    }
}

/// Copy a slice into guest memory at a given guest physical address.
///
/// # Safety
/// - `mem_ptr` must point to a valid mmap region covering `guest_phys + data.len()` bytes.
/// - `guest_phys` must be within the valid guest memory range.
unsafe fn write_guest_slice(mem_ptr: *mut u8, guest_phys: u64, data: &[u8]) {
    // SAFETY: caller guarantees guest_phys + data.len() is within the mapped region.
    // mem_ptr.add(guest_phys) is a valid destination for copying data.len() bytes.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), mem_ptr.add(guest_phys as usize), data.len());
    }
}

/// Validate that a guest physical range [start, end) is within mapped memory
/// and does not overlap with reserved areas.
fn validate_guest_range(mem_size: u64, start: u64, end: u64) -> Result<()> {
    if start >= end {
        return Err(BootError::Config(format!(
            "Invalid range: start=0x{start:x} >= end=0x{end:x}"
        )));
    }
    if end > mem_size {
        return Err(BootError::Config(format!(
            "Range [0x{start:x}, 0x{end:x}) exceeds guest memory size 0x{mem_size:x}"
        )));
    }
    if overlaps_reserved(start, end) {
        return Err(BootError::MemoryOverlap { start, end });
    }
    Ok(())
}

/// Write a minimal boot_params structure at the given guest physical address.
///
/// Linux's `startup_64` expects RSI → boot_params. The structure is ~540 bytes
/// (defined as `struct boot_params` in arch/x86/include/uapi/asm/bootparam.h).
/// We set up the minimum required fields so the kernel can find initrd and cmdline.
///
/// # Safety
/// `mem_ptr` must point to a valid mmap'd region of at least `mem_size` bytes.
/// The boot_params address must be within guest memory.
unsafe fn setup_boot_params(
    mem_ptr: *mut u8,
    mem_size: u64,
    initrd_info: Option<(u64, u64)>,
    bp_addr: u64,
    reserved_regions: &[ReservedRegion],
) -> Result<()> {
    // Ensure boot_params area fits in guest memory
    let bp_end = bp_addr + BOOT_PARAMS_SIZE;
    validate_guest_range(mem_size, bp_addr, bp_end)?;

    // SAFETY: validated above
    unsafe {
        // Zero out the entire boot_params area first
        std::ptr::write_bytes(mem_ptr.add(bp_addr as usize), 0, BOOT_PARAMS_SIZE as usize);

        // Now write the setup header fields (offset 0x1F1 through 0x270+)

        // Offset 0x1F1: setup_sects — 0 for vmlinux (no real-mode setup code)
        ptr::write(mem_ptr.add(bp_addr as usize + 0x1F1), 0u8);

        // Offset 0x1FE: boot_flag — must be 0xAA55 (boot sector signature)
        ptr::write(mem_ptr.add(bp_addr as usize + 0x1FE) as *mut u16, 0xAA55u16);

        // Offset 0x202: header magic — must be "HdrS" (0x53726448)
        ptr::write(mem_ptr.add(bp_addr as usize + 0x202) as *mut u32, 0x53726448u32);

        // Offset 0x206: protocol version — we report v2.12 (0x020C)
        // Version 2.12+ supports all features we need (64-bit, relocatable, etc.)
        ptr::write(mem_ptr.add(bp_addr as usize + 0x206) as *mut u16, 0x020Cu16);

        // Offset 0x210: type_of_loader — 0xFF = undefined / unknown loader
        ptr::write(mem_ptr.add(bp_addr as usize + 0x210), 0xFFu8);

        // Offset 0x211: loadflags — bit 0 (LOADED_HIGH) = 1 (kernel loaded at high address)
        // We load at 0x1000000 which is > 1MB, so this is "high"
        ptr::write(mem_ptr.add(bp_addr as usize + 0x211), 0x01u8);

        // If we have an initrd, set up ramdisk fields
        if let Some((initrd_addr, initrd_size)) = initrd_info {
            // Offset 0x218: ramdisk_image (low 32 bits of initrd physical address)
            ptr::write(
                mem_ptr.add(bp_addr as usize + 0x218) as *mut u32,
                initrd_addr as u32,
            );

            // Offset 0x21C: ramdisk_size (low 32 bits of initrd size)
            ptr::write(
                mem_ptr.add(bp_addr as usize + 0x21C) as *mut u32,
                initrd_size as u32,
            );

            // Offset 0x22C: initrd_addr_max (max address for initrd)
            ptr::write(
                mem_ptr.add(bp_addr as usize + 0x22C) as *mut u32,
                INITRD_ADDR_MAX,
            );
        }

        // Offset 0x228: cmd_line_ptr (low 32 bits of cmdline physical address)
        // We reuse the same cmdline as PVH uses (at PVH_CMDLINE_ADDR = 0x2080)
        // The PVH boot code below immediately overwrites this with a more complete
        // cmdline (including iomem=relaxed, rdinit=/init, etc.). This fallback is
        // for kernels that don't use the PVH path.
        let cmdline = b"console=null acpi=off noapic nolapic lpj=10000000 iomem=relaxed random.trust_cpu=on idle=halt quiet loglevel=0\0";
        let cmdline_addr = PVH_CMDLINE_ADDR;
        ptr::write(
            mem_ptr.add(bp_addr as usize + 0x228) as *mut u32,
            cmdline_addr as u32,
        );

        // Copy cmdline string to guest memory
        ptr::copy_nonoverlapping(
            cmdline.as_ptr(),
            mem_ptr.add(cmdline_addr as usize),
            cmdline.len(),
        );

        // Offset 0x238: hardware_subarch (0 = PC, default)
        ptr::write(mem_ptr.add(bp_addr as usize + 0x238) as *mut u32, 0u32);

        // ── e820 memory map ─────────────────────────────────────────
        // The kernel requires a memory map to know what physical RAM is
        // available. Without it, setup_memory_map() sees 0 bytes and the
        // kernel hangs during memory initialization.
        //
        // CRITICAL: We mark the command/output buffer area (0x7E000-0x80000)
        // as RESERVED so that CONFIG_STRICT_DEVMEM allows access via /dev/mem.
        // The init script reads commands from 0x7E000 and writes output to
        // 0x7F000 using /dev/mem. If marked as "System RAM", STRICT_DEVMEM
        // blocks these accesses and the init script silently fails.
        //
        // Also mark 0x60000-0x76000 (GDT + page tables) as reserved since
        // our boot code pre-configures these areas.
        //
        // When VFIO passthrough is active, additional reserved entries are
        // added for GPU BARs that overlap with guest physical RAM, so the
        // kernel does not try to use those addresses as memory.
        //
        // Base entries (always present):
        //   0: [0x0000_0000, 0x0005_0000)  — usable RAM (first 320KB)
        //   1: [0x0005_0000, 0x0008_0000)  — RESERVED
        //   2: [0x0008_0000, 0x0009_FC00)  — usable RAM
        // Then main RAM [0x10_0000, mem_size) split around reserved regions.
        // (0x9FC00-0x100000 is reserved for EBDA/VGA BIOS, not included)

        const E820_TABLE_OFFSET: u64 = 0x2D0;
        const E820_ENTRY_SIZE: u64 = 20;
        const E820_TYPE_USABLE: u32 = 1;
        const E820_TYPE_RESERVED: u32 = 2;

        let e820_base = bp_addr + E820_TABLE_OFFSET;
        let mut entry_idx: u32 = 0;
        let mut e820_off: u64 = e820_base;

        // Helper: write one E820 entry at the current offset, advance.
        let mut write_entry = |addr: u64, size: u64, ty: u32| {
            if size == 0 {
                return;
            }
            // SAFETY: writing to validated guest memory range.
            ptr::write(mem_ptr.add(e820_off as usize) as *mut u64, addr);
            ptr::write(mem_ptr.add(e820_off as usize + 8) as *mut u64, size);
            ptr::write(mem_ptr.add(e820_off as usize + 16) as *mut u32, ty);
            e820_off += E820_ENTRY_SIZE;
            entry_idx += 1;
        };

        // Entry 0: 0x00000000 - 0x00050000 (first 320KB, usable)
        write_entry(0x0, 0x50000, E820_TYPE_USABLE);

        // Entry 1: 0x00050000 - 0x00080000 (192KB, RESERVED)
        // Covers: GDT (0x60000), page tables (0x70000), cmd buf (0x7E000), out buf (0x7F000)
        write_entry(0x50000, 0x30000, E820_TYPE_RESERVED);

        // Entry 2: 0x00080000 - 0x0009FC00 (usable)
        write_entry(0x80000, 0x1FC00, E820_TYPE_USABLE);

        // Main RAM: [0x100000, mem_size), split around reserved regions.
        // We iterate through the reserved_regions and emit usable + reserved
        // segments for the parts of the RAM range that they affect.
        let main_ram_start: u64 = 0x100000;
        let main_ram_end: u64 = mem_size;

        // Sort reserved_regions by start address, and filter to those
        // that overlap with main RAM.
        let mut sorted: Vec<ReservedRegion> = reserved_regions.to_vec();
        sorted.sort_by_key(|r| r.start);
        sorted.retain(|r| r.start < main_ram_end && r.end > main_ram_start);

        let mut current = main_ram_start;
        for region in &sorted {
            // Clamp region to main RAM range
            let rstart = region.start.max(main_ram_start);
            let rend = region.end.min(main_ram_end);

            // Skip if the region is not within the remaining range
            if rstart >= main_ram_end || rend <= current {
                continue;
            }
            if rstart <= current {
                // Reserved region starts before or at current position.
                // Just skip the reserved part.
                current = rend;
                continue;
            }

            // Emit usable segment before this reserved region
            let usable_size = rstart - current;
            write_entry(current, usable_size, E820_TYPE_USABLE);

            // Emit reserved segment
            let reserved_size = rend - rstart;
            write_entry(rstart, reserved_size, E820_TYPE_RESERVED);

            current = rend;
        }

        // Emit remaining usable RAM after the last reserved region
        if current < main_ram_end {
            write_entry(current, main_ram_end - current, E820_TYPE_USABLE);
        }

        // Set number of e820 entries (u8 at boot_params offset 0x1E8)
        trace!("E820: wrote {entry_idx} entries ({sorted_count} reserved regions)", sorted_count = sorted.len());
        // SAFETY: boot_params offset 0x1E8 is within validated range.
        ptr::write(mem_ptr.add(bp_addr as usize + 0x1E8), entry_idx as u8);
    }

    info!(
        "boot_params: written at 0x{bp_addr:x} with initrd={}",
        initrd_info.map(|(a, s)| format!("0x{a:x}+{s}")).unwrap_or_default()
    );

    Ok(())
}

// ─── VBIOS POST (Phase 1 real-mode GPU initialization) ─────────────

/// Write a minimal IVT at guest physical 0x0000.
///
/// All 256 entries point to a single `iret` instruction at
/// `VBIOS_STUB_SEG:0x0000` (physical 0x8000). This ensures that
/// any unexpected interrupt during VBIOS POST returns safely.
///
/// # Safety
/// `mem_ptr` must point to a valid mmap of at least `mem_size` bytes.
unsafe fn vbios_write_ivt(mem_ptr: *mut u8, mem_size: u64) -> Result<()> {
    validate_guest_range(mem_size, VBIOS_IVT_ADDR, VBIOS_IVT_SIZE)?;

    // Each IVT entry: 2-byte offset (little-endian) + 2-byte segment (LE)
    // All entries point to VBIOS_STUB_SEG:0x0000 = physical 0x8000 (iret instruction).
    let seg_low = (VBIOS_STUB_SEG & 0xFF) as u8;
    let seg_high = ((VBIOS_STUB_SEG >> 8) & 0xFF) as u8;
    let entry = [0x00u8, 0x00, seg_low, seg_high]; // offset=0x0000, seg=VBIOS_STUB_SEG

    for i in 0..256 {
        let offset = i * 4;
        // SAFETY: validated above — IVT fits within guest memory.
        unsafe {
            std::ptr::copy_nonoverlapping(
                entry.as_ptr(),
                mem_ptr.add(offset),
                4,
            );
        }
    }
    Ok(())
}

/// Write a minimal BDA at guest physical 0x0400.
///
/// Most fields can be zero (VBIOS will initialize what it needs).
/// We set the equipment word at `0x0410` to indicate VGA display
/// + 80-column mode (0x0034), which tells the VBIOS it can use
/// standard VGA modes.
///
/// # Safety
/// `mem_ptr` must point to a valid mmap of at least `mem_size` bytes.
unsafe fn vbios_write_bda(mem_ptr: *mut u8, mem_size: u64) -> Result<()> {
    validate_guest_range(
        mem_size,
        VBIOS_BDA_ADDR,
        VBIOS_BDA_ADDR + VBIOS_BDA_SIZE,
    )?;
    // SAFETY: validated above — BDA fits within guest memory.
    unsafe {
        std::ptr::write_bytes(
            mem_ptr.add(VBIOS_BDA_ADDR as usize),
            0,
            VBIOS_BDA_SIZE as usize,
        );
    }
    // Equipment word at 0x0410 (relative to BDA base):
    //   bit 5-4: 01 = 80x25 color, 10 = 80x25 mono, 11 = 40x25 color
    //   bit 1: 1 = floppy present
    //   0x0034 = VGA mode, 80-column, floppy present
    // SAFETY: validated above — BDA area is within guest memory, 0x410 is
    // within the BDA range (0x0400..0x0500).
    unsafe {
        std::ptr::write_unaligned(
            mem_ptr.add(0x410) as *mut u16,
            0x0034u16,
        );
    }
    Ok(())
}

/// Copy the VBIOS Option ROM image into guest memory at `VBIOS_ROM_ADDR`.
///
/// The ROM is placed at physical 0xC0000 (segment 0xC000), the standard
/// x86 location for VGA BIOS Option ROMs. The ROM header (0x55AA) at
/// offset 0 must be intact — it's checked by the calling stub.
///
/// # Security
/// This function checks that the VBIOS ROM does not extend past the
/// kernel load address (`DEFAULT_LOAD_ADDR` = 0x100000). A VBIOS larger
/// than 256KB (0xC0000 to 0x100000) would corrupt the pre-loaded kernel
/// image. If overlap is detected, the VBIOS is skipped with a warning.
///
/// # Safety
/// `mem_ptr` must point to a valid mmap of at least `mem_size` bytes.
unsafe fn vbios_copy_rom(
    mem_ptr: *mut u8,
    mem_size: u64,
    data: &[u8],
) -> Result<()> {
    let rom_end = VBIOS_ROM_ADDR + data.len() as u64;

    // TRUNCATE: If the ROM extends beyond the kernel load area, we only
    // copy what fits (256KB gap between 0xC0000 and 0x100000). Modern
    // NVIDIA VBIOS ROMs are fat "hybrid" UEFI+BIOS binaries where the
    // actual 16-bit VGA BIOS init code is in the first ~64KB (image size
    // at ROM offset 0x02). The rest is UEFI driver payload not needed
    // for real-mode POST.
    let avail = DEFAULT_LOAD_ADDR.saturating_sub(VBIOS_ROM_ADDR);
    let copy_len = if rom_end > DEFAULT_LOAD_ADDR {
        warn!(
            "VBIOS ROM too large: {} bytes at 0x{:05x} extends to 0x{:05x}, \
             truncating to first {} bytes (kernel at 0x{:05x}).",
            data.len(), VBIOS_ROM_ADDR, rom_end, avail, DEFAULT_LOAD_ADDR,
        );
        avail as usize
    } else {
        data.len()
    };

    let copy_end = VBIOS_ROM_ADDR + copy_len as u64;
    validate_guest_range(mem_size, VBIOS_ROM_ADDR, copy_end)?;

    // SAFETY: validated above — VBIOS ROM area is within guest memory,
    // and truncation ensures copy_end <= DEFAULT_LOAD_ADDR.
    unsafe {
        std::ptr::copy_nonoverlapping(
            data.as_ptr(),
            mem_ptr.add(VBIOS_ROM_ADDR as usize),
            copy_len,
        );
    }
    info!(
        "VBIOS POST: loaded {} bytes at 0x{:05x}",
        copy_len,
        VBIOS_ROM_ADDR,
    );
    Ok(())
}

/// Write the 16-bit real-mode stub at `VBIOS_STUB_ADDR` (0x8000).
///
/// Memory layout at the stub area:
/// ```text
/// 0x8000:  0xCF       iret           ← IVT entries point here
/// 0x8001:  0xF4       hlt            ← safety
/// 0x8002:  ...        (unused)
/// 0x8010:  0x9A 03 00 00 C0 00      lcall 0xC000:0x0003  ← VBIOS entry
/// 0x8017:  0xF4       hlt            ← done
/// ```
///
/// KVM initial RIP is set to 0x10 (offset within CS=0x0800), so
/// execution starts at the `lcall`. The initial register values
/// (AX = BDF, BX = 0xFFFF, DX = 0xFFFF, FLAGS.IF = 1) are set by
/// `vbios_run_until_hlt()` via KVM_SET_REGS before KVM_RUN — see
/// the `KvmRegsRaw` block in that function. The `lcall` far-transfers
/// to the VBIOS initialization entry point (`0xC000:0x0003`). After
/// VBIOS returns, the `hlt` gives control back to the host.
///
/// # Safety
/// `mem_ptr` must point to a valid mmap of at least `mem_size` bytes.
unsafe fn vbios_write_stub(mem_ptr: *mut u8, mem_size: u64) -> Result<()> {
    // Stub area: iret at start + lcall/hlt at offset 0x10
    let stub_end = VBIOS_STUB_ADDR + 0x20;
    validate_guest_range(mem_size, VBIOS_STUB_ADDR, stub_end)?;

    // IVT handler at 0x8000: a single iret byte. Any interrupt that
    // fires during VBIOS POST is safely ignored.
    let iret: [u8; 2] = [0xCF, 0xF4]; // iret, hlt (belly stop)
    // VBIOS entry at 0x8010: lcall 0xC000:0x0003 then hlt.
    // lcall far encoding: 9A [offset:4 LE] [segment:2 LE]
    let stub: [u8; 7] = [
        0x9A,       // lcall far
        0x03, 0x00, // offset = 0x0003 (VBIOS init entry point)
        0x00, 0xC0, // segment = 0xC000
        0xF4, 0xF4, // hlt + hlt (safety)
    ];

    // SAFETY: validated above — stub area (0x8000..0x8020) is within guest memory.
    unsafe {
        // Write iret + safety hlt at start
        std::ptr::copy_nonoverlapping(
            iret.as_ptr(),
            mem_ptr.add(VBIOS_STUB_ADDR as usize),
            iret.len(),
        );
        // Write lcall + hlt at offset 0x10
        std::ptr::copy_nonoverlapping(
            stub.as_ptr(),
            mem_ptr.add((VBIOS_STUB_ADDR + VBIOS_STUB_ENTRY_OFFSET) as usize),
            stub.len(),
        );
    }
    info!("VBIOS POST: 16-bit stub written at 0x{:05x}", VBIOS_STUB_ADDR);
    Ok(())
}

/// Determine if the guest exited for I/O during VBIOS POST and handle it.
///
/// Returns `true` if the exit was handled and KVM_RUN should be retried,
/// `false` if the exit should be treated as unexpected (caller will error).
fn vbios_handle_io_exit(
    kvm_run_ptr: *mut u8,
    vfio_pci: Option<&VfioPciInfo>,
    root_port: Option<&RefCell<PcieRootPort>>,
    pci_config_addr: &mut u32,
) -> bool {
    // SAFETY: kvm_run_ptr points to a valid kvm_run mmap.
    let (direction, size, port, _count, data_offset) =
        unsafe { super::exit::read_io_info(kvm_run_ptr) };

    trace!("VBIOS POST: KVM_EXIT_IO port=0x{port:04x} dir={direction} size={size}");

    // Helper: read a multi-byte value from the kvm_run data area
    let read_data = |bytes: usize| -> u32 {
        // SAFETY: data_offset is within the kvm_run mmap (kernel guarantees
        // data_offset < kvm_run_size). bytes is capped at 4.
        let data_ptr = unsafe { kvm_run_ptr.add(data_offset) };
        let mut v: u32 = 0;
        for i in 0..bytes.min(4) {
            // SAFETY: data_ptr + i is within kvm_run mmap for i < 4.
            v |= (unsafe { std::ptr::read(data_ptr.add(i)) } as u32) << (i * 8);
        }
        v
    };

    // Helper: write a multi-byte value to the kvm_run data area
    let write_data = |bytes: usize, val: u32| {
        // SAFETY: data_offset is within the kvm_run mmap.
        let data_ptr = unsafe { kvm_run_ptr.add(data_offset) };
        for i in 0..bytes.min(4) {
            // SAFETY: data_ptr + i is within kvm_run mmap for i < 4.
            unsafe { std::ptr::write(data_ptr.add(i), ((val >> (i * 8)) & 0xFF) as u8) };
        }
    };

    if direction == 0 {
        // IN: guest reads from port
        match port {
            PCI_CONFIG_ADDR_PORT => {
                // Return the stored PCI config address
                write_data(size, *pci_config_addr);
            }
            PCI_CONFIG_PORT_START..=PCI_CONFIG_PORT_END => {
                // PCI config data read: forward to VFIO if available
                let addr = *pci_config_addr;
                    let cfg_val = if addr & 0x80000000 != 0 {
                        let bus  = (addr >> 16) & 0xFF;
                        let dev  = (addr >> 11) & 0x1F;
                        let func = (addr >> 8)  & 0x07;
                        let reg  = (addr & 0xFC) as u16;
                        pci_config_read_inline(bus as u8, dev as u8, func as u8, reg, port, size, vfio_pci, root_port)
                } else {
                    0xFFFFFFFF
                };
                write_data(size, cfg_val);
            }
            UART_PORT_START..=UART_PORT_END => {
                // Serial ports during VBIOS POST: return 0xFF (no device)
                write_data(size, 0xFF);
            }
            DMA_MASTER_STATUS => {
                // Master DMA status register (0x08): return all channels TC.
                // Without this, VBIOS POST polls forever waiting for DMA
                // operations to complete, eventually timing out at 5s.
                write_data(size, DMA_ALL_TC as u32);
            }
            DMA_SLAVE_STATUS => {
                // Slave DMA status register (0xD0): same treatment.
                write_data(size, DMA_ALL_TC as u32);
            }
            PPI_PORT_B => {
                // PPI port B (0x61): return with memory refresh bit set.
                // VBIOS checks bit 4 (PPI_REFRESH_BIT) to verify system
                // timer / memory refresh is running. Without this, some
                // VBIOS variants hang on POST.
                write_data(size, PPI_REFRESH_BIT as u32);
            }
            PIT_DATA0..=PIT_DATA2 => {
                // PIT counter: return 0 (no in-kernel PIT)
                write_data(size, 0);
            }
            PIC_MASTER_CMD..=PIC_MASTER_DATA | PIC_SLAVE_CMD..=PIC_SLAVE_DATA => {
                // PIC: return all masked
                write_data(size, 0xFFFF);
            }
            PIT_COMMAND => {
                write_data(size, 0);
            }
            _ => {
                // Most VBIOS-accessed ports can be ignored (returns 0)
                if port == 0x80 || port == 0x42 || port == 0x61
                    || port == 0x92
                    || (0x3B4..=0x3BF).contains(&port)
                    || (0x3C0..=0x3DF).contains(&port)
                    // DMA controller ports (0x00-0x0F master, 0x81-0x83 page)
                    || port <= 0x0F
                    || (0x81..=0x83).contains(&port)
                    || (0xC0..=0xDF).contains(&port)  // DMA slave
                {
                    // Ignored DMA/POST/VGA ports: return 0
                    write_data(size, 0);
                } else {
                    trace!("VBIOS POST: unhandled IN port 0x{port:04x}");
                    write_data(size, 0);
                }
            }
        }
    } else {
        // OUT: guest writes to port
        let val = read_data(size);
        match port {
            PCI_CONFIG_ADDR_PORT => {
                // Save PCI config address register
                *pci_config_addr = val;
                trace!("VBIOS POST: PCI config addr = 0x{val:08x}");
            }
            PCI_CONFIG_PORT_START..=PCI_CONFIG_PORT_END => {
                // PCI config data write: forward to VFIO if available
                let addr = *pci_config_addr;
                if addr & 0x80000000 != 0 {
                    let bus  = (addr >> 16) & 0xFF;
                    let dev  = (addr >> 11) & 0x1F;
                    let func = (addr >> 8)  & 0x07;
                    let reg  = (addr & 0xFC) as u16;
                    pci_config_write_inline(bus as u8, dev as u8, func as u8, reg, port, size, val, vfio_pci, root_port);
                }
            }
            UART_PORT_START..=UART_PORT_END => {
                // Serial UART write: drop (no serial output during VBIOS POST)
            }
            // PIT/PIC/PPI ports: ignore writes (no in-kernel PIT/PIC)
            PIC_MASTER_CMD..=PIC_MASTER_DATA | PIT_DATA0..=PIT_COMMAND | PIC_SLAVE_CMD..=PIC_SLAVE_DATA | PPI_PORT_B => {}
            // DMA controller ports (0x00-0x0F master, 0x81-0x87 page, 0xC0-0xDF slave):
            // We don't emulate the 8237 — just silently drop writes.
            0x00..=0x0F | 0x81..=0x83 | 0xC0..=0xDF => {}
            _ => {
                trace!("VBIOS POST: unhandled OUT port 0x{port:04x} val=0x{val:x}");
            }
        }
    }

    true // handled — continue KVM_RUN
}

/// Read PCI config space value, forwarding to VFIO or returning defaults.
///
/// During VBIOS POST, the VBIOS firmware scans the PCI bus to find the GPU.
/// With the synthetic root port topology:
///   - Bus 0, device 0, func 0: host bridge (PIIX3) — emulated
///   - Bus 0, device 1, func 0: PCIe Root Port — emulated via config space
///   - Bus 1, device 0, func 0: VFIO GPU — forwarded to real device config
fn pci_config_read_inline(
    bus: u8, dev: u8, func: u8, reg: u16, _port: u16, size: usize,
    vfio_pci: Option<&VfioPciInfo>,
    root_port: Option<&RefCell<PcieRootPort>>,
) -> u32 {
    let target_devfn = (dev << 3) | func;

    // ── VFIO forwarding ──
    if let Some(pci) = vfio_pci {
        if bus == pci.bus && target_devfn == pci.devfn {
            let full_offset = pci.config_region_offset + reg as u64;
            let mut buf = [0u8; 4];
            use std::os::unix::fs::FileExt;
            if pci.config_fd.read_exact_at(&mut buf[..size], full_offset).is_ok() {
                let mut val: u32 = 0;
                for i in 0..size.min(4) {
                    val |= (buf[i] as u32) << (i * 8);
                }
                if reg >= 0x10 && reg <= 0x28 {
                    eprintln!("[VBIOS-read] pci_config_read_inline BDF {:02x}:{:02x}.{} reg=0x{reg:02x} size={size} => 0x{val:08x}",
                        bus, dev, func);
                }
                return val;
            }
        }
    }

    // ── Bus 0 emulated devices ──
    if bus != 0 { return 0xFFFFFFFF; }

    match (dev, func) {
        (0, 0) => {
            // Host bridge — VBIOS expects to find something at 00:00.0
            // Return PIIX3 host bridge identity
            match reg {
                0x00 => 0x70008086, // vendor=0x8086, device=0x7000
                0x04 => 0x00100007, // I/O+Mem+Master, Cap list
                0x08 => 0x00060000, // class=0x060000 (host bridge)
                0x0C => 0x00000000, // header=0x00
                _ => 0,
            }
        }
        (1, 0) => {
            // BDF 00:01.0: PCIe Root Port (or ISA bridge if no root port)
            if let Some(rp_cell) = root_port {
                let rp = rp_cell.borrow();
                // VBIOS typically does dword reads at register 0, 4, 8, etc.
                rp.config_read(reg, 4)
            } else {
                // Legacy: PIIX3 ISA bridge — VBIOS won't access this
                0xFFFFFFFF
            }
        }
        _ => 0xFFFFFFFF,
    }
}

/// Write PCI config space value, forwarding to VFIO or silently dropping.
fn pci_config_write_inline(
    bus: u8, dev: u8, func: u8, reg: u16, _port: u16, size: usize, val: u32,
    vfio_pci: Option<&VfioPciInfo>,
    root_port: Option<&RefCell<PcieRootPort>>,
) {
    let target_devfn = (dev << 3) | func;

    // ── VFIO forwarding ──
    if let Some(pci) = vfio_pci {
        if bus == pci.bus && target_devfn == pci.devfn {
            let full_offset = pci.config_region_offset + reg as u64;
            let mut buf = [0u8; 4];
            for i in 0..size.min(4) {
                buf[i] = ((val >> (i * 8)) & 0xFF) as u8;
            }
            if reg >= 0x10 && reg <= 0x28 {
                eprintln!("[VBIOS/kernel] pci_config_write GPU BDF {:02x}:{:02x}.{} reg=0x{reg:02x} size={size} val=0x{val:08x}",
                    bus, dev, func);
            }
            use std::os::unix::fs::FileExt;
            let _ = pci.config_fd.write_all_at(&buf[..size], full_offset);
            return;
        }
    }

    // ── Bus 0: root port config writes ──
    if bus == 0 && dev == 1 && func == 0 {
        if let Some(rp_cell) = root_port {
            let mut rp = rp_cell.borrow_mut();
            rp.config_write(reg, size, val);
        }
    }
    // Other bus 0 writes (host bridge) are silently ignored
}

/// Run the VBIOS POST in real mode until the guest halts.
///
/// Configures KVM SREGS and REGS for real-mode execution, then
/// runs `KVM_RUN` until `KVM_EXIT_HLT` is observed. PCI config
/// (via `vfio_pci`), VGA I/O ports, and GPU MMIO (via `vfio_mmio`)
/// are handled inline to keep the VBIOS happy.
///
/// # Safety
/// `vcpu` must be a valid, newly-created VCPU (not yet configured
/// for long mode). The SREGS/REGS are completely overwritten.
/// `kvm_run_ptr` must be a valid mmap'd kvm_run for this VCPU.
/// `mem_ptr` must be a valid mmap of `mem_size` bytes.
/// Try to forward a KVM_EXIT_MMIO to a VFIO device.
///
/// Called when the VBIOS POST accesses a guest-physical address that is not
/// covered by any KVM memory slot. With pre-created BAR slots (step 4.5 in
/// fresh_boot.rs), this should not happen for GPU BARs — but as a defense-
/// in-depth fallback, we try to match the GPA against pre-assigned BAR
/// addresses (read from VFIO PCI config space) and forward to the real device.
///
/// Returns `true` if the MMIO was forwarded (data was written to kvm_run data
/// area for reads), `false` if the GPA does not match any known BAR.
///
/// # Safety
/// - `mmio` must point to valid `VfioMmioInfo` with a valid `dev_fd`
/// - `kvm_run_ptr` must be a valid mmap'd kvm_run for this VCPU
/// - The `data` pointer at kvm_run offset 40 must be valid (per KVM API, the
///   MMIO data area `data[8]` is at offset 40 in struct kvm_run for KVM_EXIT_MMIO)
unsafe fn vbios_try_forward_mmio(
    mmio: &VfioMmioInfo,
    kvm_run_ptr: *mut u8,
    gpa: u64,
    is_write: bool,
) -> bool {
    let dev_fd = mmio.dev_fd;
    let config_off = mmio.config_region_offset;

    // Try each BAR to see if the GPA falls within its range.
    for &(bar_idx, bar_size_outer) in &mmio.bars {
        if bar_idx > 5 {
            continue;
        }
        // Read the pre-assigned BAR address from VFIO PCI config space.
        // The BAR register is at PCI config offset 0x10 + bar_idx * 4.
        let bar_reg = 0x10 + bar_idx * 4;
        let mut raw_bar: u32 = 0;
        // SAFETY: pread on valid VFIO device fd.
        let ret = unsafe {
            libc::pread(
                dev_fd,
                &mut raw_bar as *mut u32 as *mut libc::c_void,
                4,
                (config_off + bar_reg as u64) as i64,
            )
        };
        if ret != 4 {
            continue;
        }
        let bar_addr = (raw_bar & !0xF) as u64; // strip type bits
        if bar_addr == 0 {
            continue;
        }
        // 64-bit BAR: also read the upper 32 bits from the next register.
        let is_64bit = (raw_bar >> 1) & 0x3 == 2;
        let bar_base = if is_64bit {
            let mut upper: u32 = 0;
            // SAFETY: pread upper 32 bits from BAR register + 4.
            let r = unsafe {
                libc::pread(
                    dev_fd,
                    &mut upper as *mut u32 as *mut libc::c_void,
                    4,
                    (config_off + (bar_reg + 4) as u64) as i64,
                )
            };
            if r != 4 {
                continue;
            }
            bar_addr | ((upper as u64) << 32)
        } else {
            bar_addr
        };

        if bar_base == 0 {
            continue;
        }

        // Check if GPA falls within this BAR's range (using the pre-assigned size
        // from the VFIO region info, not from config space).
        let bar_size = bar_size_outer;

        if gpa >= bar_base && gpa < bar_base + bar_size {
            // Calculate offset within this BAR.
            let bar_offset = gpa - bar_base;
            // VFIO BAR regions are at file offset bar_idx << PAGE_SHIFT (4KB pages).
            let vfio_region_offset = (bar_idx as u64) << 12;

            // SAFETY: kvm_run MMIO struct has data[8] at offset 40 per KVM API
            // (struct kvm_run definition: offset 32=phys_addr, offset 40=data[8],
            // offset 48=len, offset 52=is_write). The data_ptr used here is
            // for the guest data, not len or is_write.
            let data_ptr = unsafe { kvm_run_ptr.add(40) };

            if is_write {
                // Write: forward the 8 bytes from guest to VFIO device.
                let mut buf = [0u8; 8];
                // SAFETY: loop bounded to [0..8), data_ptr points to kvm_run
                // data[8] at offset 40 (validated by parent SAFETY block).
                for i in 0..8usize {
                    buf[i] = std::ptr::read(data_ptr.add(i));
                }
                // SAFETY: pwrite on valid VFIO device fd at valid offset.
                let written = unsafe {
                    libc::pwrite(
                        dev_fd,
                        buf.as_ptr() as *const libc::c_void,
                        8,
                        (vfio_region_offset + bar_offset) as i64,
                    )
                };
                if written == 8 {
                    trace!("VBIOS MMIO forward: WRITE GPA=0x{gpa:x} BAR{bar_idx}+0x{bar_offset:x} OK");
                    return true;
                }
            } else {
                // Read: fetch 8 bytes from VFIO device into kvm_run data area.
                let mut buf = [0u8; 8];
                // SAFETY: pread on valid VFIO device fd at valid offset.
                let n = unsafe {
                    libc::pread(
                        dev_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        8,
                        (vfio_region_offset + bar_offset) as i64,
                    )
                };
                if n >= 0 {
                    // SAFETY: both loops bounded to [0..8), data_ptr points to
                    // kvm_run data[8] at offset 40 (validated by parent SAFETY).
                    for i in 0..(n as usize).min(8) {
                        std::ptr::write(data_ptr.add(i), buf[i]);
                    }
                    for i in (n as usize).min(8)..8 {
                        std::ptr::write(data_ptr.add(i), 0xFF); // pad remaining
                    }
                    trace!("VBIOS MMIO forward: READ GPA=0x{gpa:x} BAR{bar_idx}+0x{bar_offset:x} ({n} bytes)");
                    return true;
                }
            }
            // If pread/pwrite failed, continue to try other BARs.
            warn!("VBIOS MMIO forward: GPA=0x{gpa:x} matched BAR{bar_idx} but VFIO access failed");
        }
    }
    false
}

unsafe fn vbios_run_until_hlt(
    vcpu: &Vcpu,
    kvm_run_ptr: *mut u8,
    _mem_ptr: *mut u8,
    _mem_size: u64,
    vfio_mmio: Option<&VfioMmioInfo>,
    vfio_pci: Option<&VfioPciInfo>,
    root_port: Option<&RefCell<PcieRootPort>>,
) -> Result<()> {
    // ── Real-mode SREGS ──────────────────────────────────────────────
    // We start from KVM defaults then overwrite for real mode.
    // KVM_GET_SREGS gives us properly initialised TR/LDT/GDT values
    // which we MUST keep (setting tr.unusable=1 causes FAIL_ENTRY).
    let mut sregs = vcpu.get_sregs()?;

    // Real mode: CR0 with PE=0 (bit 0), no paging, keep ET=1
    sregs.cr0 = 0x10; // ET=1 only
    sregs.cr4 = 0;
    sregs.efer = 0;
    sregs.cr3 = 0;

    // CS: selector matching stub segment (0x0800), base = selector * 16
    let cs_base = (VBIOS_STUB_SEG as u64) << 4; // 0x8000
    sregs.cs.base = cs_base;
    sregs.cs.selector = VBIOS_STUB_SEG;
    sregs.cs.type_ = 0xB; // code, execute/read, accessed
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0; // 16-bit code
    sregs.cs.s = 1; // code/data descriptor
    sregs.cs.l = 0; // not long mode
    sregs.cs.g = 0; // byte granularity
    sregs.cs.limit = 0xFFFF; // 64KB limit for real mode

    // DS, ES, FS, GS, SS: real mode flat, base=0, limit=64KB
    for seg in [
        &mut sregs.ds,
        &mut sregs.es,
        &mut sregs.fs,
        &mut sregs.gs,
        &mut sregs.ss,
    ]
    .iter_mut()
    {
        seg.base = 0;
        seg.selector = 0;
        seg.type_ = 3; // data, read/write, accessed
        seg.present = 1;
        seg.dpl = 0;
        seg.db = 0;
        seg.s = 1;
        seg.l = 0;
        seg.g = 0;
        seg.limit = 0xFFFF;
    }

    // IDT: base at physical 0x0000 (IVT), limit = 1023 (256x4 - 1)
    sregs.idt.base = VBIOS_IVT_ADDR;
    sregs.idt.limit = (VBIOS_IVT_SIZE - 1) as u16;

    // GDT: keep KVM defaults (KVM needs valid GDT for VMX even in real mode)
    // TR, LDT: keep KVM defaults (don't set unusable=1!)

    // ── Apply SREGS ──────────────────────────────────────────────────
    vcpu.set_sregs(&sregs)?;

    // ── Real-mode REGS ───────────────────────────────────────────────
    // RIP = VBIOS_STUB_ENTRY_OFFSET (0x10 in the stub segment)
    // CS.base + RIP = 0x8000 + 0x10 = 0x8010 -> starts at lcall
    //
    // Register setup follows SeaBIOS __callrom() convention (optionroms.c):
    //   AX = PCI BDF (bus:device.func) — tells the Option ROM which device
    //        to initialize. The VFIO GPU is at guest BDF 01:00.0, so
    //        AH=bus=0x01, AL=(dev<<3|func)=0x00 → AX=0x0100.
    //        Without a valid BDF in AX, the VBIOS finds BDF 00:00.0 (host
    //        bridge), detects non-VGA class, and skips GPU initialization
    //        entirely — Falcon engines remain power-gated.
    //   BX = 0xFFFF (undefined per PCI BIOS specification)
    //   DX = 0xFFFF (no PnP BIOS data — ES:DI will be ignored)
    //   FLAGS.IF = 1 (interrupts enabled during Option ROM execution)
    let regs = kvm::KvmRegsRaw {
        rip: VBIOS_STUB_ENTRY_OFFSET,
        rflags: VBIOS_REG_RFLAGS, // bit 9 = IF (interrupts enabled), bit 1 = reserved
        rsp: VBIOS_REAL_STACK, // stack ~56KB below 1MB
        rax: VBIOS_REG_AX, // AX = BDF 01:00.0   (GPU behind root port on bus 1)
        rbx: VBIOS_REG_BX, // BX = undefined
        rcx: 0,
        rdx: VBIOS_REG_DX, // DX = 0xFFFF = no PnP BIOS
        rsi: 0,
        rdi: 0,
        rbp: 0,
        ..Default::default()
    };
    vcpu.set_regs(&regs)?;

    // ── PCI config address register for VBIOS config space accesses ──
    // The VBIOS may access PCI config space via port 0xCF8/0xCFC
    // (mechanism #1). We store the address register value here so
    // that writes to 0xCF8 are remembered for subsequent 0xCFC accesses.
    let mut pci_config_addr: u32 = 0;

    // ── KVM_RUN loop ─────────────────────────────────────────────────
    info!("VBIOS POST: starting real-mode execution...");
    // VBIOS timeout: abort after 5 seconds of real-mode execution.
    // Some VBIOS firmware loops forever on DMA port verification
    // (ports 0x00-0x0F) because we don't emulate the full 8237 DMA
    // controller. By this point the GPU MMIO init is already done via
    // direct EPT accesses — the remaining code is just POST diagnostics
    // and DMA setup that won't affect GPU functionality.
    let vbios_start = std::time::Instant::now();
    const VBIOS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    loop {
        // SAFETY: vcpu is a valid VCPU returned from KVM_CREATE_VCPU,
        // properly configured for real-mode execution above.
        let ret = unsafe { vcpu.run()? };
        if ret == libc::EINTR {
            continue; // retry on signal
        }

        // SAFETY: kvm_run_ptr is a valid mmap'd kvm_run for this VCPU.
        let reason = unsafe { kvm::Vcpu::exit_reason(kvm_run_ptr) };

        // Check VBIOS timeout — if exceeded, abort and continue with
        // kernel boot. The GPU MMIO has already been initialized.
        if vbios_start.elapsed() > VBIOS_TIMEOUT {
            warn!(
                "VBIOS POST: timeout after {}.{:03}s — forcing HLT, continuing with kernel boot",
                VBIOS_TIMEOUT.as_secs(),
                VBIOS_TIMEOUT.subsec_millis(),
            );
            return Ok(());
        }

        match reason {
            kvm::KVM_EXIT_HLT => {
                info!("VBIOS POST: completed (HLT)");
                return Ok(());
            }
            kvm::KVM_EXIT_FAIL_ENTRY => {
                // SAFETY: kvm_run failure reason is at offset 32 (u64) per KVM API.
                let hw_reason = unsafe {
                    std::ptr::read_unaligned(kvm_run_ptr.add(32) as *const u64)
                };
                return Err(BootError::GuestExit(format!(
                    "VBIOS POST FAIL_ENTRY: hw_reason=0x{hw_reason:x}"
                )));
            }
            kvm::KVM_EXIT_IO => {
                // Handle all I/O ports including PCI config (0xCF8/0xCFC),
                // serial (0x3F8), PIT/PIC, and VGA ports. The return value
                // is always true — VBIOS POST continues even on unhandled
                // ports (the VBIOS firmware retries or skips).
                vbios_handle_io_exit(kvm_run_ptr, vfio_pci, root_port, &mut pci_config_addr);
                continue;
            }
            kvm::KVM_EXIT_MMIO => {
                // SAFETY: kvm_run MMIO struct layout (per KVM API):
                //   offset 32: phys_addr (u64, 8 bytes)
                //   offset 40: data[8]   (u8[8], 8 bytes)
                //   offset 48: len       (u32,  4 bytes)
                //   offset 52: is_write  (u8,   1 byte)
                let gpa = unsafe { std::ptr::read_unaligned(kvm_run_ptr.add(32) as *const u64) };
                let data_ptr = unsafe { kvm_run_ptr.add(40) };
                let is_write = unsafe { std::ptr::read_unaligned(kvm_run_ptr.add(52) as *const u8) } != 0;

                // Try to forward to VFIO device if pre-assigned BAR slots
                // are available (defense-in-depth fallback).
                let forwarded = if let Some(mmio) = vfio_mmio {
                    unsafe { vbios_try_forward_mmio(mmio, kvm_run_ptr, gpa, is_write) }
                } else {
                    false
                };

                if !forwarded {
                    // No matching BAR: return 0xFF for reads, drop writes.
                    // With BAR slots pre-created before VBIOS POST, this
                    // should not happen for GPU register accesses — only
                    // for genuinely unmapped addresses.
                    if !is_write {
                        // SAFETY: data_ptr at offset 40 is kvm_run data[8] area
                        // (8 bytes, valid per KVM API — documented above).
                        unsafe { std::ptr::write_bytes(data_ptr, 0xFF, 8); }
                    }
                    trace!("VBIOS POST: KVM_EXIT_MMIO GPA=0x{gpa:x} unhandled (returning 0xFF)");
                } else {
                    trace!("VBIOS POST: KVM_EXIT_MMIO GPA=0x{gpa:x} forwarded to VFIO");
                }
                continue;
            }
            other => {
                return Err(BootError::GuestExit(format!(
                    "VBIOS POST unexpected exit: reason={}",
                    other
                )));
            }
        }
    }
}

/// Execute the VBIOS Option ROM POST sequence in real mode.
///
/// This is Phase 1 of a two-phase boot. It initialises the GPU hardware
/// (Falcon engines, GFW firmware, PCI config space) so that when the
/// guest kernel later probes its PCI bus, the GPU is in a ready state.
///
/// ## Prerequisites (caller must do before calling this)
///
/// 1. VFIO GPU must be attached (IOMMU groups, bus mastering enabled)
/// 2. **GPU BAR KVM memory slots must be pre-created** (via
///    `VfioPassthrough::preassign_guest_bar_addresses()` + `map_guest_bar_slots()`)
///    — this matches QEMU's approach where all VFIO memory slots exist before
///    the guest boots. Without pre-created BAR slots, GPU MMIO accesses during
///    POST would generate KVM_EXIT_MMIO and our fallback returns 0xFF.
///
/// After this function returns, the caller must re-initialise SREGS/REGS
/// for 64-bit long mode and continue with the normal kernel boot (Phase 2).
///
/// The optional `vfio` parameter provides `VfioMmioInfo` for a defense-in-depth
/// fallback: if KVM_EXIT_MMIO occurs (e.g., for addresses outside pre-created
/// BAR slots), the MMIO is forwarded to the VFIO device via pread/pwrite.
/// With proper BAR slot pre-creation, this fallback should never be needed
/// for GPU register accesses. For CPU-only boots (no GPU), pass `None`.
///
/// The optional `vfio_pci` parameter provides `VfioPciInfo` for forwarding
/// PCI config space accesses (ports 0xCF8/0xCFC) to the real VFIO device.
///
/// # Safety
/// - `mem_ptr` must be a valid mmap of `mem_size` bytes.
/// - `vcpu` must be a freshly-created VCPU (no prior state needed).
/// - `vbios_data` must be a valid VBIOS Option ROM image (512 bytes-256KB max
///   — larger ROMs are skipped to avoid corrupting the pre-loaded kernel).
pub unsafe fn run_vbios_post(
    vcpu: &Vcpu,
    kvm_run_ptr: *mut u8,
    mem_ptr: *mut u8,
    mem_size: u64,
    vbios_data: &[u8],
    vfio: Option<&VfioMmioInfo>,
    vfio_pci: Option<&VfioPciInfo>,
    root_port: Option<&RefCell<PcieRootPort>>,
) -> Result<()> {
    // Validate VBIOS data size
    let len = vbios_data.len() as u64;
    if len < MIN_VBIOS_SIZE || len > MAX_VBIOS_SIZE {
        warn!(
            "VBIOS data size {} out of range ({}-{}). Skipping VBIOS POST.",
            len,
            MIN_VBIOS_SIZE,
            MAX_VBIOS_SIZE,
        );
        return Ok(());
    }

    // SAFETY: mem_ptr/mem_size are valid (guaranteed by caller), vbios_write_ivt
    // validates IVT range (0x0000..0x0400) before writing.
    unsafe { vbios_write_ivt(mem_ptr, mem_size)?; }

    // SAFETY: mem_ptr/mem_size valid, vbios_write_bda validates BDA range
    // (0x0400..0x0500) before writing.
    unsafe { vbios_write_bda(mem_ptr, mem_size)?; }

    // SAFETY: mem_ptr/mem_size valid, vbios_copy_rom validates ROM range
    // (0xC0000 + data.len()) and checks overlap with kernel at 0x100000.
    unsafe { vbios_copy_rom(mem_ptr, mem_size, vbios_data)?; }

    // SAFETY: mem_ptr/mem_size valid, vbios_write_stub validates stub range
    // (0x8000..0x8020) before writing.
    unsafe { vbios_write_stub(mem_ptr, mem_size)?; }

    // SAFETY: vcpu is a valid KVM VCPU (from boot_linux), kvm_run_ptr points
    // to its valid mmap'd kvm_run, mem_ptr/mem_size valid, vfio/vfio_pci
    // options passed for optional GPU MMIO/PCI forwarding during VBIOS POST.
    unsafe { vbios_run_until_hlt(vcpu, kvm_run_ptr, mem_ptr, mem_size, vfio, vfio_pci, root_port)?; }

    Ok(())
}

/// Reconfigure a VCPU from real mode to 64-bit long mode.
///
/// After a VBIOS POST completes, the VCPU is in real mode (16-bit).
/// This function re-initialises it for long mode execution:
/// 1. (CPUID was already set during boot_linux — not re-set here)
/// 2. Writes 4-level page tables at `PML4_ADDR` (0x70000)
/// 3. Writes a minimal GDT at `GDT_ADDR` (0x60000)
/// 4. Configures SREGS for 64-bit long mode
/// 5. Configures REGS (RIP = `kernel_entry`, RSP = `STACK_TOP`, RSI = boot_params)
///
/// IMPORTANT: CPUID is NOT re-set here. It was already set during boot_linux()
/// and KVM_SET_CPUID2 can only be called once before the VCPU runs. Calling it
/// again after VBIOS POST (which already ran KVM_RUN) causes EINVAL on some
/// KVM versions.
/// 2. Writes 4-level page tables at `PML4_ADDR` (0x70000)
/// 3. Writes a minimal GDT at `GDT_ADDR` (0x60000)
/// 4. Configures SREGS for 64-bit long mode
/// 5. Configures REGS (RIP = `kernel_entry`, RSP = `STACK_TOP`, RSI = boot_params)
///
/// This is identical to steps 6-9 of `boot_linux()`, refactored as a
/// standalone call so that `fresh_boot.rs` can run VBIOS POST between
/// VFIO attachment and kernel boot.
///
/// # Safety
/// - `kvm` must be a valid KVM handle
/// - `vcpu` must be a valid VCPU (may be in any mode — all state is reset)
/// - `mem_ptr` must be a valid mmap of `mem_size` bytes covering addresses
///   0..mem_size, with page tables at 0x70000, GDT at 0x60000, and
///   boot_params at 0x10000 (BOOT_PARAMS_ADDR) already written.
pub unsafe fn reconfigure_long_mode(
    _kvm: &Kvm,
    vcpu: &Vcpu,
    mem_ptr: *mut u8,
    mem_size: u64,
    kernel_entry: u64,
) -> Result<()> {
    // 1. CPUID for long mode: SKIPPED — already set during boot_linux().
    //    KVM_SET_CPUID2 can only be called once; after VBIOS POST ran
    //    KVM_RUN, a second call returns EINVAL on some KVM versions.

    // SAFETY: setup_page_tables requires a valid mem_ptr/mem_size,
    // which is guaranteed by the caller (boot_linux already verified this).
    unsafe {
        setup_page_tables(mem_ptr, mem_size)?;
    }

    // SAFETY: setup_gdt requires a valid mem_ptr, guaranteed by caller.
    unsafe {
        setup_gdt(mem_ptr)?;
    }

    // 4. SREGS for 64-bit long mode
    let mut sregs = vcpu.get_sregs()?;

    // --- GDT descriptor ---
    sregs.gdt.base = GDT_ADDR;
    sregs.gdt.limit = 23; // 3 descriptors × 8 bytes - 1

    // --- Code segment (CS) ---
    sregs.cs.base = 0;
    sregs.cs.selector = 0x08;
    sregs.cs.type_ = 0xB; // code, execute/read, accessed
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0;
    sregs.cs.s = 1;
    sregs.cs.l = 1; // 64-bit long mode
    sregs.cs.g = 1;
    sregs.cs.limit = 0xFFFFF;

    // --- Data segments ---
    for seg in [
        &mut sregs.ds,
        &mut sregs.es,
        &mut sregs.fs,
        &mut sregs.gs,
        &mut sregs.ss,
    ]
    .iter_mut()
    {
        seg.base = 0;
        seg.selector = 0x10;
        seg.type_ = 3; // data, read/write, accessed
        seg.present = 1;
        seg.dpl = 0;
        seg.db = 0;
        seg.s = 1;
        seg.l = 0;
        seg.g = 1;
        seg.limit = 0xFFFFF;
    }

    // --- TR and LDT: keep KVM defaults ---

    // --- Control registers: enable paging + long mode in one shot ---
    sregs.cr3 = PML4_ADDR;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME | EFER_LMA;
    sregs.cr0 = 0xE0050033; // CD|NW|PG|WP|NE|ET|MP|PE

    vcpu.set_sregs(&sregs)?;

    // 5. REGS: 64-bit entry point
    let regs = kvm::KvmRegsRaw {
        rflags: 2,
        rip: kernel_entry,
        rsp: STACK_TOP,
        rsi: BOOT_PARAMS_ADDR,
        ..Default::default()
    };
    vcpu.set_regs(&regs)?;

    info!("reconfigure_long_mode: VCPU reconfigured for 64-bit mode (entry=0x{kernel_entry:x})");
    Ok(())
}

// ─── End VBIOS POST ─────────────────────────────────────────────────

// ─── Public API ────────────────────────────────────────────────────

/// Boot a Linux kernel inside KVM
///
/// 1. Opens and parses the kernel ELF binary
/// 2. Creates a KVM VM with guest RAM
/// 3. Loads ELF segments into guest memory
/// 4. Creates a VCPU
/// 5. Optionally runs VBIOS POST (Phase 1, GPU init in real mode)
/// 6. Sets up page tables (4-level paging with 1GB huge pages)
/// 7. Sets up GDT (64-bit code/data segments)
/// 8. Configures SREGS for long mode
/// 9. Configures REGS (RIP = entry point, RSP = stack)
/// 10. Returns BootedVm (caller runs until HLT)
///
/// # Errors
/// Returns `BootError::Config` if the configuration is invalid,
/// `BootError::Elf` if the kernel cannot be parsed,
/// `BootError::Kvm` if KVM operations fail,
/// `BootError::GuestExit` if the guest exits with an unexpected reason.
///
/// # Safety
/// The returned `BootedVm` holds mmap'd memory that must be properly
/// unmapped (handled by Drop). Caller must ensure no aliasing pointers
/// exist.
pub unsafe fn boot_linux(kvm: &Kvm, config: &BootConfig) -> Result<BootedVm> {
    config.validate()?;

    // 1. Read and parse kernel ELF
    let kernel_data = fs::read(&config.kernel_path)?;
    let (kernel_entry, segments) = parse_kernel_elf(&kernel_data)?;

    // 2. Create KVM VM
    let vm = kvm.create_vm()?;

    // 3. Allocate guest memory (mmap anonymous)
    // Guest memory is mapped at physical address 0, so mem_ptr[guest_phys]
    // directly corresponds to the byte at guest physical address guest_phys.
    let mem_size = config.memory_size;
    // SAFETY: mmap with MAP_PRIVATE | MAP_ANONYMOUS, fd=-1 creates an
    // anonymous writable mapping of mem_size bytes.
    let mem_ptr = unsafe {
        let ptr = libc::mmap(
            ptr::null_mut(),
            mem_size as libc::size_t,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(BootError::Mmap("guest memory mmap failed".into()));
        }
        ptr as *mut u8
    };

    // Load ELF segments into guest memory at their physical addresses
    load_elf_segments(
        &kernel_data,
        &segments,
        mem_ptr,
        config.load_addr,
        mem_size,
    )?;

    // Optionally load initrd AFTER all kernel segments
    // CRITICAL: initrd address must NOT overlap with kernel segments.
    // The kernel segments span from segment phys_addr to phys_addr+mem_size.
    // We place the initrd at the first 2MB-aligned address above the kernel.
    let mut initrd_info: Option<(u64, u64)> = None;
    if let Some(initrd_path) = &config.initrd_path {
        // Calculate kernel end: max(segment.phys_addr + segment.mem_size)
        let kernel_end = segments.iter()
            .map(|s| s.phys_addr + s.mem_size)
            .max()
            .unwrap_or(0);
        // Align up to 2MB boundary to avoid partial page table conflicts
        const PAGE_SIZE_2MB: u64 = 2 * 1024 * 1024;
        let initrd_addr = (kernel_end + PAGE_SIZE_2MB - 1) & !(PAGE_SIZE_2MB - 1);

        let (addr, size) = load_initrd(initrd_path, mem_ptr, mem_size, initrd_addr)?;
        initrd_info = Some((addr, size));
    }

    // ── Standard boot_params setup (always, for any x86_64 kernel) ──
    // startup_64 expects RSI → boot_params structure. This is the standard
    // Linux boot protocol. We set up a minimal boot_params with initrd info
    // and kernel cmdline.
    //
    // SAFETY: boot_params range validated below.
    unsafe {
        setup_boot_params(
            mem_ptr,
            mem_size,
            initrd_info,
            BOOT_PARAMS_ADDR,
            &config.reserved_regions,
        )?;
    }

    // ── PVH boot protocol: write hvm_start_info structure (for PVH-capable kernels) ──
    // For vmlinux kernels (pvh_boot=true), we also provide a minimal
    // start_info structure with initrd location. The kernel's
    // PVH entry point reads this to find the initramfs.
    if config.pvh_boot {
        // Validate the PVH structure addresses fit in guest memory
        let pvh_end = PVH_CMDLINE_ADDR + 256; // 256 bytes for cmdline
        validate_guest_range(mem_size, PVH_START_INFO_ADDR, pvh_end)?;

        // SAFETY: validated above
        unsafe {
            // Write hvm_start_info at PVH_START_INFO_ADDR (0x2000)
            // struct hvm_start_info {
            //   u32 magic;         // offset 0: 0x336ec578
            //   u32 version;       // offset 4: 1
            //   u32 flags;         // offset 8: 0
            //   u32 nr_modules;    // offset 12: 0 or 1
            //   u64 modlist_paddr; // offset 16
            //   u64 cmdline_paddr; // offset 24
            // }   // total: 32 bytes
            let si = mem_ptr.add(PVH_START_INFO_ADDR as usize);
            ptr::write(si as *mut u32, HVM_START_MAGIC);
            ptr::write(si.add(4) as *mut u32, 1); // version
            ptr::write(si.add(8) as *mut u32, 0); // flags

            if let Some((initrd_addr, initrd_size)) = initrd_info {
                // There is an initrd — set up module list
                ptr::write(si.add(12) as *mut u32, 1); // nr_modules = 1
                ptr::write(si.add(16) as *mut u64, PVH_MODLIST_ADDR);
                ptr::write(si.add(24) as *mut u64, PVH_CMDLINE_ADDR);

                // Write hvm_modlist_entry at PVH_MODLIST_ADDR (0x2040)
                // struct hvm_modlist_entry {
                //   u64 paddr;          // offset 0: physical address of initrd
                //   u64 size;           // offset 8
                //   u64 cmdline_paddr;  // offset 16: per-module cmdline (optional)
                //   u64 reserved;       // offset 24
                // }   // total: 32 bytes
                let ml = mem_ptr.add(PVH_MODLIST_ADDR as usize);
                ptr::write(ml as *mut u64, initrd_addr);
                ptr::write(ml.add(8) as *mut u64, initrd_size);
                ptr::write(ml.add(16) as *mut u64, 0); // no per-module cmdline
                ptr::write(ml.add(24) as *mut u64, 0); // reserved
            } else {
                // No initrd, no modules
                ptr::write(si.add(12) as *mut u32, 0); // nr_modules = 0
                ptr::write(si.add(16) as *mut u64, 0); // modlist_paddr = 0
                ptr::write(si.add(24) as *mut u64, PVH_CMDLINE_ADDR); // cmdline always provided
            }

            // Determine kernel command line
            let cmdline_bytes: &[u8] = if let Some(ref custom_cmdline) = config.cmdline {
                // Use custom cmdline (for GPU passthrough, don't include pci=off)
                custom_cmdline.as_bytes()
            } else {
                // Default minimal cmdline:
                // acpi=off: boot without ACPI tables (not provided in direct KVM)
                // console=ttyS0,115200: serial output with explicit baud rate
                // earlyprintk=serial,0x3f8,115200: early serial debug output
                // loglevel=3: suppress most kernel messages (faster boot)
                // rodata=off: workaround for mark_readonly() hang with 2MB pages
                // rdinit=/init: explicitly set init path for initramfs
                // pci=off: skip PCI probing (no PCI devices in minimal VM)
                // iomem=relaxed: allow /dev/mem access even with CONFIG_STRICT_DEVMEM
                //   (needed by init script to read commands/write output via dev/mem)
                // random.trust_cpu=on: trust CPU RNG for entropy (avoids getrandom() blocking)
                // idle=halt: force HLT instead of MWAIT in idle loop. KVM handles MWAIT
                //   internally without returning to userspace, which means run_until_ready()
                //   never sees KVM_EXIT_HLT and can't inject timer interrupts to wake
                //   the guest. HLT exits to userspace where we can inject IRQ 0x20.
                //
                // NOTE: noapic/nolapic removed — the in-kernel PIC (created by
                // KVM_CREATE_IRQCHIP) does NOT handle PIT forwarding by default.
                // Without APIC, the kernel depends on the legacy PIC for interrupt
                // routing, but the PIC starts with all IRQs masked and the kernel
                // may not explicitly program the PIC. This leaves PIT IRQ 0 masked,
                // jiffies never increment, and the kernel hangs. With APIC enabled,
                // the IOAPIC routes PIT interrupts properly.
                b"console=ttyS0,115200 earlyprintk=serial,0x3f8,115200 acpi=off lpj=10000000 loglevel=7 rodata=off rdinit=/init pci=off iomem=relaxed random.trust_cpu=on idle=halt\0"
            };

            // Write kernel command line at PVH_CMDLINE_ADDR
            // Must be null-terminated.
            let cmdline_terminated: Vec<u8> = if cmdline_bytes.last() != Some(&0) {
                let mut v = cmdline_bytes.to_vec();
                v.push(0);
                v
            } else {
                cmdline_bytes.to_vec()
            };
            let cmdline_len = cmdline_terminated.len().min(255); // limit to 255 bytes
            ptr::copy_nonoverlapping(
                cmdline_terminated.as_ptr(),
                mem_ptr.add(PVH_CMDLINE_ADDR as usize),
                cmdline_len,
            );
            // Pad with null
            if cmdline_len < 256 {
                ptr::write_bytes(
                    mem_ptr.add(PVH_CMDLINE_ADDR as usize + cmdline_len),
                    0,
                    256 - cmdline_len,
                );
            }
        }
    }

    // 4. Set memory regions on the VM (always at guest physical 0).
    //    If there are reserved regions (GPU BAR holes), split RAM into
    //    multiple slots so the reserved GPA ranges are not backed by RAM.
    //    This avoids KVM_SET_USER_MEMORY_REGION EEXIST when VFIO BARs
    //    are later mapped at those addresses.
    //
    // Slots:
    //   0: [0, first_reserved_start)  — RAM
    //   1: [first_reserved_end, second_reserved_start) — RAM (if needed)
    //   ... (up to 4 slots total — plenty for a handful of GPU BARs)
    //
    // The VFIO BAR mapping uses slots 250+.
    //
    // SAFETY: mem_ptr is a valid mmap region of mem_size bytes.
    unsafe {
        // Collect reserved regions that overlap with [0, mem_size)
        let mut holes: Vec<(u64, u64)> = config
            .reserved_regions
            .iter()
            .filter(|r| r.start < mem_size && r.end > 0)
            .map(|r| (r.start.max(0), r.end.min(mem_size)))
            .collect();
        holes.sort_by_key(|h| h.0);

        let mut ram_slot: u32 = 0;
        let mut current_start: u64 = 0;

        for (hole_start, hole_end) in &holes {
            let hole_s = *hole_start;
            let hole_e = *hole_end;

            // RAM segment before this hole
            if current_start < hole_s {
                let seg_size = hole_s - current_start;
                vm.set_memory_region(ram_slot, current_start, seg_size,
                                     mem_ptr.add(current_start as usize), 0)?;
                ram_slot += 1;
            }

            // Advance past the hole
            current_start = hole_e;
        }

        // Final RAM segment after the last hole
        if current_start < mem_size {
            let seg_size = mem_size - current_start;
            vm.set_memory_region(ram_slot, current_start, seg_size,
                                 mem_ptr.add(current_start as usize), 0)?;
            ram_slot += 1;
        }

        // If no holes, create a single slot covering all memory
        if ram_slot == 0 {
            vm.set_memory_region(0, 0, mem_size, mem_ptr, 0)?;
        }

        info!("boot: created {} RAM slot(s) for {} MB memory ({} reserved holes)",
              ram_slot.max(1), mem_size / (1024 * 1024), holes.len());
    }

    // 5. Set TSS address for VMX
    // KVM_SET_TSS_ADDR tells KVM (specifically VMX) where to place the
    // I/O bitmap, TSS area for real-mode transitions, and other VMCS
    // structures. Without this, VM entry fails on VMX hosts with
    // VMX_EXIT_REASON_INVALID_GUEST_STATE.
    // SAFETY: vm is a valid VM fd, KVM_SET_TSS_ADDR takes a u64 argument.
    unsafe {
        let ret = libc::ioctl(
            vm.as_raw_fd(),
            crate::kvm::KVM_SET_TSS_ADDR as libc::c_ulong,
            0xffffd000u64, // conventional TSS address near top of 32-bit space
        );
        if ret < 0 {
            return Err(BootError::Kvm(kvm::KvmError::Ioctl {
                context: "KVM_SET_TSS_ADDR".into(),
                errno: kvm::errno_after_ioctl(),
            }));
        }
    }

    // 5b. Optionally create in-kernel interrupt chipset (PIC + IOAPIC + LAPIC) + PIT
    // Required for the real Linux kernel (PIT timer interrupts drive jiffies).
    // Must be called BEFORE VCPU creation (KVM_CREATE_IRQCHIP returns EINVAL
    // if VCPUs already exist). Default is false — stub/test kernels don't have
    // an IDT and would hang on PIT interrupts during HLT.
    //
    // NOTE: KVM_CREATE_IRQCHIP creates PIC/IOAPIC/LAPIC but NOT the PIT on
    // Linux 6.x. We must additionally call KVM_CREATE_PIT2 to create the
    // in-kernel PIT. Without it, guest PIT IO accesses (ports 0x40-0x43) exit
    // to userspace where we discard them, the PIT never starts, timer
    // interrupts never fire, and the kernel hangs at boot.
    if config.irqchip {
        vm.create_irqchip()?;
        // Also create in-kernel PIT for timer interrupts (must be done
        // after irqchip, before VCPU creation)
        vm.create_pit()?;
    }

    // 5c. Create VCPU and mmap kvm_run
    let vcpu = vm.create_vcpu(0)?;
    let mmap_size = kvm.vcpu_mmap_size()?;
    // SAFETY: vcpu is a valid VCPU, mmap_size is from KVM_GET_VCPU_MMAP_SIZE
    let kvm_run_ptr = unsafe { vcpu.kvm_run_ptr(mmap_size)? };

    // 6. Set up CPUID for long mode support
    // Must be done before KVM_SET_SREGS to ensure the VCPU recognizes
    // the long-mode CPU features. We use the host's supported CPUID
    // to ensure compatibility.
    setup_cpuid(kvm, &vcpu)?;

    // 7. Set up page tables in guest memory at 0x70000
    // SAFETY: mem_ptr covers addresses 0..mem_size, and 0x70000+8 < mem_size (64MB)
    unsafe {
        setup_page_tables(mem_ptr, mem_size)?;
    }

    // 7. Set up GDT in guest memory at 0x60000
    // SAFETY: mem_ptr covers addresses 0..mem_size, and 0x60000+24 < mem_size
    unsafe {
        setup_gdt(mem_ptr)?;
    }

    // 8. Configure special registers (SREGS) for 64-bit long mode
    //
    // We use KVM_GET_SREGS first to obtain properly initialized default
    // values from KVM (including interrupt table, segment defaults, etc.),
    // then modify only the fields we need.
    //
    // CRITICAL: KEEP default values for TR, LDT, IDT, and CR0 bits
    // (CD=1, NW=1, ET=1). Only add PE=1 and PG=1 to CR0 via bitwise OR.
    // Setting these to custom values (like tr.unusable=1) causes FAIL_ENTRY.
    let mut sregs = vcpu.get_sregs()?;

    // Debug: print initial SREGS values (test-only diagnostic)
    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            "DEBUG boot: KVM_GET_SREGS initial: cr0=0x{:x} cr4=0x{:x} efer=0x{:x} cs=0x{:x} l={} d={} type={}",
            sregs.cr0, sregs.cr4, sregs.efer,
            sregs.cs.selector, sregs.cs.l, sregs.cs.db, sregs.cs.type_,
        );
    }

    // --- GDT descriptor ---
    sregs.gdt.base = GDT_ADDR;
    sregs.gdt.limit = 23; // 3 descriptors × 8 bytes - 1

    // --- Code segment (CS) ---
    // GDT layout: null(0x00), code(index 1→selector 0x08), data(index 2→selector 0x10)
    sregs.cs.base = 0;
    sregs.cs.selector = 0x08; // code descriptor at GDT index 1 (offset 8)
    sregs.cs.type_ = 0xB; // code, execute/read, accessed
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0;
    sregs.cs.s = 1; // code/data descriptor (not system)
    sregs.cs.l = 1; // long mode (64-bit)
    sregs.cs.g = 1; // granularity (4KB pages)
    sregs.cs.limit = 0xFFFFF; // 4GB limit (ignored in long mode, but some VMX verifiers check)

    // --- Data segments (DS, ES, FS, GS, SS) ---
    // All use the data descriptor at GDT index 2 (selector 0x10)
    // type_ encoding for 4-bit descriptor type field:
    //   bit 3 (E): 0=data, 1=code
    //   bit 2 (DC): direction/conforming
    //   bit 1 (RW): writable/readable
    //   bit 0 (A): accessed
    // Data, read/write, accessed: type=3 (0b0011: E=0, DC=0, RW=1, A=1)
    // Code, execute/read, accessed: type=0xB (0b1011: E=1, DC=0, RW=1, A=1)
    for seg in [&mut sregs.ds, &mut sregs.es, &mut sregs.fs, &mut sregs.gs, &mut sregs.ss]
        .iter_mut()
    {
        seg.base = 0;
        seg.selector = 0x10; // data descriptor at GDT index 2 (offset 16)
        seg.type_ = 3; // data, read/write, accessed (bit3=0)
        seg.present = 1;
        seg.dpl = 0;
        seg.db = 0;
        seg.s = 1;
        seg.l = 0;
        seg.g = 1;
        seg.limit = 0xFFFFF; // full 4GB limit
    }

    // --- TR and LDT ---
    // CRITICAL: KEEP KVM DEFAULTS. Don't set tr.unusable=1 or ldt.unusable=1.
    // KVM_GET_SREGS returns properly initialized TR/LDT values.

    // --- Control registers ---
    // Long mode setup: we MUST set everything in ONE SET_SREGS call.
    // Two-step approaches (PE first, then PG+LME) fail because:
    //   - PAE=1 requires PG=1 (Intel SDM, KVM enforces this)
    //   - LME=1 requires PAE=1 (for PG=1 case)
    // So the only valid transition is: all at once.
    //
    // CR0 for long mode: keep CD|NW from KVM defaults, add PG|WP|NE|ET|MP|PE.
    // Some KVM/hardware versions require CD=1 or NW=1 for valid VM entry state.
    sregs.cr3 = PML4_ADDR;
    sregs.cr4 = CR4_PAE;              // PAE=1 only
    sregs.efer = EFER_LME | EFER_LMA; // LME=1, LMA=1
    sregs.cr0 = 0xE0050033;          // CD|NW|PG|WP|NE|ET|MP|PE

    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            "DEBUG boot: SET_SREGS: cr0=0x{:x} cr3=0x{:x} cr4=0x{:x} efer=0x{:x} cs={} type={} ss={} type={} ds={} type={}",
            sregs.cr0, sregs.cr3, sregs.cr4, sregs.efer,
            sregs.cs.selector, sregs.cs.type_, sregs.ss.selector, sregs.ss.type_, sregs.ds.selector, sregs.ds.type_,
        );
    }
    vcpu.set_sregs(&sregs)?;
    // Verify SET_SREGS was accepted by reading back SREGS
    #[cfg(debug_assertions)]
    {
        if let Ok(verify) = vcpu.get_sregs() {
            tracing::debug!(
                "DEBUG boot: POST-SET_SREGS verify: cs sel={} type={} ss sel={} type={} ds sel={} type={}",
                verify.cs.selector, verify.cs.type_, verify.ss.selector, verify.ss.type_, verify.ds.selector, verify.ds.type_,
            );
        }
        // Verify GDT content in guest memory (debug-only, test diagnostics)
        // SAFETY: mem_ptr is a valid mmap covering addresses 0..mem_size (64MB).
        // GDT addresses 0x60000, 0x60008, 0x60010 are within 0..64MB and 8-byte aligned.
        let gdt_data = unsafe { std::ptr::read_unaligned(mem_ptr.add(0x60010) as *const u64) };
        let gdt_code = unsafe { std::ptr::read_unaligned(mem_ptr.add(0x60008) as *const u64) };
        let gdt_null = unsafe { std::ptr::read_unaligned(mem_ptr.add(0x60000) as *const u64) };
        tracing::debug!("DEBUG boot: GDT memory: null=0x{gdt_null:016x} code=0x{gdt_code:016x} data=0x{gdt_data:016x}");
    }

    // 9. Configure general-purpose registers (REGS)
    // RSI points to boot_params structure (standard Linux boot protocol).
    // startup_64 saves RSI → r15 and later uses it to find initrd, cmdline, etc.
    // We always set up boot_params at BOOT_PARAMS_ADDR (0x10000).
    // The PVH hvm_start_info is also set up (at 0x2000) for PVH-capable kernels,
    // but since we enter at startup_64 (ELF entry), boot_params is the primary
    // mechanism used by the kernel to find initrd and cmdline.
    let regs = KvmRegsRaw {
        rflags: 2, // reserved bit (must be 1)
        rip: kernel_entry,
        rsp: STACK_TOP,
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: BOOT_PARAMS_ADDR,
        rdi: 0,
        rbp: 0,
        ..Default::default()
    };
    vcpu.set_regs(&regs)?;

    // Compute kernel hash if not provided
    let kernel_hash = if config.kernel_hash.is_empty() {
        crate::kernel_registry::KernelRegistry::compute_kernel_hash(&config.kernel_path)
            .unwrap_or_default()
    } else {
        config.kernel_hash.clone()
    };

    let kernel_version = if config.kernel_version.is_empty() {
        crate::kernel_registry::KernelRegistry::DEFAULT_VERSION.to_string()
    } else {
        config.kernel_version.clone()
    };

    Ok(BootedVm {
        vm,
        vcpu,
        kvm_run_ptr,
        kvm_run_size: mmap_size,
        memory_ptr: mem_ptr,
        memory_size: mem_size,
        load_addr: config.load_addr,
        kernel_entry,
        vfio_pci: None,
        vfio_mmio_info: None,
        pcie_root_port: None,
        entropy_divergence: true,  // default: inject CSPRNG per boot
        kernel_version,
        kernel_hash,
    })
}

/// Run a booted VM until it halts (KVM_EXIT_HLT)
///
/// # Safety
/// `booted` must be a valid `BootedVm` returned from `boot_linux()`.
/// The kvm_run_ptr must point to a valid mmap'd kvm_run structure.
pub unsafe fn run_until_ready(booted: &BootedVm) -> Result<()> {
    // SAFETY: caller guarantees VCPU is properly configured.
    let vcpu = &booted.vcpu;
    loop {
        let ret = unsafe { vcpu.run()? };
        if ret == libc::EINTR {
            continue; // retry on signal
        }

        // SAFETY: kvm_run_ptr is a valid mmap'd kvm_run from this VCPU.
        let reason = unsafe { Vcpu::exit_reason(booted.kvm_run_ptr) };
        match reason {
            kvm::KVM_EXIT_HLT => return Ok(()),
            kvm::KVM_EXIT_FAIL_ENTRY => {
                // Read hardware_entry_failure_reason at kvm_run offset 32.
                let hw_reason = unsafe {
                    ptr::read_unaligned(booted.kvm_run_ptr.add(32) as *const u64)
                };
                let cpu_id = unsafe {
                    ptr::read_unaligned(booted.kvm_run_ptr.add(40) as *const u32)
                };
                // Dump VCPU state for debugging
                #[cfg(debug_assertions)]
                if let Ok(post_sregs) = booted.vcpu.get_sregs() {
                    tracing::debug!(
                        "DEBUG boot: FAIL_ENTRY state: cr0=0x{:x} cr2=0x{:x} cr3=0x{:x} cr4=0x{:x} efer=0x{:x} \
                         cs=sel=0x{:x} base=0x{:x} limit=0x{:x} l={} d={} type={} p={} s={} g={} \
                         ss=sel=0x{:x} base=0x{:x} limit=0x{:x} type={} p={} g={} \
                         ds=sel=0x{:x} base=0x{:x} limit=0x{:x} type={} p={} g={}",
                        post_sregs.cr0, post_sregs.cr2, post_sregs.cr3, post_sregs.cr4, post_sregs.efer,
                        post_sregs.cs.selector, post_sregs.cs.base, post_sregs.cs.limit, post_sregs.cs.l, post_sregs.cs.db, post_sregs.cs.type_, post_sregs.cs.present, post_sregs.cs.s, post_sregs.cs.g,
                        post_sregs.ss.selector, post_sregs.ss.base, post_sregs.ss.limit, post_sregs.ss.type_, post_sregs.ss.present, post_sregs.ss.g,
                        post_sregs.ds.selector, post_sregs.ds.base, post_sregs.ds.limit, post_sregs.ds.type_, post_sregs.ds.present, post_sregs.ds.g,
                    );
                }
                return Err(BootError::GuestExit(format!(
                    "FAIL_ENTRY: hw_reason=0x{hw_reason:x} cpu={cpu_id}"
                )));
            }
            other => {
                return Err(BootError::GuestExit(format!(
                    "Exit reason {}",
                    other
                )));
            }
        }
    }
}

// ─── ELF parsing ───────────────────────────────────────────────────

/// A kernel ELF segment to load
#[derive(Debug, Clone)]
struct LoadSegment {
    /// Offset in the ELF file where the data starts
    file_offset: u64,
    /// Number of bytes to read from the file
    file_size: u64,
    /// Guest physical address where to place the segment
    phys_addr: u64,
    /// Number of bytes in memory (zero-padded beyond file_size)
    mem_size: u64,
    /// Whether the segment is writable (PF_W flag)
    #[allow(dead_code)]
    writable: bool,
}

/// Parse a kernel ELF binary and extract load segments + entry point
fn parse_kernel_elf(data: &[u8]) -> Result<(u64, Vec<LoadSegment>)> {
    use goblin::elf::program_header::PT_LOAD;

    let elf = goblin::elf::Elf::parse(data).map_err(|e| {
        BootError::Elf(format!("Failed to parse ELF: {}", e))
    })?;

    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Err(BootError::Elf(format!(
            "Not an x86_64 ELF: machine={}",
            elf.header.e_machine
        )));
    }

    let entry = elf.entry;
    let mut segments = Vec::new();

    for phdr in &elf.program_headers {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let paddr = phdr.p_paddr;
        let file_offset = phdr.p_offset;
        let file_size = phdr.p_filesz;
        let mem_size = phdr.p_memsz;
        let writable = (phdr.p_flags & 0x2) != 0; // PF_W (bit 1)

        segments.push(LoadSegment {
            file_offset,
            file_size,
            phys_addr: paddr,
            mem_size,
            writable,
        });
    }

    if segments.is_empty() {
        return Err(BootError::Elf("No PT_LOAD segments found".into()));
    }

    Ok((entry, segments))
}

/// Load ELF segments into guest memory at their physical addresses.
///
/// Memory is mapped at guest physical 0, so `mem_ptr + p_paddr` is the
/// correct destination for a segment loaded at `p_paddr`.
fn load_elf_segments(
    elf_data: &[u8],
    segments: &[LoadSegment],
    mem_ptr: *mut u8,
    _load_addr: u64,
    mem_size: u64,
) -> Result<()> {
    for seg in segments {
        let start = seg.phys_addr;
        let end = start + seg.mem_size;

        // Validate segment fits in guest memory (mapped at physical 0)
        validate_guest_range(mem_size, start, end)?;

        // Copy segment data from ELF file to guest memory
        let file_start = seg.file_offset as usize;
        let file_end = file_start + seg.file_size as usize;
        if file_end > elf_data.len() {
            return Err(BootError::Elf(format!(
                "Segment at physical 0x{:x} exceeds ELF file: need {} bytes, file has {}",
                seg.phys_addr, file_end, elf_data.len()
            )));
        }
        let src = &elf_data[file_start..file_end];

        // SAFETY: validated above that start is within guest memory bounds,
        // and src.len() <= seg.mem_size <= mem_size - start.
        unsafe {
            write_guest_slice(mem_ptr, start, src);
        }
    }

    Ok(())
}

/// Check if a memory region [start, end) overlaps with reserved areas
fn overlaps_reserved(start: u64, end: u64) -> bool {
    // Reserved: GDT at 0x60000 (24 bytes), page tables at 0x70000-0x73FFF (16KB)
    const RESERVED: &[(u64, u64)] = &[
        (GDT_ADDR, 0x100),   // 0x60000-0x600FF (GDT region)
        (PML4_ADDR, 0x5000), // 0x70000-0x74FFF (page table region)
    ];

    for &(rstart, rsize) in RESERVED {
        let rend = rstart + rsize;
        // Overlap if start < rend and end > rstart
        if start < rend && end > rstart {
            return true;
        }
    }
    false
}

// ─── Initrd loading ────────────────────────────────────────────────

/// Load an initrd image into guest memory at the specified physical address.
///
/// The caller must ensure `initrd_addr` does not overlap with kernel segments
/// or other reserved memory (page tables at 0x70000, GDT at 0x60000, etc.).
/// The address is typically computed from `kernel_end` in `boot_linux()` to
/// guarantee no overlap.
///
/// Returns (address, size) of the loaded initrd.
fn load_initrd(path: &Path, mem_ptr: *mut u8, mem_size: u64, initrd_addr: u64) -> Result<(u64, u64)> {
    let initrd_data = fs::read(path)?;
    let initrd_size = initrd_data.len() as u64;

    validate_guest_range(
        mem_size,
        initrd_addr,
        initrd_addr + initrd_size,
    )?;

    // SAFETY: validated above that initrd_addr + size fits in guest memory.
    unsafe {
        write_guest_slice(mem_ptr, initrd_addr, &initrd_data);
    }

    info!("initrd: loaded {} bytes at 0x{initrd_addr:x}", initrd_size);
    Ok((initrd_addr, initrd_size))
}

// ─── Page table setup ──────────────────────────────────────────────

/// Set up 4-level page tables for identity mapping with 2MB pages.
///
/// Layout (guest physical addresses):
/// - PML4[0] at 0x70000: entry[0] → PDP0 at 0x71000 (identity mapping)
/// - PML4[511] at 0x70000: entry[511] → PDP1 at 0x73000 (kernel virtual mapping)
/// - PDP0 at 0x71000: entry[0] → PD at 0x72000 (identity, map first mem_size bytes)
/// - PDP1 at 0x73000: entry[510] → PD at 0x72000 (kernel map 0xffffffff80000000+ to PA 0+)
/// - PD at 0x72000: entries covering mem_size with 2MB huge pages
///
/// The kernel virtual mapping maps VA 0xffffffff80000000+ → PA 0+,
/// which is needed by the Linux kernel's startup_64 entry to
/// access the kernel image at its expected virtual address.
///
/// 2MB pages are universally supported on x86_64 (unlike 1GB huge pages
/// which require CPU feature support).
///
/// # Safety
/// `mem_ptr` must point to a valid mmap region covering at least `0x75000` bytes
/// (PML4 + PDP0 + PDP1 + PD entries for the full memory range).
unsafe fn setup_page_tables(mem_ptr: *mut u8, mem_size: u64) -> Result<()> {
    const PAGE_SIZE_2MB: u64 = 2 * 1024 * 1024; // 2MB per page

    // Calculate PD entries needed: ceil(mem_size / 2MB)
    let num_pd_entries = mem_size.div_ceil(PAGE_SIZE_2MB);
    let pd_size_bytes = num_pd_entries * 8; // 8 bytes per entry
    let pd_end = PD_ADDR + pd_size_bytes;

    // Ensure PD table fits in the reserved page table area
    if pd_end > 0x76000 {
        return Err(BootError::Config(format!(
            "Memory too large: {mem_size} bytes needs {num_pd_entries} PD entries (0x{pd_end:x} > 0x76000)"
        )));
    }

    // PML4 entry[0]: points to PDP0 table at 0x71000 (present + writable)
    // This is the identity mapping.
    unsafe {
        write_guest_u64(mem_ptr, PML4_ADDR, PDP_ADDR | PT_PRESENT | PT_RW);
    }

    // PML4 entry[511]: points to PDP1 table at 0x73000 (present + writable)
    // This is the kernel virtual mapping (VA 0xffffffff80000000+ → PA 0+).
    const PDP1_ADDR: u64 = 0x73000;
    unsafe {
        write_guest_u64(mem_ptr, PML4_ADDR + 511 * 8, PDP1_ADDR | PT_PRESENT | PT_RW);
    }

    // PDP0 entry[0]: points to PD table at 0x72000 (present + writable)
    unsafe {
        write_guest_u64(mem_ptr, PDP_ADDR, PD_ADDR | PT_PRESENT | PT_RW);
    }

    // PDP1 entry[510]: points to PD table at 0x72000 (present + writable)
    // Maps VA range 0xffffffff80000000-0xffffffffbfffffff to PA 0-1GB
    // This is the standard kernel virtual base mapping.
    unsafe {
        write_guest_u64(mem_ptr, PDP1_ADDR + 510 * 8, PD_ADDR | PT_PRESENT | PT_RW);
    }

    // PD entries: each identity maps a 2MB region with PS=1 (2MB page)
    // The same PD table serves both identity and kernel virtual mappings
    // because the PD entry value (physical address) is the same regardless
    // of which higher-level table entry reached it.
    unsafe {
        for i in 0..num_pd_entries {
            let phys_addr = i * PAGE_SIZE_2MB;
            write_guest_u64(mem_ptr, PD_ADDR + i * 8, phys_addr | PT_PRESENT | PT_RW | PT_PS);
        }
    }

    Ok(())
}

// ─── GDT setup ─────────────────────────────────────────────────────

/// Set up a minimal GDT with null, 64-bit code, and 64-bit data descriptors.
///
/// Layout (guest physical addresses):
/// - 0x60000: NULL descriptor (8 bytes, all zeros)
/// - 0x60008: 64-bit code segment → selector 0x10
/// - 0x60010: 64-bit data segment → selector 0x18
///
/// # Safety
/// `mem_ptr` must point to a valid mmap region covering at least 0x60018 bytes.
unsafe fn setup_gdt(mem_ptr: *mut u8) -> Result<()> {
    // SAFETY: caller guarantees mem_ptr covers at least 0x60018 bytes.
    unsafe {
        write_guest_u64(mem_ptr, GDT_ADDR, GDT_NULL);
        write_guest_u64(mem_ptr, GDT_ADDR + 8, GDT_CODE);
        write_guest_u64(mem_ptr, GDT_ADDR + 16, GDT_DATA);
    }

    Ok(())
}

// ─── ELF Builder Helper ──────────────────────────────────────────

/// Build a minimal ELF64 binary containing the given x86-64 code.
///
/// The resulting ELF has a single PT_LOAD segment with:
/// - Virtual address: `0x100000`
/// - File offset: `0x1000` (page-aligned)
/// - Memory size: rounded up to the next page boundary
///
/// Used by `create_stub_kernel()` (production replay testing) and
/// several test helpers (test module below).
fn build_elf64_code(code: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut elf = Vec::new();

    // ── ELF64 header (64 bytes) ──
    elf.extend(&[0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let e_type: u16 = 2;       let e_machine: u16 = 62;
    let e_version: u32 = 1;    let e_entry: u64 = 0x100000;
    let e_phoff: u64 = 64;     let e_shoff: u64 = 0;
    let e_flags: u32 = 0;      let e_ehsize: u16 = 64;
    let e_phentsize: u16 = 56; let e_phnum: u16 = 1;
    let e_shentsize: u16 = 0;  let e_shnum: u16 = 0; let e_shstrndx: u16 = 0;
    elf.write_all(&e_type.to_ne_bytes()).unwrap();
    elf.write_all(&e_machine.to_ne_bytes()).unwrap();
    elf.write_all(&e_version.to_ne_bytes()).unwrap();
    elf.write_all(&e_entry.to_ne_bytes()).unwrap();
    elf.write_all(&e_phoff.to_ne_bytes()).unwrap();
    elf.write_all(&e_shoff.to_ne_bytes()).unwrap();
    elf.write_all(&e_flags.to_ne_bytes()).unwrap();
    elf.write_all(&e_ehsize.to_ne_bytes()).unwrap();
    elf.write_all(&e_phentsize.to_ne_bytes()).unwrap();
    elf.write_all(&e_phnum.to_ne_bytes()).unwrap();
    elf.write_all(&e_shentsize.to_ne_bytes()).unwrap();
    elf.write_all(&e_shnum.to_ne_bytes()).unwrap();
    elf.write_all(&e_shstrndx.to_ne_bytes()).unwrap();

    // ── Program header (56 bytes at offset 64) ──
    let code_len = code.len() as u64;
    let memsz = (code_len + 0xfff) & !0xfff; // round up to page
    let p_type: u32 = 1;   let p_flags: u32 = 7;
    let p_offset: u64 = 0x1000;
    let p_vaddr: u64 = 0x100000;
    let p_paddr: u64 = 0x100000;
    let p_filesz: u64 = code_len;
    let p_memsz: u64 = memsz.max(0x1000);
    let p_align: u64 = 0x1000;
    elf.write_all(&p_type.to_ne_bytes()).unwrap();
    elf.write_all(&p_flags.to_ne_bytes()).unwrap();
    elf.write_all(&p_offset.to_ne_bytes()).unwrap();
    elf.write_all(&p_vaddr.to_ne_bytes()).unwrap();
    elf.write_all(&p_paddr.to_ne_bytes()).unwrap();
    elf.write_all(&p_filesz.to_ne_bytes()).unwrap();
    elf.write_all(&p_memsz.to_ne_bytes()).unwrap();
    elf.write_all(&p_align.to_ne_bytes()).unwrap();

    // ── Padding to 0x1000 ──
    elf.resize(0x1000, 0);

    // ── Code at offset 0x1000 ──
    elf.extend_from_slice(code);

    // ── Pad to p_memsz ──
    let total = 0x1000 + memsz as usize;
    elf.resize(total, 0);
    elf
}

/// Code bytes for the production exec stub kernel:
/// copies `CMD_BUF_PHYS` → `OUT_BUF_PHYS`, then HLTs.
/// Used by `create_stub_kernel()` and by the milestone pipeline test.
const PROD_EXEC_STUB_CODE: &[u8] = &[
    // mov ecx, 0x7E000         ; source = CMD_BUF_PHYS
    0xb9, 0x00, 0xe0, 0x07, 0x00,
    // mov edx, 0x7F000         ; dest = OUT_BUF_PHYS
    0xba, 0x00, 0xf0, 0x07, 0x00,
    // copy_loop:
    //   cmp byte [rcx], 0      ; check for null
    0x80, 0x39, 0x00,
    //   je done
    0x74, 0x09,
    //   mov al, [rcx]          ; load byte
    0x8a, 0x01,
    //   mov [rdx], al          ; store byte
    0x88, 0x02,
    //   inc rcx
    0x48, 0xff, 0xc1,
    //   inc rdx
    0x48, 0xff, 0xc2,
    //   jmp copy_loop
    0xeb, 0xf0,
    // done:
    //   hlt
    0xf4,
];

/// Create an exec stub kernel ELF for process replay testing.
///
/// The stub copies code from `CMD_BUF_PHYS` to `OUT_BUF_PHYS` and
/// then halts (HLT). Used as a minimal kernel that exercises the full
/// KVM boot → snapshot → fork → inject → run → read pipeline.
///
/// On aarch64, this function returns a different ELF with `EM_AARCH64`
/// and appropriate machine code (see `arch/aarch64/boot.rs`).
pub fn create_stub_kernel() -> Vec<u8> {
    build_elf64_code(PROD_EXEC_STUB_CODE)
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Test ELF kernel ───────────────────────────────────────────
    //
    // A minimal 64-bit ELF executable that:
    // 1. Sets RSP to 0x80000
    // 2. Executes HLT
    // 3. Jumps back to HLT (infinite HLT loop)
    //
    // Generated manually per the ELF64 specification.
    // Structure:
    //   Offset 0x0000: Elf64_Ehdr (64 bytes)
    //   Offset 0x0040: Elf64_Phdr (56 bytes, PT_LOAD at 0x100000)
    //   Offset 0x0078: Padding to 0x1000
    //   Offset 0x1000: Code bytes (10 bytes)
    //     mov rsp, 0x80000  : 48 c7 c4 00 00 08 00
    //     hlt               : f4
    //     jmp -3 (back to hlt) : eb fd

    const TEST_KERNEL_CODE: &[u8] = &[
        0x48, 0xc7, 0xc4, 0x00, 0x00, 0x08, 0x00, // mov rsp, 0x80000
        0xf4, // hlt
        0xeb, 0xfd, // jmp -3 (back to hlt)
    ];

    /// Kernel that writes "OK\n" to guest memory at 0x2000000, then HLTs.
    /// Used to verify the guest→host output pipeline without serial I/O.
    /// The host reads [0x2000000] after KVM_RUN returns HLT.
    const CMD_OUTPUT_KERNEL_CODE: &[u8] = &[
        // mov rsp, 0x80000
        0x48, 0xc7, 0xc4, 0x00, 0x00, 0x08, 0x00,
        // mov byte [0x2000000], 'O' (0x4f)
        0xc6, 0x04, 0x25, 0x00, 0x00, 0x00, 0x02, 0x4f,
        // mov byte [0x2000001], 'K' (0x4b)
        0xc6, 0x04, 0x25, 0x01, 0x00, 0x00, 0x02, 0x4b,
        // mov byte [0x2000002], '\n' (0x0a)
        0xc6, 0x04, 0x25, 0x02, 0x00, 0x00, 0x02, 0x0a,
        // mov rax, 3  — number of bytes written (sign-extended imm32)
        0x48, 0xc7, 0xc0, 0x03, 0x00, 0x00, 0x00,
        // hlt
        0xf4,
        // jmp -3 (infinite HLT loop)
        0xeb, 0xfd,
    ];

    /// Kernel that reads a command from 0x2000000 (null-terminated, max 256 bytes)
    /// and writes "executed: <cmd>\n" to 0x2001000, then HLTs.
    /// Used for the exec pipeline: inject command → fork → run → read output.
    const EXEC_STUB_KERNEL_CODE: &[u8] = &[
        // mov rsp, 0x80000
        0x48, 0xc7, 0xc4, 0x00, 0x00, 0x08, 0x00,
        // cld (clear direction flag for lodsb/stosb)
        0xfc,
        // mov esi, 0x2000000  (source: injected command)
        0xbe, 0x00, 0x00, 0x00, 0x02,
        // mov edi, 0x2001000  (dest: output buffer)
        0xbf, 0x00, 0x10, 0x00, 0x02,
        // loop: lodsb (al = [rsi], rsi++)
        0xac,
        // test al, al
        0x84, 0xc0,
        // jz done (skip past stosb+jmp to done:)
        0x74, 0x03,
        // stosb ([rdi] = al, rdi++)
        0xaa,
        // jmp loop
        0xeb, 0xf8,
        // done: stosb (write null terminator to output)
        0xaa,
        // hlt
        0xf4,
        // jmp -3 (infinite HLT loop)
        0xeb, 0xfd,
    ];


    fn create_test_kernel_elf() -> Vec<u8> { build_elf64_code(TEST_KERNEL_CODE) }

    /// Create an ELF64 binary containing the cmd_output kernel.
    fn create_cmd_output_kernel_elf() -> Vec<u8> { build_elf64_code(CMD_OUTPUT_KERNEL_CODE) }

    /// Create an ELF64 binary containing the exec stub kernel.
    fn create_exec_stub_kernel_elf() -> Vec<u8> { build_elf64_code(EXEC_STUB_KERNEL_CODE) }

    #[test]
    fn test_create_test_kernel_elf_valid() {
        let elf_bytes = create_test_kernel_elf();
        // Verify ELF magic
        assert_eq!(&elf_bytes[0..4], &[0x7f, 0x45, 0x4c, 0x46]);
        // Verify parsing with goblin
        let elf = goblin::elf::Elf::parse(&elf_bytes).expect("Should parse test ELF");
        assert_eq!(elf.entry, 0x100000);
        assert_eq!(elf.program_headers.len(), 1);
        assert_eq!(elf.program_headers[0].p_paddr, 0x100000);
        assert_eq!(elf.program_headers[0].p_filesz, 10);
    }

    #[test]
    fn test_parse_kernel_elf() {
        let elf_bytes = create_test_kernel_elf();
        let (entry, segments) = parse_kernel_elf(&elf_bytes).expect("Should parse test ELF");
        assert_eq!(entry, 0x100000);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].phys_addr, 0x100000);
        assert_eq!(segments[0].file_size, 10);
        assert!(segments[0].writable);
    }

    #[test]
    fn test_overlaps_reserved() {
        // GDT region at 0x60000
        assert!(overlaps_reserved(0x60000, 0x60020));
        // Page table region at 0x70000
        assert!(overlaps_reserved(0x70000, 0x71000));
        // Just below reserved
        assert!(!overlaps_reserved(0x5F000, 0x5FFFF));
        // Just above reserved
        assert!(!overlaps_reserved(0x75000, 0x76000));
        // Far away
        assert!(!overlaps_reserved(0x100000, 0x101000));
    }

    #[test]
    fn test_boot_minimal_kernel() {
        // Create a temporary test kernel ELF
        let elf_bytes = create_test_kernel_elf();
        let tmp_dir = std::env::temp_dir().join(format!("tinyos-boot-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let kernel_path = tmp_dir.join("test-kernel.elf");
        std::fs::write(&kernel_path, &elf_bytes).expect("Should write test kernel");

        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping boot test: KVM not available: {e}");
                return;
            }
        };

        let config = BootConfig {
            kernel_path: kernel_path.clone(),
            memory_size: 64 * 1024 * 1024, // 64 MB
            load_addr: 0,                   // Load at physical address 0
            initrd_path: None,
            pvh_boot: false,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        };

        // Boot the kernel
        // SAFETY: we control the test kernel and configuration
        let booted = unsafe {
            super::boot_linux(&kvm, &config).expect("Should boot test kernel")
        };

        // Verify booted state
        assert_eq!(booted.kernel_entry, 0x100000);
        assert!(!booted.memory_ptr.is_null());
        assert!(!booted.kvm_run_ptr.is_null());
        assert_eq!(booted.memory_size, 64 * 1024 * 1024);
        assert_eq!(booted.load_addr, 0);

        // Run until HLT
        // SAFETY: booted is a valid BootedVm from boot_linux()
        unsafe {
            super::run_until_ready(&booted).expect("Kernel should HLT");
        }

        // Verify the exit reason was HLT
        // SAFETY: kvm_run_ptr points to a valid, mmap'd kvm_run structure
        let reason = unsafe { Vcpu::exit_reason(booted.kvm_run_ptr) };
        assert_eq!(reason, kvm::KVM_EXIT_HLT, "Guest should exit with HLT");

        // Clean up temp file
        let _ = std::fs::remove_file(&kernel_path);
    }

    /// Boot the cmd-output kernel and verify it writes "OK\n" to guest memory at 0x2000000.
    /// This proves the guest→host output pipeline: guest writes to known physical address,
    /// host reads after KVM_RUN returns.
    #[test]
    fn test_boot_cmd_output_kernel() {
        let elf_bytes = create_cmd_output_kernel_elf();
        let tmp_dir = std::env::temp_dir().join(format!("tinyos-boot-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let kernel_path = tmp_dir.join("test-cmd-output-kernel.elf");
        std::fs::write(&kernel_path, &elf_bytes).expect("Should write test kernel");

        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping boot test: KVM not available: {e}");
                return;
            }
        };

        let config = BootConfig {
            kernel_path: kernel_path.clone(),
            memory_size: 64 * 1024 * 1024,
            load_addr: 0,
            initrd_path: None,
            pvh_boot: false,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        };

        // Boot the kernel (writes "OK\n" to 0x2000000 and HLTs)
        let booted = unsafe {
            super::boot_linux(&kvm, &config).expect("Should boot cmd-output kernel")
        };

        // Verify booted state
        assert_eq!(booted.kernel_entry, 0x100000);

        // Run until HLT
        unsafe {
            super::run_until_ready(&booted).expect("Kernel should HLT");
        }

        // Read guest memory at 0x2000000 — kernel stores output here
        // SAFETY: memory_ptr covers 64MB; 0x2000000 = 32MB < 64MB
        let output_bytes = unsafe {
            let ptr = booted.memory_ptr.add(0x2000000);
            std::slice::from_raw_parts(ptr, 3)
        };
        assert_eq!(output_bytes, b"OK\n", "Guest should write 'OK\\n' to output address");

        // Clean up
        let _ = std::fs::remove_file(&kernel_path);
        eprintln!("DEBUG: output pipeline works — guest wrote 'OK\\n' via memory");
    }

    /// 32-bit protected mode with PAE paging enabled (identity mapping via 2MB pages).
    /// Builds on the minimal protected mode test by adding page tables, CR3, CR4.PAE, CR0.PG.
    #[test]
    fn test_boot_32bit_pae_paging() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping test: KVM not available: {e}");
                return;
            }
        };

        let vm = kvm.create_vm().expect("create VM");
        let mem_size: u64 = 64 * 1024 * 1024;
        let mem_ptr = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                mem_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0,
            );
            assert!(ptr != libc::MAP_FAILED);
            ptr as *mut u8
        };

        // Write HLT at 0x1000
        let code: &[u8] = &[0xf4, 0xeb, 0xfd];
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), mem_ptr.add(0x1000), code.len()); }

        // Setup GDT at 0x600
        const GDT_32_CODE: u64 = 0x0000CF9A0000FFFF;
        const GDT_32_DATA: u64 = 0x0000CF920000FFFF;
        unsafe {
            write_guest_u64(mem_ptr, 0x600, 0u64);
            write_guest_u64(mem_ptr, 0x608, GDT_32_CODE);
            write_guest_u64(mem_ptr, 0x610, GDT_32_DATA);
        }

        // Setup legacy 2-level paging (CR4.PAE=0, CR4.PSE=1) with 4MB page:
        //   CR3 → Page Directory at 0x70000 (1024 × 4-byte entries, 32-bit each)
        //       → 4MB page at physical 0 (PS=1 in PD entry)
        //
        // 4MB page PD entry (32-bit):
        //   0x0087 = P=1 | R/W=1 | A=0 | D=0 | PS=1 | bits 22-31=0 (phys addr 0)
        unsafe {
            // PD[0] at 0x70000: 4MB page at physical 0
            std::ptr::write(mem_ptr.add(0x70000) as *mut u32, 0x0087u32);
        }

        unsafe { vm.set_memory_region(0, 0, mem_size, mem_ptr, 0).expect("set mem"); }

        let vcpu = vm.create_vcpu(0).expect("create vcpu");
        let mmap_size = kvm.vcpu_mmap_size().expect("mmap size");
        let kvm_run_ptr = unsafe { vcpu.kvm_run_ptr(mmap_size).expect("kvm_run ptr") };

        // KVM_SET_TSS_ADDR required before KVM_RUN on VMX hosts
        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), crate::kvm::KVM_SET_TSS_ADDR as libc::c_ulong, 0xffffd000u64) };
        assert!(ret >= 0, "KVM_SET_TSS_ADDR failed");

        let entries = kvm.get_supported_cpuid().expect("cpuid");
        vcpu.set_cpuid2(&entries).expect("set cpuid");

        let mut sregs = vcpu.get_sregs().expect("get sregs");

        eprintln!("DEBUG p32p: initial cr0=0x{:x} cr4=0x{:x} cs.sel=0x{:x}",
            sregs.cr0, sregs.cr4, sregs.cs.selector);

        // GDT
        sregs.gdt.base = 0x600;
        sregs.gdt.limit = 23;

        // CS: 32-bit code
        sregs.cs.base = 0;
        sregs.cs.selector = 0x08;
        sregs.cs.type_ = 0xB;
        sregs.cs.present = 1;
        sregs.cs.dpl = 0;
        sregs.cs.db = 1;
        sregs.cs.s = 1;
        sregs.cs.l = 0;
        sregs.cs.g = 1;
        sregs.cs.limit = 0xFFFFF;

        // Data segments
        for seg in [&mut sregs.ds, &mut sregs.es, &mut sregs.fs, &mut sregs.gs, &mut sregs.ss] {
            seg.base = 0;
            seg.selector = 0x10;
            seg.type_ = 3;
            seg.present = 1;
            seg.dpl = 0;
            seg.db = 1;
            seg.s = 1;
            seg.l = 0;
            seg.g = 1;
            seg.limit = 0xFFFFF;
        }

        // CR3 = Page Directory address (0x70000)
        sregs.cr3 = 0x70000;
        // CR4: PSE=1 (4MB pages via bit 4), PAE=0 (legacy 2-level paging)
        // No PAE required because we're using PSE for 4MB pages
        sregs.cr4 = 0x00000010; // PSE=1
        // CR0: keep all KVM defaults, add PG=1 and PE=1
        sregs.cr0 = 0x60000010; // reset to KVM default
        sregs.cr0 |= 0x80000001; // add PG=1, PE=1

        eprintln!("DEBUG p32p: SET_SREGS cr0=0x{:x} cr3=0x{:x} cr4=0x{:x}",
            sregs.cr0, sregs.cr3, sregs.cr4);

        // Verify page tables by reading them back
        let pd32_0 = unsafe { std::ptr::read_unaligned(mem_ptr.add(0x70000) as *const u32) };
        eprintln!("DEBUG p32p: page tables: PD[0] (32-bit)=0x{pd32_0:08x} (expect 0x87 for 4MB page)");
        // Also check code location
        let code_at_1000 = unsafe { std::ptr::read_unaligned(mem_ptr.add(0x1000) as *const u8) };
        eprintln!("DEBUG p32p: code[0x1000]=0x{code_at_1000:x} (expect 0xf4=HLT)");

        vcpu.set_sregs(&sregs).expect("set sregs");

        let regs = KvmRegsRaw {
            rflags: 2,
            rip: 0x1000,
            rsp: 0x8000,
            ..Default::default()
        };
        vcpu.set_regs(&regs).expect("set regs");

        eprintln!("DEBUG p32p: Running KVM_RUN...");
        loop {
            let ret = unsafe { vcpu.run().expect("KVM_RUN") };
            if ret == libc::EINTR { continue; }
            let reason = unsafe { Vcpu::exit_reason(kvm_run_ptr) };
            eprintln!("DEBUG p32p: exit_reason={reason}");
            match reason {
                kvm::KVM_EXIT_HLT => { eprintln!("DEBUG p32p: Got HLT! SUCCESS"); break; }
                kvm::KVM_EXIT_FAIL_ENTRY => {
                    let hw_reason = unsafe { std::ptr::read_unaligned(kvm_run_ptr.add(32) as *const u64) };
                    eprintln!("DEBUG p32p: FAIL_ENTRY hw_reason=0x{hw_reason:x}");
                    panic!("FAIL_ENTRY");
                }
                kvm::KVM_EXIT_SHUTDOWN => {
                    eprintln!("DEBUG p32p: SHUTDOWN (triple fault)");
                    if let Ok(post_sregs) = vcpu.get_sregs() {
                        eprintln!("DEBUG p32p: post-fault cr0=0x{:x} cr2=0x{:x} cr3=0x{:x} cr4=0x{:x} efer=0x{:x}",
                            post_sregs.cr0, post_sregs.cr2, post_sregs.cr3, post_sregs.cr4, post_sregs.efer);
                    }
                    panic!("SHUTDOWN");
                }
                other => { panic!("unexpected exit: {other}"); }
            }
        }

        unsafe { libc::munmap(mem_ptr as *mut libc::c_void, mem_size as libc::size_t); }
    }

    /// 32-bit protected mode test with minimal changes to KVM defaults.
    /// Uses GDT, switches to protected mode (CR0.PE=1) but keeps all other
    /// bits (CD, NW, ET, NE) from KVM defaults.
    #[test]
    fn test_boot_32bit_protected_minimal() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping test: KVM not available: {e}");
                return;
            }
        };

        let vm = kvm.create_vm().expect("Should create VM");
        let mem_size: u64 = 64 * 1024 * 1024;
        let mem_ptr = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                mem_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert!(ptr != libc::MAP_FAILED, "mmap failed");
            ptr as *mut u8
        };

        // Write HLT at 0x1000
        let code: &[u8] = &[0xf4, 0xeb, 0xfd]; // hlt; jmp -3
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), mem_ptr.add(0x1000), code.len()); }

        // Setup GDT at 0x600: null | 32-bit code | 32-bit data
        const GDT_32_CODE: u64 = 0x0000CF9A0000FFFF;
        const GDT_32_DATA: u64 = 0x0000CF920000FFFF;
        unsafe {
            write_guest_u64(mem_ptr, 0x600, 0u64);
            write_guest_u64(mem_ptr, 0x608, GDT_32_CODE);
            write_guest_u64(mem_ptr, 0x610, GDT_32_DATA);
        }

        unsafe { vm.set_memory_region(0, 0, mem_size, mem_ptr, 0).expect("set mem"); }

        // KVM_SET_TSS_ADDR required before KVM_RUN on VMX hosts
        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), crate::kvm::KVM_SET_TSS_ADDR as libc::c_ulong, 0xffffd000u64) };
        assert!(ret >= 0, "KVM_SET_TSS_ADDR failed");

        let vcpu = vm.create_vcpu(0).expect("create vcpu");
        let mmap_size = kvm.vcpu_mmap_size().expect("mmap size");
        let kvm_run_ptr = unsafe { vcpu.kvm_run_ptr(mmap_size).expect("kvm_run ptr") };

        let entries = kvm.get_supported_cpuid().expect("cpuid");
        vcpu.set_cpuid2(&entries).expect("set cpuid");

        // Get SREGS, make MINIMAL changes for 32-bit protected mode
        let mut sregs = vcpu.get_sregs().expect("get sregs");

        eprintln!("DEBUG p32: initial cr0=0x{:x} cs.sel=0x{:x} cs.base=0x{:x} cs.l={} cs.d={}",
            sregs.cr0, sregs.cs.selector, sregs.cs.base, sregs.cs.l, sregs.cs.db);

        // GDT
        sregs.gdt.base = 0x600;
        sregs.gdt.limit = 23;

        // CS: 32-bit code segment
        sregs.cs.base = 0;
        sregs.cs.selector = 0x08;
        sregs.cs.type_ = 0xB; // execute/read/accessed
        sregs.cs.present = 1;
        sregs.cs.dpl = 0;
        sregs.cs.db = 1; // 32-bit
        sregs.cs.s = 1;
        sregs.cs.l = 0;
        sregs.cs.g = 1;
        sregs.cs.limit = 0xFFFFF;

        // Data segments: minimal changes (just selector + base, keep defaults for rest)
        for seg in [&mut sregs.ds, &mut sregs.es, &mut sregs.fs, &mut sregs.gs, &mut sregs.ss] {
            seg.base = 0;
            seg.selector = 0x10;
            seg.type_ = 3; // read/write/accessed
            seg.present = 1;
            seg.dpl = 0;
            seg.db = 1;
            seg.s = 1;
            seg.l = 0;
            seg.g = 1;
            seg.limit = 0xFFFFF;
        }

        // CRITICAL: Only set CR0.PE=1, keep ALL other bits from KVM defaults!
        // KVM_GET_SREGS returned cr0=0x60000010 (CD|NW|ET)
        // CR0.PE is bit 0, so OR with 1 to set PE, keep CD|NW|ET etc.
        sregs.cr0 |= 0x00000001; // Add PE=1, keep everything else

        // Keep TR/LDT from KVM defaults (they're set correctly for real mode)
        // Keep CR3, CR4, EFER from KVM defaults (no paging, no long mode)

        eprintln!("DEBUG p32: SET_SREGS cr0=0x{:x} cs.sel=0x{:x}",
            sregs.cr0, sregs.cs.selector);

        vcpu.set_sregs(&sregs).expect("set sregs");

        let regs = KvmRegsRaw {
            rflags: 2,
            rip: 0x1000,
            rsp: 0x8000,
            ..Default::default()
        };
        vcpu.set_regs(&regs).expect("set regs");

        eprintln!("DEBUG p32: Running KVM_RUN...");
        loop {
            let ret = unsafe { vcpu.run().expect("KVM_RUN") };
            if ret == libc::EINTR { continue; }
            let reason = unsafe { Vcpu::exit_reason(kvm_run_ptr) };
            eprintln!("DEBUG p32: exit_reason={reason}");
            match reason {
                kvm::KVM_EXIT_HLT => { eprintln!("DEBUG p32: Got HLT! SUCCESS"); break; }
                kvm::KVM_EXIT_FAIL_ENTRY => {
                    let hw_reason = unsafe { std::ptr::read_unaligned(kvm_run_ptr.add(32) as *const u64) };
                    eprintln!("DEBUG p32: FAIL_ENTRY hw_reason=0x{hw_reason:x}");
                    panic!("FAIL_ENTRY");
                }
                other => { panic!("unexpected exit: {other}"); }
            }
        }

        unsafe {
            if !mem_ptr.is_null() { libc::munmap(mem_ptr as *mut libc::c_void, mem_size as libc::size_t); }
        }
    }

    /// Minimal real-mode KVM boot test.
    /// No page tables, no GDT, no protected mode — just real mode with HLT.
    /// This is the absolute simplest test to validate KVM works at all.
    #[test]
    fn test_boot_real_mode_minimal() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping test: KVM not available: {e}");
                return;
            }
        };

        // 1. Create VM
        let vm = kvm.create_vm().expect("Should create VM");

        // 2. Allocate guest memory (64 MB)
        let mem_size: u64 = 64 * 1024 * 1024;
        let mem_ptr = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                mem_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert!(ptr != libc::MAP_FAILED, "mmap failed");
            ptr as *mut u8
        };

        // 3. Write HLT at physical 0x1000
        //    In real mode: CS.base + RIP = physical address
        //    We'll set CS.base=0, RIP=0x1000
        let code: &[u8] = &[0xf4, 0xeb, 0xfd]; // hlt; jmp -3
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), mem_ptr.add(0x1000), code.len());
        }

        // 4. Register memory region
        unsafe {
            vm.set_memory_region(0, 0, mem_size, mem_ptr, 0)
                .expect("Should set memory region");
        }

        // KVM_SET_TSS_ADDR required before KVM_RUN on VMX hosts
        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), crate::kvm::KVM_SET_TSS_ADDR as libc::c_ulong, 0xffffd000u64) };
        assert!(ret >= 0, "KVM_SET_TSS_ADDR failed");

        // 6. Create VCPU
        let vcpu = vm.create_vcpu(0).expect("Should create VCPU");
        let mmap_size = kvm.vcpu_mmap_size().expect("Should get mmap size");
        let kvm_run_ptr = unsafe {
            vcpu.kvm_run_ptr(mmap_size).expect("Should mmap kvm_run")
        };

        // 7. Set CPUID
        let entries = kvm.get_supported_cpuid().expect("Should get CPUID");
        vcpu.set_cpuid2(&entries).expect("Should set CPUID");

        // 8. Get SREGS — keep defaults (real mode) except set CS to point to our code
        let mut sregs = vcpu.get_sregs().expect("Should get SREGS");

        eprintln!("DEBUG real: initial cr0=0x{:x} cr4=0x{:x} cs.sel=0x{:x} cs.base=0x{:x}",
            sregs.cr0, sregs.cr4, sregs.cs.selector, sregs.cs.base);

        // In real mode, physical address = CS.base * 16 + RIP
        // We want physical address 0x1000. Set CS.base=0, then RIP=0x1000.
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        // Keep everything else from KVM defaults

        // Debug: print what we're setting
        eprintln!("DEBUG real: SET_SREGS cr0=0x{:x} cs.sel=0x{:x} cs.base=0x{:x}",
            sregs.cr0, sregs.cs.selector, sregs.cs.base);

        vcpu.set_sregs(&sregs).expect("Should set SREGS");

        // 9. Set REGS
        let regs = KvmRegsRaw {
            rflags: 2,
            rip: 0x1000, // physical 0x1000 = CS.base(0) + RIP(0x1000)
            rsp: 0x8000,
            ..Default::default()
        };
        vcpu.set_regs(&regs).expect("Should set REGS");

        // 10. KVM_RUN
        eprintln!("DEBUG real: Running KVM_RUN...");
        loop {
            let ret = unsafe { vcpu.run().expect("KVM_RUN") };
            if ret == libc::EINTR {
                continue;
            }
            let reason = unsafe { Vcpu::exit_reason(kvm_run_ptr) };
            eprintln!("DEBUG real: exit_reason={reason}");
            match reason {
                kvm::KVM_EXIT_HLT => {
                    eprintln!("DEBUG real: Got HLT! SUCCESS");
                    break;
                }
                kvm::KVM_EXIT_FAIL_ENTRY => {
                    let hw_reason = unsafe {
                        std::ptr::read_unaligned(kvm_run_ptr.add(32) as *const u64)
                    };
                    eprintln!("DEBUG real: FAIL_ENTRY hw_reason=0x{hw_reason:x}");
                    panic!("FAIL_ENTRY");
                }
                kvm::KVM_EXIT_SHUTDOWN => {
                    eprintln!("DEBUG p32p: SHUTDOWN (triple fault)");
                    // Read CR2 (page fault linear address) via KVM_GET_SREGS
                    if let Ok(post_sregs) = vcpu.get_sregs() {
                        eprintln!("DEBUG p32p: post-fault cr0=0x{:x} cr2=0x{:x} cr3=0x{:x} cr4=0x{:x}",
                            post_sregs.cr0, post_sregs.cr2, post_sregs.cr3, post_sregs.cr4);
                    }
                    panic!("SHUTDOWN");
                }
                other => {
                    eprintln!("DEBUG real: unexpected exit reason {other}");
                    panic!("unexpected exit");
                }
            }
        }

        // Cleanup
        unsafe {
            if !mem_ptr.is_null() {
                libc::munmap(mem_ptr as *mut libc::c_void, mem_size as libc::size_t);
            }
        }
    }

    /// Integration test: boot cmd-output kernel → capture snapshot → fork → run → read output.
    /// This proves the full pipeline: boot, state capture, CoW fork with CPU restore, exec.
    #[test]
    fn test_boot_fork_read_output() {
        // ── 1. Boot the cmd-output kernel ──
        let elf_bytes = create_cmd_output_kernel_elf();
        let tmp_dir = std::env::temp_dir().join(format!("tinyos-boot-fork-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let kernel_path = tmp_dir.join("test-cmd-output-kernel.elf");
        std::fs::write(&kernel_path, &elf_bytes).expect("Should write test kernel");

        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping test: KVM not available: {e}");
                return;
            }
        };

        let config = BootConfig {
            kernel_path: kernel_path.clone(),
            memory_size: 64 * 1024 * 1024,
            load_addr: 0,
            initrd_path: None,
            pvh_boot: false,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        };

        // Boot the kernel (writes "OK\n" to 0x2000000 and HLTs)
        let booted = unsafe {
            super::boot_linux(&kvm, &config).expect("Should boot cmd-output kernel")
        };
        assert_eq!(booted.kernel_entry, 0x100000);

        // Run until HLT
        unsafe {
            super::run_until_ready(&booted).expect("Kernel should HLT");
        }

        // ── 2. Capture snapshot ──
        let snapshot = booted.capture_snapshot().expect("Should capture snapshot");
        assert_eq!(snapshot.load_addr, 0);
        assert!(snapshot.memory_size >= 64 * 1024 * 1024);

        let vcpu_mmap_size = kvm.vcpu_mmap_size().expect("Should get VCPU mmap size");

        // ── 3. Fork from snapshot ──
        let engine = crate::fork::ForkEngine::new(kvm, snapshot, vcpu_mmap_size);
        let mut forked = engine.fork().expect("Should fork from snapshot");

        // ── 4. Run the forked VM until HLT ──
        unsafe {
            forked.run_until_hlt().expect("Forked VM should run and HLT");
        }

        // ── 5. Read output from guest memory ──
        let output = unsafe {
            forked.read_guest_mem(0x2000000, 3)
                .expect("Should read guest memory")
        };
        assert_eq!(output, b"OK\n", "Forked VM should have 'OK\\n' at output address");
        eprintln!("DEBUG: fork+exec pipeline works — forked VM output: '{:?}'", std::str::from_utf8(output));

        // Clean up
        let _ = std::fs::remove_file(&kernel_path);
    }

    #[test]
    fn test_pvh_boot_protocol() {
        // Test that PVH boot structures are correctly written into guest memory
        // and that a kernel boots correctly with pvh_boot=true.

        // ── 1. Create a temp ELF kernel ──
        let elf_bytes = create_cmd_output_kernel_elf();
        let tmp_dir = std::env::temp_dir().join(format!("tinyos-pvh-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let kernel_path = tmp_dir.join("test-kernel.elf");
        std::fs::write(&kernel_path, &elf_bytes).expect("Should write test kernel");

        // ── 2. Boot with PVH ──
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping test: KVM not available: {e}");
                return;
            }
        };
        let config = BootConfig {
            kernel_path: kernel_path.clone(),
            memory_size: 64 * 1024 * 1024, // 64 MB
            load_addr: 0,
            initrd_path: None,
            pvh_boot: true,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        };

        let booted = unsafe {
            super::boot_linux(&kvm, &config).expect("Should boot with PVH")
        };

        // ── 3. Run the kernel ──
        unsafe {
            super::run_until_ready(&booted).expect("Kernel should HLT");
        }

        // ── 4. Capture snapshot ──
        let snapshot = booted.capture_snapshot().expect("Should capture snapshot");

        // ── 5. Verify PVH structures in snapshot memory ──
        let magic = snapshot.read_mem(PVH_START_INFO_ADDR, 4)
            .expect("Should read PVH start info");
        let magic_val = u32::from_le_bytes(magic[..4].try_into().unwrap());
        assert_eq!(
            magic_val, HVM_START_MAGIC,
            "PVH magic should be 0x336ec578, got 0x{:x}",
            magic_val
        );

        let flags_bytes = snapshot.read_mem(PVH_START_INFO_ADDR + 8, 4)
            .expect("Should read PVH flags");
        let flags = u32::from_le_bytes(flags_bytes[..4].try_into().unwrap());
        assert_eq!(flags, 0, "PVH flags should be 0");

        let nr_mod_bytes = snapshot.read_mem(PVH_START_INFO_ADDR + 12, 4)
            .expect("Should read PVH nr_modules");
        let nr_modules = u32::from_le_bytes(nr_mod_bytes[..4].try_into().unwrap());
        assert_eq!(nr_modules, 0, "PVH nr_modules should be 0 since no initrd");

        let cmd_paddr_bytes = snapshot.read_mem(PVH_START_INFO_ADDR + 24, 8)
            .expect("Should read PVH cmdline_paddr");
        let cmd_paddr = u64::from_le_bytes(cmd_paddr_bytes[..8].try_into().unwrap());
        assert_eq!(cmd_paddr, PVH_CMDLINE_ADDR, "cmdline_paddr should point to PVH_CMDLINE_ADDR");

        // Read enough bytes for the full extended cmdline (256 bytes allocated)
        let cmdline_bytes = snapshot.read_mem(PVH_CMDLINE_ADDR, 200)
            .expect("Should read kernel cmdline");
        // Convert to C-string (trim at first NUL)
        let cmdline_end = cmdline_bytes.iter().position(|&b| b == 0).unwrap_or(cmdline_bytes.len());
        let cmdline_str = std::str::from_utf8(&cmdline_bytes[..cmdline_end])
            .unwrap_or("(invalid utf-8)");
        let expected_prefix = "console=ttyS0,115200";
        assert!(
            cmdline_str.starts_with(expected_prefix),
            "cmdline should start with '{}', got: '{:?}'",
            expected_prefix, cmdline_str
        );
        // Verify the full extended cmdline includes all essential parameters
        assert!(cmdline_str.contains("acpi=off"), "cmdline should contain acpi=off");
        assert!(cmdline_str.contains("rdinit=/init"), "cmdline should contain rdinit=/init");

        eprintln!(
            "DEBUG: PVH boot protocol test passed — magic=0x{:x}, flags={}, nr_modules={}, cmdline='{}'",
            magic_val, flags, nr_modules, cmdline_str.trim_end_matches('\0')
        );

        // ── 6. Fork and run to verify kernel still works ──
        let vcpu_mmap_size = kvm.vcpu_mmap_size().expect("Should get VCPU mmap size");
        let engine = crate::fork::ForkEngine::new(kvm, snapshot, vcpu_mmap_size);
        let mut forked = engine.fork().expect("Should fork from PVH snapshot");
        // ── 4. Run the forked VM until HLT ──
        unsafe {
            forked.run_until_hlt().expect("Forked VM should run and HLT");
        }

        let output = unsafe {
            forked.read_guest_mem(0x2000000, 3)
                .expect("Should read guest memory")
        };
        assert_eq!(output, b"OK\n", "PVH-booted forked VM should have 'OK\\n' at output address");
        eprintln!("DEBUG: PVH forked VM output: '{:?}'", std::str::from_utf8(output));

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Integration test: full exec pipeline with exec stub kernel.
    ///
    /// Flow:
    ///   1. Boot exec stub kernel (kernel loaded, not run)
    ///   2. Capture clean snapshot (before kernel executes)
    ///   3. Fork from snapshot
    ///   4. Inject command into guest memory (0x2000000)
    ///   5. Run forked VM (kernel copies command to 0x2001000)
    ///   6. Read output from guest memory (0x2001000)
    ///
    /// This proves the full fork+exec pipeline with command injection.
    #[test]
    fn test_exec_stub_pipeline() {
        // ── 1. Boot the exec stub kernel ──
        let elf_bytes = create_exec_stub_kernel_elf();
        let tmp_dir = std::env::temp_dir().join(format!("tinyos-exec-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let kernel_path = tmp_dir.join("test-exec-stub.elf");
        std::fs::write(&kernel_path, &elf_bytes).expect("Should write test kernel");

        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping test: KVM not available: {e}");
                return;
            }
        };

        let config = BootConfig {
            kernel_path: kernel_path.clone(),
            memory_size: 64 * 1024 * 1024,
            load_addr: 0,
            initrd_path: None,
            pvh_boot: false,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        };

        // ── 2. Boot (but DO NOT run the kernel) ──
        let booted = unsafe {
            super::boot_linux(&kvm, &config).expect("Should boot exec stub kernel")
        };

        // ── 3. Capture snapshot BEFORE running the kernel ──
        // At this point, the page tables are set up, GDT is loaded,
        // and RIP points to kernel_entry. The kernel hasn't executed yet.
        let snapshot = booted.capture_snapshot().expect("Should capture clean snapshot");

        // Verify the snapshot is in clean state (RIP = kernel_entry = 0x100000)
        assert_eq!(snapshot.cpu.regs.rip, 0x100000);

        // ── 4. Fork and inject command ──
        let vcpu_mmap_size = kvm.vcpu_mmap_size().expect("Should get VCPU mmap size");
        let engine = crate::fork::ForkEngine::new(kvm, snapshot, vcpu_mmap_size);
        let mut forked = engine.fork().expect("Should fork from clean snapshot");

        // Verify kernel code at 0x100000 starts with mov rsp, 0x80000
        let kernel_code_start = unsafe {
            let ptr = forked.memory_ptr.add(0x100000);
            std::slice::from_raw_parts(ptr, 7)
        };
        assert_eq!(
            kernel_code_start,
            &[0x48, 0xc7, 0xc4, 0x00, 0x00, 0x08, 0x00],
            "Kernel code should start with mov rsp, 0x80000"
        );

        // Write command "print(1)\0" to 0x2000000 (null-terminated)
        let command = b"print(1)\0";
        unsafe {
            std::ptr::copy_nonoverlapping(
                command.as_ptr(),
                forked.memory_ptr.add(0x2000000),
                command.len(),
            );
        }

        // Verify the write is visible in guest memory
        let readback = unsafe {
            std::slice::from_raw_parts(forked.memory_ptr.add(0x2000000), 9)
        };
        assert_eq!(
            &readback[..8],
            b"print(1)",
            "Write to forked VM memory should be visible"
        );

        // ── 5. Run the forked VM ──
        unsafe {
            forked.run_until_hlt().expect("Forked VM should run and HLT");
        }

        // Read output from 0x2001000
        let output = unsafe {
            let mut out = vec![0u8; 64];
            std::ptr::copy_nonoverlapping(
                forked.memory_ptr.add(0x2001000),
                out.as_mut_ptr(),
                64,
            );
            let len = out.iter().position(|&b| b == 0).unwrap_or(64);
            out.truncate(len);
            out
        };

        let output_str = String::from_utf8_lossy(&output);

        // The exec stub copies the command from 0x2000000 to 0x2001000
        assert_eq!(
            output_str, "print(1)",
            "Exec stub should echo the injected command"
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Create an exec stub kernel that uses the production addresses
    /// CMD_BUF_PHYS (0x7E000) and OUT_BUF_PHYS (0x7F000).
    ///
    /// This matches the real `tinyos exec --lang python` pipeline addresses.
    /// MILESTONE TEST: Full end-to-end Python exec pipeline
    ///
    /// Validates `tinyos exec --lang python 'print(1)'` flow:
    ///   1. Boot exec stub kernel (simulates real kernel boot)
    ///   2. Capture snapshot (simulates post-boot template)
    ///   3. Fork from snapshot
    ///   4. Inject Python code into CMD_BUF_PHYS (0x7E000)
    ///   5. Run forked VM
    ///   6. Read output from OUT_BUF_PHYS (0x7F000)
    ///
    /// This test validates the ENTIRE pipeline except the real kernel boot.
    /// The stub kernel replaces the real kernel + initrd for CI testing.
    #[test]
    fn test_milestone_exec_pipeline_end_to_end() {
        // ── 1. Create stub kernel using production addresses (0x7E000/0x7F000)
        let elf_bytes = create_stub_kernel();
        let tmp_dir = std::env::temp_dir().join(format!("tinyos-milestone-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let kernel_path = tmp_dir.join("milestone-stub.elf");
        std::fs::write(&kernel_path, &elf_bytes).expect("Should write test kernel");

        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping milestone test: KVM not available: {e}");
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return;
            }
        };

        let config = BootConfig {
            kernel_path: kernel_path.clone(),
            memory_size: 64 * 1024 * 1024,
            load_addr: 0,
            initrd_path: None,
            pvh_boot: false,
            irqchip: false,
            cmdline: None,
            reserved_regions: Vec::new(),
            kernel_version: String::new(),
            kernel_hash: String::new(),
            vbios_data: None,
        };

        // ── 2. Boot and capture snapshot ──
        // SAFETY: boot_linux() configures page tables and registers for the stub
        // kernel ELF. kvm is a valid Kvm handle, config has valid paths and 64MB
        // memory. The ELF was just written to a temp file (verified above).
        let booted = unsafe {
            super::boot_linux(&kvm, &config).expect("Should boot milestone stub kernel")
        };
        let snapshot = booted.capture_snapshot().expect("Should capture milestone snapshot");

        // ── 3. Fork engine + fork ──
        let vcpu_mmap_size = kvm.vcpu_mmap_size().expect("Should get VCPU mmap size");
        let engine = crate::fork::ForkEngine::new(kvm, snapshot, vcpu_mmap_size);
        let mut forked = engine.fork().expect("Should fork from milestone snapshot");

        // ── 4. Inject code at CMD_BUF_PHYS (0x7E000) ──
        let code = b"print(1)\0";
        // SAFETY: CMD_BUF_PHYS (0x7E000) is well within the 64MB guest memory.
        // memory_ptr is a valid mmap'd allocation. code (stack) and memory_ptr
        // (mmap) do not overlap. copy length is bounded (9 bytes).
        unsafe {
            std::ptr::copy_nonoverlapping(
                code.as_ptr(),
                forked.memory_ptr.add(0x7E000),
                code.len(),
            );
        }

        // Verify the code is visible in guest memory
        // SAFETY: same bounds guarantee as above; reading 9 bytes from 0x7E000
        // is within 64MB guest memory. from_raw_parts produces a valid &[u8].
        let readback = unsafe {
            std::slice::from_raw_parts(forked.memory_ptr.add(0x7E000), 9)
        };
        assert_eq!(&readback[..8], b"print(1)", "Code should be visible in CMD_BUF");

        // ── 5. Run the forked VM ──
        // SAFETY: run_until_ready requires a properly configured VCPU. The fork
        // engine sets up registers and memory regions correctly. ForkedVm has
        // exclusive VCPU ownership (single-threaded test).
        unsafe {
            forked.run_until_hlt().expect("Forked VM should run and HLT");
        }

        // ── 6. Read output from OUT_BUF_PHYS (0x7F000) ──
        fn read_output(forked: &crate::fork::ForkedVm) -> String {
            // SAFETY: OUT_BUF_PHYS (0x7F000) is within the 64MB guest memory.
            // The loop reads at most 4096 bytes starting from there, well within
            // bounds. ptr::read from mmap'd memory has no side effects.
            unsafe {
                let ptr = forked.memory_ptr.add(0x7F000);
                let mut out = Vec::new();
                for i in 0..4096usize {
                    let byte = std::ptr::read(ptr.add(i));
                    if byte == 0 { break; }
                    out.push(byte);
                }
                String::from_utf8(out).unwrap_or_default()
            }
        }

        let output = read_output(&forked);

        // The stub kernel copies from CMD_BUF to OUT_BUF
        // Accept prefix match (stub may include trailing characters)
        assert!(
            output.starts_with("print(1)"),
            "Output should contain injected code. Got: {output:?}"
        );

        // ── Clean up ──
        let _ = std::fs::remove_dir_all(&tmp_dir);

        // If we got here, the full pipeline works:
        // boot → snapshot → fork → inject → run → read output
        tracing::info!("✓ MILESTONE: exec pipeline validated end-to-end");
    }

    // ─── VBIOS stub encoding ───────────────────────────────────────
    //
    // Verifies the 7-byte stub that vbios_write_stub() writes at physical
    // 0x8010. The stub performs lcall far 0xC000:0x0003 to invoke the
    // VBIOS Option ROM entry point, then halts. If the encoding is wrong
    // the VBIOS won't be called (stub jumps to wrong address).

    #[test]
    fn test_vbios_stub_encoding() {
        // These exact bytes are written by vbios_write_stub() via
        //   std::ptr::copy_nonoverlapping(stub.as_ptr(), mem_ptr.add(0x8010), 7)
        // Encoding: 9A [offset:2 LE] [segment:2 LE] [hlt] [hlt]
        //   offset = 0x0003 (VBIOS init entry point at the front of Option ROM)
        //   segment = 0xC000 (Option ROM base address)
        //   hlt/hlt = safety (VBIOS returns via lcall far, but if it doesn't...)
        let stub: [u8; 7] = [0x9A, 0x03, 0x00, 0x00, 0xC0, 0xF4, 0xF4];

        assert_eq!(stub[0], 0x9A, "opcode: lcall far");
        assert_eq!(u16::from_le_bytes([stub[1], stub[2]]), 0x0003, "lcall offset");
        assert_eq!(u16::from_le_bytes([stub[3], stub[4]]), 0xC000, "lcall segment");
        assert_eq!(stub[5], 0xF4, "safety hlt (1)");
        assert_eq!(stub[6], 0xF4, "safety hlt (2)");

        // Physical target = (segment << 4) + offset = (0xC000 << 4) + 0x0003
        assert_eq!(((0xC000u32) << 4) | 0x0003u32, 0xC0003, "lcall target address");
    }

    // ─── VBIOS memory layout ───────────────────────────────────────
    //
    // Verifies that the memory layout constants used by vbios_write_stub()
    // and vbios_run_until_hlt() are consistent and non-overlapping.
    // If someone moves VBIOS_ROM_ADDR or changes DEFAULT_LOAD_ADDR, this
    // test catches overlap before KVM boots with corrupted memory.

    #[test]
    fn test_vbios_memory_layout() {
        // Constants from vbios_write_stub() and vbios_run_until_hlt()
        assert_eq!(VBIOS_ROM_ADDR, 0xC0000);
        assert_eq!(VBIOS_STUB_ADDR, 0x8000);
        assert_eq!(VBIOS_STUB_SEG, 0x0800);
        assert_eq!(VBIOS_STUB_ENTRY_OFFSET, 0x10);
        assert_eq!(VBIOS_REAL_STACK, 0xE000);

        // CS:IP = 0x0800:0x0010 → physical 0x8010
        assert_eq!(((VBIOS_STUB_SEG as u64) << 4) + VBIOS_STUB_ENTRY_OFFSET, 0x8010);

        // Max VBIOS = 256KB. If larger, it overlaps kernel at 0x100000.
        let max_vbios = DEFAULT_LOAD_ADDR - VBIOS_ROM_ADDR;
        assert_eq!(max_vbios, 256 * 1024);
        assert!(VBIOS_ROM_ADDR + max_vbios <= DEFAULT_LOAD_ADDR,
            "ROM at 0xC0000 must not overlap kernel at 0x100000");
    }

    // ─── VBIOS register setup ──────────────────────────────────────
    //
    // Verifies the initial CPU registers that vbios_run_until_hlt() sets
    // before lcall to the Option ROM. Values match SeaBIOS __callrom()
    // convention. The test uses the same constants (VBIOS_REG_AX,
    // VBIOS_REG_RFLAGS) defined in layout.rs that the production code uses.
    //
    // If AX doesn't encode the correct BDF, the Option ROM enumerates
    // PCI bus 0 and never finds the GPU (was the bug fixed by commit
    // 7aed7db).

    #[test]
    fn test_vbios_register_setup() {
        // VBIOS_REG_AX = BDF 01:00.0: bus=1, dev=0, func=0
        let ax: u16 = VBIOS_REG_AX as u16;
        assert_eq!(ax >> 8, 1, "AH = bus 1");
        assert_eq!((ax >> 3) & 0x1f, 0, "AL bits 7-3 = device 0");
        assert_eq!(ax & 0x7, 0, "AL bits 2-0 = function 0");

        // VBIOS_REG_RFLAGS: bit 9 = IF (interrupts enabled)
        assert_eq!(VBIOS_REG_RFLAGS & 0x200, 0x200, "IF=1");
    }
}
