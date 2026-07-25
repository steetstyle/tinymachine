//! aarch64 Boot Protocol — DTB + PSCI based boot (STUB).
//!
//! aarch64 KVM guests use a different boot protocol than x86_64:
//! - Boot via Device Tree Blob (DTB) instead of PVH/boot_params
//! - CPU boot via PSCI (Power State Coordination Interface) instead of
//!   x86 INIT/SIPI/SIPI sequence
//! - Interrupt controller: GICv3 instead of LAPIC/IOAPIC/PIC
//! - UART: MMIO-based PL011 instead of port I/O 16550
//! - No port I/O — all device access via MMIO
//!
//! This module contains stub implementations that will be replaced
//! when aarch64 support is fully implemented.

use std::path::PathBuf;
use thiserror::Error;
use tracing::warn;

/// Errors from boot operations
#[derive(Error, Debug)]
pub enum BootError {
    #[error("KVM error: {0}")]
    Kvm(String),
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
    #[error("Architecture not yet supported: {0}")]
    UnsupportedArch(String),
}

pub type Result<T> = std::result::Result<T, BootError>;

/// Memory region to reserve in the guest memory map
#[derive(Debug, Clone)]
pub struct ReservedRegion {
    pub start: u64,
    pub end: u64,
}

/// Configuration for booting a Linux kernel inside KVM (aarch64 stub)
#[derive(Debug, Clone)]
pub struct BootConfig {
    pub kernel_path: PathBuf,
    pub initrd_path: Option<PathBuf>,
    pub memory_size: u64,
    pub load_addr: u64,
    pub irqchip: bool,
    pub cmdline: Option<String>,
    pub reserved_regions: Vec<ReservedRegion>,
    pub kernel_version: String,
    pub kernel_hash: String,
    pub vbios_data: Option<Vec<u8>>,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            kernel_path: PathBuf::new(),
            initrd_path: None,
            memory_size: 64 * 1024 * 1024,
            load_addr: 0x100000,
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
    pub fn validate(&self) -> Result<()> {
        if !self.kernel_path.exists() {
            return Err(BootError::Config(format!(
                "Kernel file not found: {}",
                self.kernel_path.display()
            )));
        }
        Ok(())
    }
}

/// A booted KVM VM — ready for snapshotting or execution (aarch64 stub)
#[derive(Debug)]
pub struct BootedVm {
    pub vm: crate::kvm::Vm,
    pub vcpu: crate::kvm::Vcpu,
    pub kvm_run_ptr: *mut u8,
    pub kvm_run_size: usize,
    pub memory_ptr: *mut u8,
    pub memory_size: u64,
    pub load_addr: u64,
    pub kernel_entry: u64,
    pub vfio_pci: Option<()>,
    pub vfio_mmio_info: Option<()>,
    pub entropy_divergence: bool,
    pub pcie_root_port: Option<()>,
    pub kernel_version: String,
    pub kernel_hash: String,
}

/// Write entropy to guest memory region.
pub fn write_entropy_ctrl(_memory_ptr: *mut u8, _entropy_divergence: bool) -> [u8; 4] {
    warn!("write_entropy_ctrl: aarch64 stub — returning zeros");
    [0u8; 4]
}

/// Boot a Linux kernel inside KVM (aarch64 stub).
///
/// # Safety
/// This is a stub — calling this will return UnsupportedArch error.
pub unsafe fn boot_linux(
    _kvm: &crate::kvm::Kvm,
    _config: &BootConfig,
) -> Result<BootedVm> {
    Err(BootError::UnsupportedArch(
        "aarch64 boot_linux not yet implemented".into()
    ))
}

/// Create an exec stub kernel ELF for process replay testing (STUB).
///
/// On aarch64, this would return an ELF with `EM_AARCH64` and appropriate
/// machine code. Currently returns an error message as bytes (placeholder).
pub fn create_stub_kernel() -> Vec<u8> {
    warn!("create_stub_kernel: aarch64 stub — returning placeholder");
    Vec::new()
}

/// Build the base kernel commandline for an aarch64 KVM guest (STUB).
///
/// aarch64 uses a PL011 UART at a different MMIO address. This stub
/// returns a minimal cmdline string with the PL011 console.
pub fn build_kernel_cmdline(loglevel: u32, profile_suffix: &str) -> String {
    format!(
        "console=ttyAMA0,115200 earlycon=pl011,0x9000000 \
         loglevel={loglevel} rdinit=/init {profile_suffix}"
    )
    .trim_end()
    .to_string()
}

/// Run VBIOS POST (no-op on aarch64 — VBIOS is x86-specific).
///
/// # Safety
/// No-op stub — always safe.
pub unsafe fn run_vbios_post(
    _vm: &mut BootedVm,
    _vbios_data: &[u8],
) -> Result<()> {
    warn!("run_vbios_post: aarch64 stub — VBIOS is x86-specific, no-op");
    Ok(())
}

/// Reconfigure CPU to long mode (no-op on aarch64 — always in 64-bit mode).
///
/// # Safety
/// No-op stub — always safe.
pub unsafe fn reconfigure_long_mode(
    _vm: &mut BootedVm,
) -> Result<()> {
    warn!("reconfigure_long_mode: aarch64 stub — aarch64 is always in 64-bit mode");
    Ok(())
}

/// Wait for the guest to write "READY" to the output buffer (aarch64 stub).
///
/// # Safety
/// Stub implementation — returns error.
pub unsafe fn run_until_ready(_vm: &BootedVm) -> Result<()> {
    Err(BootError::UnsupportedArch(
        "aarch64 run_until_ready not yet implemented".into()
    ))
}
