//! VFIO type definitions — device info, BAR info, MSI config, errors

use std::os::fd::RawFd;
use thiserror::Error;

// ─── VFIO ioctl constants (from linux/vfio.h) ──────────────────────
//
// VFIO_TYPE = ';' = 0x3B, VFIO_BASE = 100 = 0x64
// _IO(type, nr) = (0 << 30) | (0 << 16) | (type << 8) | nr
pub(crate) const VFIO_GET_API_VERSION: u64 = 0x003B64;
#[allow(dead_code)]
pub(crate) const VFIO_CHECK_EXTENSION: u64 = 0x003B65;
pub(crate) const VFIO_SET_IOMMU: u64 = 0x003B66;
pub(crate) const VFIO_GROUP_SET_CONTAINER: u64 = 0x003B68;
pub(crate) const VFIO_GROUP_GET_DEVICE_FD: u64 = 0x003B6A;
pub(crate) const VFIO_DEVICE_GET_REGION_INFO: u64 = 0x003B6C;
pub(crate) const VFIO_DEVICE_GET_IRQ_INFO: u64 = 0x003B6D;
pub(crate) const VFIO_DEVICE_SET_IRQS: u64 = 0x003B6E;
pub(crate) const VFIO_DEVICE_RESET: u64 = 0x003B6F;

// ─── VFIO interrupt routing constants ───────────────────────────────
pub(crate) const VFIO_PCI_INTX_IRQ_INDEX: u32 = 0;
#[allow(dead_code)]
pub(crate) const VFIO_PCI_MSI_IRQ_INDEX: u32 = 1;

pub(crate) const VFIO_IRQ_SET_DATA_NONE: u32 = 1 << 0;
#[allow(dead_code)]
pub(crate) const VFIO_IRQ_SET_DATA_BOOL: u32 = 1 << 1;
pub(crate) const VFIO_IRQ_SET_DATA_EVENTFD: u32 = 1 << 2;
#[allow(dead_code)]
pub(crate) const VFIO_IRQ_SET_ACTION_MASK: u32 = 1 << 3;
#[allow(dead_code)]
pub(crate) const VFIO_IRQ_SET_ACTION_UNMASK: u32 = 1 << 4;
pub(crate) const VFIO_IRQ_SET_ACTION_TRIGGER: u32 = 1 << 5;

// ─── VFIO region info flags ─────────────────────────────────────────
pub(crate) const VFIO_REGION_INFO_FLAG_MMAP: u32 = 1 << 1;
pub(crate) const VFIO_REGION_INFO_FLAG_READ: u32 = 1 << 2;
pub(crate) const VFIO_REGION_INFO_FLAG_WRITE: u32 = 1 << 3;

// ─── PCI BAR region indices ─────────────────────────────────────────
pub(crate) const VFIO_PCI_BAR0_REGION_INDEX: u32 = 0;
pub(crate) const VFIO_PCI_BAR1_REGION_INDEX: u32 = 1;
pub(crate) const VFIO_PCI_BAR2_REGION_INDEX: u32 = 2;
pub(crate) const VFIO_PCI_BAR3_REGION_INDEX: u32 = 3;
pub(crate) const VFIO_PCI_BAR4_REGION_INDEX: u32 = 4;
pub(crate) const VFIO_PCI_BAR5_REGION_INDEX: u32 = 5;
pub(crate) const VFIO_PCI_CONFIG_REGION_INDEX: u32 = 6;
pub(crate) const VFIO_PCI_VGA_REGION_INDEX: u32 = 7;

/// API version that must match (from linux/vfio.h)
pub(crate) const VFIO_API_VERSION: u32 = 0;

/// IOMMU driver types
pub(crate) const VFIO_TYPE1_IOMMU: u32 = 1;
pub(crate) const VFIO_TYPE1V2_IOMMU: u32 = 3;

// ─── Errors ─────────────────────────────────────────────────────────

/// Errors from VFIO operations
#[derive(Error, Debug)]
pub enum VfioError {
    #[error("VFIO not available: /dev/vfio/vfio not found")]
    NotAvailable,
    #[error("VFIO ioctl failed: {context} — errno {errno}")]
    Ioctl { context: String, errno: i32 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("No GPU found with VFIO-compatible IOMMU group")]
    NoGpuFound,
    #[error("GPU device {0} not bound to vfio-pci driver")]
    NotBoundToVfio(String),
    #[error("IOMMU group {0} already in use")]
    GroupInUse(u32),
    #[error("KVM integration failed: {0}")]
    Kvm(String),
    #[error("Invalid VFIO API version: got {got}, expected {expected}")]
    ApiVersion { got: u32, expected: u32 },
    #[error("CString conversion failed: {0}")]
    CString(#[from] std::ffi::NulError),
}

/// Result alias for VFIO operations
pub type Result<T> = std::result::Result<T, VfioError>;

/// Retrieve errno after a failed ioctl
// SAFETY: Must be called immediately after a failed libc::ioctl call.
// __errno_location() returns a pointer to thread-local errno,
// which is always valid to dereference in this context.
#[inline]
pub(crate) fn errno_after_ioctl() -> i32 {
    unsafe { *libc::__errno_location() }
}

// ─── GPU Device Info ────────────────────────────────────────────────

/// Information about a detected GPU device
#[derive(Debug, Clone)]
pub struct GpuDeviceInfo {
    /// PCI BDF identifier (e.g., "0000:01:00.0")
    pub pci_bdf: String,
    /// IOMMU group number
    pub iommu_group: u32,
    /// Vendor ID (e.g., 0x10de for NVIDIA)
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// GPU name from sysfs
    pub name: String,
}

// ─── VFIO Passthrough types ─────────────────────────────────────────

/// A VFIO BAR that has been mmap'd into userspace and mapped as a KVM memory slot.
#[derive(Debug)]
pub(crate) struct BarMappedRegion {
    pub guest_phys: u64,
    pub size: u64,
    pub host_ptr: *mut u8,
}
// SAFETY: BarMappedRegion owns a mmap region (host_ptr). It is only accessed
// from a single thread (no Sync) and ownership ensures proper cleanup in Drop.
unsafe impl Send for BarMappedRegion {}

/// Information about a VFIO PCI BAR region
#[derive(Debug, Clone)]
pub struct BarRegionInfo {
    /// BAR index (0-5 for PCI BARs, 6 for config, 7 for VGA)
    pub index: u32,
    /// Region size in bytes
    pub size: u64,
    /// Offset within the VFIO device fd for mmap
    pub offset: u64,
    /// Whether the region supports mmap
    pub can_mmap: bool,
    /// Whether the region is readable
    pub can_read: bool,
    /// Whether the region is writable
    pub can_write: bool,
}

/// MSI capability configuration read from VFIO PCI config space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiConfig {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u16,
    pub num_vectors: u32,
    pub is_64bit: bool,
    pub has_per_vector_mask: bool,
    pub enabled: bool,
}

/// Base KVM memory slot number for VFIO BAR mappings.
pub const VFIO_BAR_SLOT_BASE: u32 = 250;

/// Maximum number of VFIO BAR slots.
pub const VFIO_MAX_BAR_SLOTS: u32 = 10;

// ─── GPU Device Detection ───────────────────────────────────────────

/// Detect GPU devices on the system that could be used for VFIO passthrough.
pub fn detect_gpu_devices() -> Vec<GpuDeviceInfo> {
    let pci_dir = std::path::Path::new("/sys/bus/pci/devices");
    let mut devices = Vec::new();

    let entries = match std::fs::read_dir(pci_dir) {
        Ok(e) => e,
        Err(_) => return devices,
    };

    for entry in entries.flatten() {
        let bdf = entry.file_name();
        let bdf_str = bdf.to_string_lossy();

        let vendor_path = entry.path().join("vendor");
        let device_path = entry.path().join("device");
        let class_path = entry.path().join("class");

        let vendor = std::fs::read_to_string(&vendor_path).ok();
        let device = std::fs::read_to_string(&device_path).ok();
        let class_code = std::fs::read_to_string(&class_path).ok();

        let vendor_id = vendor
            .and_then(|s| u16::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok());
        let device_id = device
            .and_then(|s| u16::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok());
        let class_val = class_code
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok());

        let is_gpu = class_val.map(|c| (c & 0xFFFF00) == 0x030000).unwrap_or(false);
        if !is_gpu {
            continue;
        }

        let iommu_group = read_iommu_group(&entry.path());

        let name_path = entry.path().join("label");
        let name = std::fs::read_to_string(&name_path).unwrap_or_default();
        let name = name.trim().to_string();
        let name = if name.is_empty() {
            format!(
                "GPU {:04x}:{:04x}",
                vendor_id.unwrap_or(0),
                device_id.unwrap_or(0)
            )
        } else {
            name
        };

        if iommu_group != 0xFFFFFFFF && !bdf_str.starts_with("0000:00:0") {
            match check_iommu_group_complete(&bdf_str, iommu_group) {
                Ok((complete, unbound)) if !complete => {
                    tracing::warn!(
                        "GPU {} in IOMMU group {} — group INCOMPLETE. Unbound devices: {}",
                        bdf_str,
                        iommu_group,
                        unbound.join(", ")
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::trace!(
                        "Could not check IOMMU group {} for {}: {}",
                        iommu_group,
                        bdf_str,
                        e
                    );
                }
            }
        }

        devices.push(GpuDeviceInfo {
            pci_bdf: bdf_str.to_string(),
            iommu_group,
            vendor_id: vendor_id.unwrap_or(0),
            device_id: device_id.unwrap_or(0),
            name,
        });
    }

    devices
}

/// Read the IOMMU group number for a PCI device from sysfs.
fn read_iommu_group(dev_path: &std::path::Path) -> u32 {
    let group_path = dev_path.join("iommu_group");
    let link = match std::fs::read_link(&group_path) {
        Ok(l) => l,
        Err(_) => return 0xFFFFFFFF,
    };
    link.file_name()
        .and_then(|n| n.to_str())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0xFFFFFFFF)
}

/// Check if a GPU is bound to the vfio-pci driver
pub fn is_bound_to_vfio(bdf: &str) -> bool {
    let driver_link = std::path::Path::new("/sys/bus/pci/devices").join(bdf).join("driver");
    match std::fs::read_link(&driver_link) {
        Ok(link) => link
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == "vfio-pci")
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Check if all devices in an IOMMU group are bound to vfio-pci.
fn check_iommu_group_complete(
    bdf: &str,
    group_nr: u32,
) -> std::result::Result<(bool, Vec<String>), VfioError> {
    let group_sysfs = std::path::Path::new("/sys/kernel/iommu_groups")
        .join(group_nr.to_string())
        .join("devices");

    let entries = match std::fs::read_dir(&group_sysfs) {
        Ok(e) => e,
        Err(e) => return Err(VfioError::Io(e)),
    };

    let mut unbound_devices = Vec::new();
    for entry in entries.flatten() {
        let dev_bdf = entry.file_name();
        let dev_bdf_str = dev_bdf.to_string_lossy().to_string();
        if dev_bdf_str == bdf {
            continue;
        }

        let driver_path = entry.path().join("driver");
        if driver_path.exists() {
            let driver_link = std::fs::read_link(&driver_path).ok();
            let driver_name = match &driver_link {
                Some(link) => link
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                None => String::new(),
            };
            if driver_name != "vfio-pci" {
                unbound_devices.push(format!(
                    "{} (driver: {})",
                    dev_bdf_str,
                    if driver_name.is_empty() { "none" } else { &driver_name }
                ));
            }
        } else {
            unbound_devices.push(format!("{} (no driver)", dev_bdf_str));
        }
    }

    Ok((unbound_devices.is_empty(), unbound_devices))
}

/// Read the current driver name for a PCI device
pub(crate) fn read_driver_name(bdf: &str) -> String {
    let driver_link = std::path::Path::new("/sys/bus/pci/devices").join(bdf).join("driver");
    match std::fs::read_link(&driver_link) {
        Ok(link) => link
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("(unknown)")
            .to_string(),
        Err(_) => "(none)".to_string(),
    }
}
