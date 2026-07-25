//! VfioPassthroughBase — generic VFIO passthrough lifecycle
//!
//! Manages VFIO container, group, device fd lifecycle, KVM registration,
//! BAR mapping, MSI/INTx interrupt routing. GPU-type-specific operations
//! (power preinit, firmware loading) are delegated to `GpuBackend`.

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::ptr;

use tracing::{debug, error, info, trace, warn};

use crate::vfio::backend::{detect_gpu_backend, GpuBackend};
use crate::vfio::device::{
    errno_after_ioctl, BarMappedRegion, BarRegionInfo, GpuDeviceInfo, MsiConfig, Result, VfioError,
    VFIO_API_VERSION, VFIO_BAR_SLOT_BASE, VFIO_DEVICE_GET_IRQ_INFO, VFIO_DEVICE_GET_REGION_INFO,
    VFIO_DEVICE_RESET, VFIO_DEVICE_SET_IRQS, VFIO_GET_API_VERSION, VFIO_GROUP_GET_DEVICE_FD,
    VFIO_GROUP_SET_CONTAINER, VFIO_IRQ_SET_ACTION_TRIGGER, VFIO_IRQ_SET_DATA_EVENTFD,
    VFIO_IRQ_SET_DATA_NONE, VFIO_MAX_BAR_SLOTS, VFIO_PCI_BAR0_REGION_INDEX,
    VFIO_PCI_BAR1_REGION_INDEX, VFIO_PCI_BAR2_REGION_INDEX, VFIO_PCI_BAR3_REGION_INDEX,
    VFIO_PCI_BAR4_REGION_INDEX, VFIO_PCI_BAR5_REGION_INDEX, VFIO_PCI_CONFIG_REGION_INDEX,
    VFIO_PCI_INTX_IRQ_INDEX, VFIO_PCI_MSI_IRQ_INDEX, VFIO_PCI_VGA_REGION_INDEX,
    VFIO_REGION_INFO_FLAG_MMAP, VFIO_REGION_INFO_FLAG_READ, VFIO_REGION_INFO_FLAG_WRITE,
    VFIO_SET_IOMMU, VFIO_TYPE1V2_IOMMU, VFIO_TYPE1_IOMMU,
};
use crate::vfio::pci_config::{parse_msi_at, read_config_u32, write_config_u32};

// ─── VfioPassthroughBase ────────────────────────────────────────────

/// A VFIO GPU passthrough session — owns container, group, and device fds.
///
/// # Lifecycle
///
/// 1. `VfioPassthroughBase::probe()` — detect available GPU + IOMMU group
/// 2. `init(vm_fd)` — open VFIO container, attach group, set IOMMU, register
///    with KVM, and map GPU BARs as KVM memory slots for guest MMIO access
/// 3. `destroy()` — unmap BARs, close all fds, release GPU (Drop handles this)
///
/// GPU-type-specific operations (power preinit, firmware loading) are
/// delegated to a `GpuBackend` that is auto-detected from the device.
#[derive(Debug)]
pub struct VfioPassthroughBase {
    /// GPU device info
    pub device: GpuDeviceInfo,
    /// VFIO container fd (from /dev/vfio/vfio)
    container_fd: Option<std::fs::File>,
    /// VFIO group fd (from /dev/vfio/<group>)
    group_fd: Option<std::fs::File>,
    /// VFIO device fd (from VFIO_GROUP_GET_DEVICE_FD) — needed for BAR mmap and reset
    device_fd: Option<std::fs::File>,
    /// Information about PCI BAR regions (queried after init)
    bar_regions: Vec<BarRegionInfo>,
    /// Whether initialization succeeded
    initialized: bool,
    /// The VFIO file offset of the region that contains valid PCI config space.
    valid_config_region_offset: Option<u64>,
    /// Mapped VFIO BAR regions as KVM memory slots.
    mapped_bars: Vec<BarMappedRegion>,
    /// Auto-detected GPU backend for type-specific operations
    gpu_backend: Option<Box<dyn GpuBackend>>,
}

impl VfioPassthroughBase {
    /// Probe the system for a VFIO-compatible GPU and create a passthrough session.
    pub fn probe() -> Option<Self> {
        let devices = crate::vfio::device::detect_gpu_devices();
        if devices.is_empty() {
            info!("VFIO probe: no GPU devices found on this system");
            return None;
        }

        for device in &devices {
            if crate::vfio::device::is_bound_to_vfio(&device.pci_bdf) {
                info!(
                    "VFIO probe: found GPU '{}' at {} (IOMMU group {}) bound to vfio-pci",
                    device.name, device.pci_bdf, device.iommu_group
                );
                return Some(Self {
                    device: device.clone(),
                    container_fd: None,
                    group_fd: None,
                    device_fd: None,
                    bar_regions: Vec::new(),
                    initialized: false,
                    valid_config_region_offset: None,
                    mapped_bars: Vec::new(),
                    gpu_backend: None,
                });
            }
        }

        for device in &devices {
            let driver_name = crate::vfio::device::read_driver_name(&device.pci_bdf);
            info!(
                "VFIO probe: GPU '{}' at {} found but NOT bound to vfio-pci (current driver: {})",
                device.name, device.pci_bdf, driver_name,
            );
        }
        warn!(
            "VFIO: no GPU bound to vfio-pci driver. To enable GPU passthrough, \
             bind the GPU to vfio-pci driver first."
        );
        None
    }

    /// Initialize VFIO passthrough: open container, attach group, set IOMMU,
    /// get device fd, and register with KVM.
    pub fn init(&mut self, vm_fd: RawFd) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        // 1. Open VFIO container
        let container_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .map_err(|_| VfioError::NotAvailable)?;

        // Check API version
        unsafe {
            let ret = libc::ioctl(
                container_file.as_raw_fd(),
                VFIO_GET_API_VERSION as libc::c_ulong,
                0,
            );
            if ret < 0 {
                return Err(VfioError::Ioctl {
                    context: "VFIO_GET_API_VERSION".into(),
                    errno: errno_after_ioctl(),
                });
            }
            if (ret as u32) != VFIO_API_VERSION {
                return Err(VfioError::ApiVersion {
                    got: ret as u32,
                    expected: VFIO_API_VERSION,
                });
            }
        }

        // 2. Open IOMMU group fd
        let group_path_str = format!("/dev/vfio/{}", self.device.iommu_group);
        let group_path = Path::new(&group_path_str);
        if !group_path.exists() {
            return Err(VfioError::NotBoundToVfio(self.device.pci_bdf.clone()));
        }

        let group_file = fs::OpenOptions::new().read(true).write(true).open(group_path)?;

        // 3. Add group to container
        unsafe {
            let container_fd_val = container_file.as_raw_fd();
            let ret = libc::ioctl(
                group_file.as_raw_fd(),
                VFIO_GROUP_SET_CONTAINER as libc::c_ulong,
                &container_fd_val as *const _ as *const libc::c_void,
            );
            if ret < 0 {
                let errno = errno_after_ioctl();
                if errno == libc::EBUSY {
                    return Err(VfioError::GroupInUse(self.device.iommu_group));
                }
                return Err(VfioError::Ioctl {
                    context: "VFIO_GROUP_SET_CONTAINER".into(),
                    errno,
                });
            }
        }

        // 4. Set IOMMU type on the container
        unsafe {
            let ret = libc::ioctl(
                container_file.as_raw_fd(),
                VFIO_SET_IOMMU as libc::c_ulong,
                VFIO_TYPE1V2_IOMMU as libc::c_ulong,
            );
            if ret < 0 {
                let errno = errno_after_ioctl();
                if errno == libc::EINVAL {
                    let ret2 = libc::ioctl(
                        container_file.as_raw_fd(),
                        VFIO_SET_IOMMU as libc::c_ulong,
                        VFIO_TYPE1_IOMMU as libc::c_ulong,
                    );
                    if ret2 < 0 {
                        return Err(VfioError::Ioctl {
                            context: "VFIO_SET_IOMMU (Type1)".into(),
                            errno: errno_after_ioctl(),
                        });
                    }
                } else {
                    return Err(VfioError::Ioctl {
                        context: "VFIO_SET_IOMMU (Type1v2)".into(),
                        errno,
                    });
                }
            }
        }

        // 5. Get device fd from the group
        let dev_fd = unsafe {
            let bdf_cstr = CString::new(self.device.pci_bdf.as_str())?;
            let ret = libc::ioctl(
                group_file.as_raw_fd(),
                VFIO_GROUP_GET_DEVICE_FD as libc::c_ulong,
                bdf_cstr.as_ptr() as *const libc::c_void,
            );
            if ret < 0 {
                return Err(VfioError::Ioctl {
                    context: format!("VFIO_GROUP_GET_DEVICE_FD({})", self.device.pci_bdf),
                    errno: errno_after_ioctl(),
                });
            }
            let dev_file = std::fs::File::from_raw_fd(ret);
            dev_file
        };

        // 6. Optionally reset the GPU device
        if true {
            unsafe {
                let ret = libc::ioctl(dev_fd.as_raw_fd(), VFIO_DEVICE_RESET as libc::c_ulong, 0);
                if ret < 0 {
                    let errno = errno_after_ioctl();
                    warn!(
                        "VFIO_DEVICE_RESET returned {} (errno={}) — GPU may be in unclean state",
                        ret, errno
                    );
                } else {
                    info!("GPU device reset complete — clean state for nvidia.ko");
                }
            }
        } else {
            info!("VFIO_DEVICE_RESET skipped — preserving GPU power state");
        }

        // 7. Query PCI BAR regions via VFIO_DEVICE_GET_REGION_INFO
        let bar_regions = self.query_bar_regions(&dev_fd)?;

        // 7b. Find which region contains valid PCI config space
        let config_offset = self.find_config_region(&dev_fd, &bar_regions);
        if let Some(off) = config_offset {
            info!(
                "VFIO: config space found at region offset 0x{off:x} ({} regions scanned)",
                bar_regions.len()
            );
        } else {
            warn!(
                "VFIO: no valid config space found in any of {} regions — \
                 PCI proxy will be unavailable",
                bar_regions.len()
            );
        }

        // 7c. Store bar_regions and device_fd so the backend can access them
        self.bar_regions = bar_regions;
        self.device_fd = Some(dev_fd);

        // 7d. Auto-detect GPU backend and perform power pre-init
        self.gpu_backend = detect_gpu_backend(&self.device);
        info!(
            "VFIO: GPU backend: {}",
            self.gpu_backend
                .as_ref()
                .map(|b| b.name())
                .unwrap_or("none (generic PCI)")
        );

        if let Some(ref backend) = self.gpu_backend {
            if let Err(e) = backend.power_preinit(self) {
                warn!(
                    "VFIO: GPU power pre-init failed (non-fatal): {}",
                    e
                );
            }
        }

        // 7e. Ensure PCI bus mastering is enabled on the physical device.
        if let Some(cfg_off) = config_offset {
            let dev_raw = match self.device_fd() {
                Some(fd) => fd,
                None => {
                    warn!("VFIO: device_fd lost — cannot enable bus mastering");
                    return Err(VfioError::Ioctl {
                        context: "device_fd unavailable for bus mastering enable".into(),
                        errno: 0,
                    });
                }
            };
            let cmd = read_config_u32(dev_raw, cfg_off, 0x04, 2) as u16;
            let want_bm = cmd | 0x0004;
            if cmd != want_bm {
                let ok = write_config_u32(dev_raw, cfg_off, 0x04, want_bm as u32, 2);
                let after = read_config_u32(dev_raw, cfg_off, 0x04, 2) as u16;
                info!(
                    "VFIO: PCI bus mastering {} (cmd: 0x{cmd:04x} → 0x{after:04x})",
                    if ok { "ENABLED" } else { "WRITE FAILED" }
                );
                if !ok {
                    warn!("VFIO: cannot enable bus mastering — Falcon DMA will not work");
                }
            } else {
                info!("VFIO: PCI bus mastering already enabled (cmd=0x{cmd:04x})");
            }
        } else {
            warn!("VFIO: no config region — cannot check/enable bus mastering");
        }

        // 8. Register the VFIO group with KVM
        unsafe {
            self.register_with_kvm(vm_fd, group_file.as_raw_fd())?;
        }

        self.container_fd = Some(container_file);
        self.group_fd = Some(group_file);
        self.valid_config_region_offset = config_offset;

        self.initialized = true;

        info!(
            "VFIO passthrough initialized: GPU {} (IOMMU group {})",
            self.device.name, self.device.iommu_group
        );
        Ok(())
    }

    /// Load GPU firmware (delegated to the backend).
    pub fn load_gpu_firmware(&self) -> Result<()> {
        match self.gpu_backend {
            Some(ref backend) => backend.load_firmware(self),
            None => Ok(()),
        }
    }

    /// Query PCI BAR regions via VFIO_DEVICE_GET_REGION_INFO.
    fn query_bar_regions(&self, dev_fd: &std::fs::File) -> Result<Vec<BarRegionInfo>> {
        #[repr(C)]
        #[derive(Debug, Default)]
        struct VfioRegionInfo {
            argsz: u32,
            flags: u32,
            index: u32,
            cap_offset: u32,
            size: u64,
            offset: u64,
        }

        let bar_indices = [
            (VFIO_PCI_BAR0_REGION_INDEX, "BAR0"),
            (VFIO_PCI_BAR1_REGION_INDEX, "BAR1"),
            (VFIO_PCI_BAR2_REGION_INDEX, "BAR2"),
            (VFIO_PCI_BAR3_REGION_INDEX, "BAR3"),
            (VFIO_PCI_BAR4_REGION_INDEX, "BAR4"),
            (VFIO_PCI_BAR5_REGION_INDEX, "BAR5"),
            (VFIO_PCI_CONFIG_REGION_INDEX, "Config"),
            (VFIO_PCI_VGA_REGION_INDEX, "VGA"),
        ];

        let mut regions = Vec::new();

        for &(index, name) in &bar_indices {
            let mut info = VfioRegionInfo {
                argsz: std::mem::size_of::<VfioRegionInfo>() as u32,
                index,
                ..Default::default()
            };

            let ret = unsafe {
                libc::ioctl(
                    dev_fd.as_raw_fd(),
                    VFIO_DEVICE_GET_REGION_INFO as libc::c_ulong,
                    &mut info as *mut _ as *mut libc::c_void,
                )
            };

            if ret < 0 {
                let errno = unsafe { *libc::__errno_location() };
                trace!(
                    "VFIO: region {} ({}) query failed (errno={}) — skipping",
                    index, name, errno
                );
                continue;
            }

            let region = BarRegionInfo {
                index: info.index,
                size: info.size,
                offset: info.offset,
                can_mmap: (info.flags & VFIO_REGION_INFO_FLAG_MMAP) != 0,
                can_read: (info.flags & VFIO_REGION_INFO_FLAG_READ) != 0,
                can_write: (info.flags & VFIO_REGION_INFO_FLAG_WRITE) != 0,
            };

            info!(
                "VFIO: region {} ({}) — size={}, offset={:#x}, mmap={}, r/w={}/{}",
                index, name, region.size, region.offset, region.can_mmap,
                region.can_read, region.can_write
            );

            regions.push(region);
        }

        Ok(regions)
    }

    /// Scan VFIO regions to find which one contains valid PCI config space.
    fn find_config_region(&self, dev_fd: &std::fs::File, regions: &[BarRegionInfo]) -> Option<u64> {
        use std::os::unix::fs::FileExt;

        let known_vendor = self.device.vendor_id;
        let known_device = self.device.device_id;

        let config_candidates = [6u32, 7u32];

        let read_u16 = |fd: &std::fs::File, region_offset: u64, reg_offset: u64| -> Option<u16> {
            let mut buf = [0u8; 2];
            fd.read_at(&mut buf, region_offset + reg_offset).ok().and_then(|n| {
                if n == 2 { Some(u16::from_le_bytes(buf)) } else { None }
            })
        };

        for &idx in &config_candidates {
            let region = match regions.iter().find(|r| r.index == idx) {
                Some(r) => r,
                None => continue,
            };
            if region.size < 256 {
                trace!("VFIO: config candidate region {idx}: size={} — too small", region.size);
                continue;
            }

            let vendor = match read_u16(dev_fd, region.offset, 0) {
                Some(v) => v,
                None => {
                    trace!("VFIO: config candidate region {idx}: couldn't read vendor");
                    continue;
                }
            };
            let device = read_u16(dev_fd, region.offset, 2).unwrap_or(0);
            let header_type = read_u16(dev_fd, region.offset, 0x0e).unwrap_or(0xFFFF);

            let header_ok = (header_type & 0xFF) == 0x00 || (header_type & 0xFF) == 0x80;
            let vendor_ok = vendor != 0 && vendor != 0xFFFF && vendor != 0xAA55;
            let known_match = known_vendor != 0 && vendor == known_vendor && device == known_device;

            if known_match {
                info!(
                    "VFIO: config space at region {} (offset 0x{:x}) — matches sysfs {known_vendor:04x}:{known_device:04x}",
                    idx, region.offset
                );
                return Some(region.offset);
            }
            if vendor_ok && header_ok {
                info!(
                    "VFIO: config space candidate at region {} (offset 0x{:x}, vendor=0x{vendor:04x}, device=0x{device:04x})",
                    idx, region.offset
                );
                return Some(region.offset);
            }
        }

        // Fallback: scan ALL regions
        trace!("VFIO: fallback scanning all {} regions", regions.len());
        for region in regions {
            if region.size < 256 {
                continue;
            }

            let vendor = match read_u16(dev_fd, region.offset, 0) {
                Some(v) => v,
                None => continue,
            };
            let device = read_u16(dev_fd, region.offset, 2).unwrap_or(0);
            let header_type = read_u16(dev_fd, region.offset, 0x0e).unwrap_or(0xFFFF);

            let header_ok = (header_type & 0xFF) == 0x00 || (header_type & 0xFF) == 0x80;
            let vendor_ok = vendor != 0 && vendor != 0xFFFF && vendor != 0xAA55;
            let known_match = known_vendor != 0 && vendor == known_vendor && device == known_device;

            if known_match {
                info!(
                    "VFIO: config space at region {} (offset 0x{:x}) — matches sysfs {known_vendor:04x}:{known_device:04x}",
                    region.index, region.offset
                );
                return Some(region.offset);
            }
            if vendor_ok && header_ok {
                info!(
                    "VFIO: config space candidate at region {} (offset 0x{:x}, vendor=0x{vendor:04x}, device=0x{device:04x})",
                    region.index, region.offset
                );
                return Some(region.offset);
            }
        }

        warn!("VFIO: no valid PCI config space found in any of {} regions", regions.len());
        None
    }

    /// Register the VFIO group with KVM via KVM_DEV_VFIO_GROUP.
    ///
    /// # Safety
    ///
    /// `vm_fd` must be a valid KVM VM fd. `group_fd` must be a valid VFIO group fd.
    unsafe fn register_with_kvm(&self, vm_fd: RawFd, group_fd: RawFd) -> Result<()> {
        use crate::kvm;

        let mut cd = kvm::KvmCreateDevice {
            type_: kvm::KVM_DEV_TYPE_VFIO,
            fd: -1,
            flags: 0,
        };

        unsafe {
            let ret = libc::ioctl(
                vm_fd,
                kvm::KVM_CREATE_DEVICE as libc::c_ulong,
                &mut cd as *mut _ as *mut libc::c_void,
            );
            if ret < 0 {
                return Err(VfioError::Kvm(format!(
                    "KVM_CREATE_DEVICE(VFIO) failed: errno={}",
                    errno_after_ioctl()
                )));
            }
        }

        if cd.fd < 0 {
            return Err(VfioError::Kvm(
                "KVM_CREATE_DEVICE returned invalid fd".into(),
            ));
        }

        let kvm_dev_file = unsafe { std::fs::File::from_raw_fd(cd.fd) };

        let kda = kvm::KvmDeviceAttr {
            flags: 0,
            group: kvm::KVM_DEV_VFIO_GROUP,
            attr: kvm::KVM_DEV_VFIO_GROUP_ADD,
            addr: &group_fd as *const _ as u64,
        };

        unsafe {
            let ret = libc::ioctl(
                kvm_dev_file.as_raw_fd(),
                kvm::KVM_SET_DEVICE_ATTR as libc::c_ulong,
                &kda as *const _ as *const libc::c_void,
            );
            if ret < 0 {
                let errno = errno_after_ioctl();
                drop(kvm_dev_file);
                return Err(VfioError::Kvm(format!(
                    "KVM_SET_DEVICE_ATTR(VFIO_GROUP_ADD) failed: errno={}",
                    errno
                )));
            }
        }

        drop(kvm_dev_file);

        info!("VFIO group {} registered with KVM", self.device.iommu_group);
        Ok(())
    }

    // ─── INTx Interrupt Routing ─────────────────────────────────────

    /// Set up VFIO INTx interrupt routing via irqfd.
    pub fn setup_intx_irqfd(&self, vm: &crate::kvm::Vm, gsi: u32) -> Result<()> {
        let dev_fd = self.device_fd().ok_or(VfioError::NotAvailable)?;

        let irq_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        if irq_fd < 0 {
            return Err(VfioError::Io(std::io::Error::last_os_error()));
        }

        let irq_set_size = 20u32 + 4u32;
        let mut irq_set = vec![0u8; irq_set_size as usize];

        unsafe {
            let ptr = irq_set.as_mut_ptr() as *mut u32;
            ptr::write(ptr.add(0), irq_set_size);
            ptr::write(
                ptr.add(1),
                VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
            );
            ptr::write(ptr.add(2), VFIO_PCI_INTX_IRQ_INDEX);
            ptr::write(ptr.add(3), 0);
            ptr::write(ptr.add(4), 1);
            ptr::write(ptr.add(5), irq_fd as u32);
        }

        let ret = unsafe {
            libc::ioctl(
                dev_fd,
                VFIO_DEVICE_SET_IRQS as libc::c_ulong,
                irq_set.as_ptr() as *const libc::c_void,
            )
        };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::close(irq_fd); }
            return Err(VfioError::Kvm(format!(
                "VFIO_DEVICE_SET_IRQS(INTX) failed: errno={}",
                errno,
            )));
        }

        let irqfd_result = unsafe { vm.set_irqfd(irq_fd, gsi, None) };
        match irqfd_result {
            Ok(()) => {
                unsafe { libc::close(irq_fd); }
            }
            Err(e) => {
                unsafe { libc::close(irq_fd); }
                return Err(VfioError::Kvm(format!("KVM_IRQFD failed: {}", e)));
            }
        }

        info!("VFIO: INTX irqfd set up for GSI {}", gsi);
        Ok(())
    }

    /// Disable INTx on the VFIO device (count=0, DATA_NONE).
    pub fn disable_intx(&self) -> Result<()> {
        let dev_fd = self.device_fd().ok_or(VfioError::NotAvailable)?;

        let sz = 20u32;
        let mut irq_set = vec![0u8; sz as usize];

        unsafe {
            let ptr = irq_set.as_mut_ptr() as *mut u32;
            ptr::write(ptr.add(0), sz);
            ptr::write(ptr.add(1), VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER);
            ptr::write(ptr.add(2), VFIO_PCI_INTX_IRQ_INDEX);
            ptr::write(ptr.add(3), 0);
            ptr::write(ptr.add(4), 0);
        }

        let ret = unsafe {
            libc::ioctl(
                dev_fd,
                VFIO_DEVICE_SET_IRQS as libc::c_ulong,
                irq_set.as_ptr() as *const libc::c_void,
            )
        };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(VfioError::Kvm(format!(
                "VFIO_DEVICE_SET_IRQS(INTX, disable) failed: errno={}",
                errno,
            )));
        }

        info!("VFIO: INTX disabled (clearing VFIO internal state for MSI)");
        Ok(())
    }

    // ─── MSI Interrupt Routing ──────────────────────────────────────

    /// Query the maximum number of MSI interrupt vectors VFIO supports for this device.
    pub fn query_msi_vector_count(&self) -> u32 {
        let dev_fd = match self.device_fd() {
            Some(fd) => fd,
            None => return 0,
        };

        #[allow(dead_code)]
        struct VfioIrqInfoRaw {
            argsz: u32,
            flags: u32,
            index: u32,
            count: u32,
            _pad: [u32; 7],
        }

        let mut irq_info = VfioIrqInfoRaw {
            argsz: std::mem::size_of::<VfioIrqInfoRaw>() as u32,
            flags: 0,
            index: VFIO_PCI_MSI_IRQ_INDEX,
            count: 0,
            _pad: [0; 7],
        };

        let ret = unsafe {
            libc::ioctl(
                dev_fd,
                VFIO_DEVICE_GET_IRQ_INFO as libc::c_ulong,
                &mut irq_info as *mut _ as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return 0;
        }
        irq_info.count
    }

    /// Set up VFIO MSI eventfds and wire them to the KVM irqchip.
    pub fn setup_msi_irqfds(&self, vm: &crate::kvm::Vm, gsi_base: u32, num_vectors: u32) -> Result<()> {
        if num_vectors == 0 {
            return Ok(());
        }

        let dev_fd = self.device_fd().ok_or(VfioError::NotAvailable)?;

        let mut irq_fds: Vec<i32> = Vec::with_capacity(num_vectors as usize);
        for _ in 0..num_vectors {
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
            if fd < 0 {
                for &old_fd in &irq_fds {
                    unsafe { libc::close(old_fd); }
                }
                return Err(VfioError::Io(std::io::Error::last_os_error()));
            }
            irq_fds.push(fd);
        }

        let data_size = 4u32 * num_vectors;
        let irq_set_size = 20u32 + data_size;
        let mut irq_set = vec![0u8; irq_set_size as usize];

        unsafe {
            let ptr = irq_set.as_mut_ptr() as *mut u32;
            ptr::write(ptr.add(0), irq_set_size);
            ptr::write(
                ptr.add(1),
                VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
            );
            ptr::write(ptr.add(2), VFIO_PCI_MSI_IRQ_INDEX);
            ptr::write(ptr.add(3), 0);
            ptr::write(ptr.add(4), num_vectors);
            for (i, &fd) in irq_fds.iter().enumerate() {
                ptr::write(ptr.add(5 + i), fd as u32);
            }
        }

        let ret = unsafe {
            libc::ioctl(
                dev_fd,
                VFIO_DEVICE_SET_IRQS as libc::c_ulong,
                irq_set.as_ptr() as *const libc::c_void,
            )
        };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            for fd in &irq_fds {
                unsafe { libc::close(*fd); }
            }
            return Err(VfioError::Kvm(format!(
                "VFIO_DEVICE_SET_IRQS(MSI, count={}) failed: errno={}",
                num_vectors, errno,
            )));
        }

        for (i, &irq_fd) in irq_fds.iter().enumerate() {
            let gsi = gsi_base + i as u32;
            if let Err(e) = unsafe { vm.set_irqfd(irq_fd, gsi, None) } {
                for &fd in irq_fds.iter().skip(i) {
                    unsafe { libc::close(fd); }
                }
                return Err(VfioError::Kvm(format!(
                    "KVM_IRQFD(gsi={}) failed for MSI vector {}: {}",
                    gsi, i, e
                )));
            }
        }

        for &fd in &irq_fds {
            unsafe { libc::close(fd); }
        }
        info!(
            "VFIO: MSI irqfds set up for GSIs {}-{} ({} vectors)",
            gsi_base,
            gsi_base + num_vectors - 1,
            num_vectors,
        );
        Ok(())
    }

    // ─── BAR Mapping ────────────────────────────────────────────────

    /// Read a BAR address from the VFIO device's PCI config space.
    fn read_guest_bar_addr(&self, bar_index: u32) -> u64 {
        let config_off = match self.config_region_offset() {
            Some(off) => off,
            None => return 0,
        };
        let dev_fd = match self.device_fd() {
            Some(fd) => fd,
            None => return 0,
        };

        let bar_reg = 0x10 + bar_index * 4;

        let mut raw_val: u32 = 0;
        let ret = unsafe {
            libc::pread(
                dev_fd,
                &mut raw_val as *mut u32 as *mut libc::c_void,
                4,
                (config_off + bar_reg as u64) as i64,
            )
        };
        if ret != 4 {
            return 0;
        }

        if raw_val & 1 != 0 {
            return 0;
        }

        let base = (raw_val & 0xFFFFFFF0) as u64;

        let bar_type = (raw_val >> 1) & 0x3;
        if bar_type == 2 {
            let mut upper: u32 = 0;
            let ret = unsafe {
                libc::pread(
                    dev_fd,
                    &mut upper as *mut u32 as *mut libc::c_void,
                    4,
                    (config_off + bar_reg as u64 + 4) as i64,
                )
            };
            if ret != 4 {
                warn!("VFIO: failed to read BAR{} upper 32 bits — returning lower only", bar_index);
                return base;
            }
            (upper as u64) << 32 | base
        } else {
            base
        }
    }

    /// Write a guest-physical address for a PCI BAR to VFIO config space.
    fn write_guest_bar_addr(&self, bar_index: u32, guest_addr: u64) -> bool {
        let config_off = match self.config_region_offset() {
            Some(off) => off,
            None => return false,
        };
        let dev_fd = match self.device_fd() {
            Some(fd) => fd,
            None => return false,
        };

        let bar_reg = 0x10 + bar_index * 4;

        let mut raw_val: u32 = 0;
        let ret = unsafe {
            libc::pread(
                dev_fd,
                &mut raw_val as *mut u32 as *mut libc::c_void,
                4,
                (config_off + bar_reg as u64) as i64,
            )
        };
        if ret != 4 {
            return false;
        }

        if raw_val & 1 != 0 {
            return false;
        }

        let bar_type = (raw_val >> 1) & 0x3;

        let lower = (guest_addr & 0xFFFFFFF0) as u32 | (raw_val & 0xF);
        if !write_config_u32(dev_fd, config_off, bar_reg as u16, lower, 4) {
            warn!("VFIO: failed to write BAR{} lower address 0x{:08x}", bar_index, lower);
            return false;
        }

        if bar_type == 2 {
            let upper = (guest_addr >> 32) as u32;
            if !write_config_u32(dev_fd, config_off, (bar_reg + 4) as u16, upper, 4) {
                warn!("VFIO: failed to write BAR{} upper address 0x{:08x}", bar_index, upper);
                return false;
            }
        }

        true
    }

    /// Pre-assign BAR addresses for all mmap-able VFIO regions.
    pub fn preassign_guest_bar_addresses(&self) -> Result<Vec<(u32, u64, u64)>> {
        let mut assigned = Vec::new();
        let mut next_64bit: u64 = 0x100_0000_000;
        let mut next_32bit: u64 = 0xE000_0000;
        let dev_fd = match self.device_fd() {
            Some(fd) => fd,
            None => return Err(VfioError::NotAvailable),
        };
        let config_off = match self.config_region_offset() {
            Some(off) => off,
            None => return Err(VfioError::NotAvailable),
        };

        for bar in &self.bar_regions {
            if bar.index > 5 || !bar.can_mmap || bar.size == 0 {
                continue;
            }

            let bar_reg = 0x10 + bar.index * 4;

            let mut raw_bar: u32 = 0;
            let ret = unsafe {
                libc::pread(
                    dev_fd,
                    &mut raw_bar as *mut u32 as *mut libc::c_void,
                    4,
                    (config_off + bar_reg as u64) as i64,
                )
            };
            if ret != 4 {
                warn!("VFIO: could not read BAR{} config register", bar.index);
                continue;
            }
            if raw_bar & 1 != 0 {
                info!("VFIO: BAR{} is an I/O BAR, skipping", bar.index);
                continue;
            }

            let bar_type = (raw_bar >> 1) & 0x3;
            let is_64bit = bar_type == 2;

            let (addr, next_addr) = if is_64bit {
                let align = 0x4000_0000u64.max(bar.size).next_power_of_two();
                let base = if next_64bit < align { align } else { next_64bit };
                let addr = (base + align - 1) & !(align - 1);
                (addr, addr + bar.size)
            } else {
                let align = 0x1000u64.max(bar.size).next_power_of_two();
                let base = if next_32bit < align { align } else { next_32bit };
                let addr = (base + align - 1) & !(align - 1);
                if addr > 0xFFFF_FFFF {
                    warn!("VFIO: BAR{} is 32-bit but address {:#x} exceeds 4 GB — skipping", bar.index, addr);
                    continue;
                }
                (addr, addr + bar.size)
            };

            if !self.write_guest_bar_addr(bar.index, addr) {
                warn!("VFIO: failed to write pre-assigned address for BAR{} at GPA {:#x}", bar.index, addr);
                continue;
            }

            if is_64bit {
                next_64bit = next_addr;
            } else {
                next_32bit = next_addr;
            }

            info!(
                "VFIO: pre-assigned BAR{} at GPA {:#x} (size {}, 64-bit={})",
                bar.index, addr, bar.size, is_64bit
            );
            assigned.push((bar.index, addr, bar.size));
        }

        Ok(assigned)
    }

    /// Unmap and clear all previously mapped VFIO BAR regions.
    pub fn clear_mapped_bars(&mut self) {
        let count = self.mapped_bars.len();
        for bar in self.mapped_bars.drain(..) {
            trace!("VFIO: munmap pre-boot BAR at {:#x} (size {})", bar.guest_phys, bar.size);
            unsafe {
                libc::munmap(bar.host_ptr as *mut libc::c_void, bar.size as usize);
            }
        }
        info!("VFIO: cleared {} pre-boot BAR mappings", count);
    }

    /// Map VFIO BAR regions as KVM memory slots using guest-assigned addresses.
    pub fn map_guest_bar_slots(&mut self, vm_fd: RawFd) -> Result<()> {
        let dev_fd = match self.device_fd() {
            Some(fd) => fd,
            None => return Err(VfioError::NotAvailable),
        };

        let mut slot = VFIO_BAR_SLOT_BASE;
        let mut mapped_count = 0u32;

        for bar in &self.bar_regions {
            if bar.index > 5 || !bar.can_mmap || bar.size == 0 {
                continue;
            }

            let guest_phys = self.read_guest_bar_addr(bar.index);
            if guest_phys == 0 {
                info!("VFIO: BAR{} not mapped (unassigned or I/O BAR)", bar.index);
                continue;
            }

            eprintln!("[VFIO] map_guest_bar_slots: BAR{} guest_phys={:#x} size={} offset={:#x}",
                bar.index, guest_phys, bar.size, bar.offset);
            info!(
                "VFIO: mapping BAR{} at guest GPA {:#x} (size {}, VFIO offset {:#x})",
                bar.index, guest_phys, bar.size, bar.offset
            );

            let host_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bar.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    dev_fd,
                    bar.offset as i64,
                )
            };

            if host_ptr == libc::MAP_FAILED {
                warn!(
                    "VFIO: failed to mmap BAR{} at VFIO offset {:#x}: {}",
                    bar.index,
                    bar.offset,
                    std::io::Error::last_os_error()
                );
                continue;
            }

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
                    guest_phys_addr: guest_phys,
                    memory_size: bar.size,
                    userspace_addr: host_ptr as u64,
                };

                libc::ioctl(
                    vm_fd,
                    crate::kvm::KVM_SET_USER_MEMORY_REGION as libc::c_ulong,
                    &region as *const _ as *const libc::c_void,
                )
            };

            if ret < 0 {
                let errno = unsafe { *libc::__errno_location() };
                warn!(
                    "VFIO: KVM_SET_USER_MEMORY_REGION failed for BAR{} at {:#x}: errno={}",
                    bar.index, guest_phys, errno
                );
                unsafe { libc::munmap(host_ptr, bar.size as usize); }
                continue;
            }

            info!(
                "VFIO: -> mapped BAR{} at guest GPA {:#x} via KVM slot {}",
                bar.index, guest_phys, slot
            );

            self.mapped_bars.push(BarMappedRegion {
                guest_phys,
                size: bar.size,
                host_ptr: host_ptr as *mut u8,
            });
            mapped_count += 1;

            slot += 1;
            if slot >= VFIO_BAR_SLOT_BASE + VFIO_MAX_BAR_SLOTS {
                warn!("VFIO: ran out of BAR slots (max {})", VFIO_MAX_BAR_SLOTS);
                break;
            }
        }

        Ok(())
    }

    // ─── Accessors ──────────────────────────────────────────────────

    /// Check if this VFIO session has been initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the GPU device info
    pub fn device_info(&self) -> &GpuDeviceInfo {
        &self.device
    }

    /// Get the VFIO file offset for the PCI config space region.
    pub fn config_region_offset(&self) -> Option<u64> {
        self.valid_config_region_offset
    }

    /// Get information about PCI BAR regions.
    pub fn bar_regions(&self) -> &[BarRegionInfo] {
        &self.bar_regions
    }

    /// Get the VFIO device fd for low-level operations (BAR mmap, reset).
    pub fn device_fd(&self) -> Option<RawFd> {
        self.device_fd.as_ref().map(|f| f.as_raw_fd())
    }

    /// Duplicate the VFIO device fd for PCI config space proxying.
    pub fn dup_device_fd(&self) -> Option<std::fs::File> {
        self.device_fd.as_ref().and_then(|f| {
            let raw = f.as_raw_fd();
            let duped = unsafe { libc::dup(raw) };
            if duped < 0 {
                error!("VFIO: dup(device_fd) failed: {}", std::io::Error::last_os_error());
                None
            } else {
                Some(unsafe { std::fs::File::from_raw_fd(duped) })
            }
        })
    }

    /// Read MSI capability configuration from VFIO PCI config space.
    pub fn read_msi_config(&self) -> Option<MsiConfig> {
        let config_off = self.config_region_offset()?;
        let dev_fd = self.device_fd()?;

        let status = read_config_u32(dev_fd, config_off, 0x06, 2);
        if status & (1u32 << 4) == 0 {
            return None;
        }

        let cap_ptr = read_config_u32(dev_fd, config_off, 0x34, 1) as u8;
        if cap_ptr < 0x40 {
            return None;
        }

        let mut curr = cap_ptr as u16;
        for _ in 0..64 {
            if !(0x40..0xFE).contains(&curr) {
                return None;
            }

            let cap_id = read_config_u32(dev_fd, config_off, curr, 1) as u8;

            if cap_id == 0x05 {
                return parse_msi_at(dev_fd, config_off, curr);
            }

            let next = read_config_u32(dev_fd, config_off, curr + 1, 1) as u8;
            if next == 0 {
                return None;
            }
            curr = next as u16;
        }

        None
    }

    /// Disable MSI on the physical device by clearing the MSI Enable bit.
    pub fn disable_msi_on_physical_device(&self) -> bool {
        let config_off = match self.config_region_offset() {
            Some(off) => off,
            None => {
                warn!("disable_msi_on_physical_device: no config region offset");
                return false;
            }
        };
        let dev_fd = match self.device_fd() {
            Some(fd) => fd,
            None => {
                warn!("disable_msi_on_physical_device: no device fd");
                return false;
            }
        };

        let status = read_config_u32(dev_fd, config_off, 0x06, 2);
        if status & (1u32 << 4) == 0 {
            return false;
        }

        let cap_ptr = read_config_u32(dev_fd, config_off, 0x34, 1) as u8;
        if cap_ptr < 0x40 {
            return false;
        }

        let mut curr = cap_ptr as u16;
        for _ in 0..64 {
            if !(0x40..0xFE).contains(&curr) {
                return false;
            }
            let cap_id = read_config_u32(dev_fd, config_off, curr, 1) as u8;
            if cap_id == 0x05 {
                let msg_ctrl = read_config_u32(dev_fd, config_off, curr + 2, 2);
                if msg_ctrl & 1 == 0 {
                    return true;
                }
                let new_ctrl = msg_ctrl & !1u32;
                let ok = write_config_u32(dev_fd, config_off, curr + 2, new_ctrl, 2);
                return ok;
            }
            let next = read_config_u32(dev_fd, config_off, curr + 1, 1) as u8;
            if next == 0 {
                return false;
            }
            curr = next as u16;
        }
        false
    }

    // ─── Lifecycle ──────────────────────────────────────────────────

    /// Destroy the VFIO session and release all resources.
    pub fn destroy(&mut self) {
        if !self.initialized {
            return;
        }
        self.initialized = false;

        for bar in self.mapped_bars.drain(..) {
            trace!("VFIO: munmap BAR at {:#x} (size {})", bar.guest_phys, bar.size);
            unsafe {
                libc::munmap(bar.host_ptr as *mut libc::c_void, bar.size as usize);
            }
        }

        if let Some(ref dev_fd) = self.device_fd {
            unsafe {
                let ret = libc::ioctl(dev_fd.as_raw_fd(), VFIO_DEVICE_RESET as libc::c_ulong, 0);
                if ret != 0 {
                    warn!(
                        "VFIO_DEVICE_RESET returned {} (errno={}) — GPU state may persist",
                        ret,
                        *libc::__errno_location()
                    );
                } else {
                    info!("GPU device reset complete");
                }
            }
        }

        self.device_fd = None;
        self.group_fd = None;
        self.container_fd = None;
        self.bar_regions.clear();
        self.gpu_backend = None;
        info!("VFIO passthrough destroyed for GPU {}", self.device.name);
    }
}

impl Drop for VfioPassthroughBase {
    fn drop(&mut self) {
        self.destroy();
    }
}
