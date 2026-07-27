//! KVM fd lifecycle — raw ioctl layer for KVM API
//!
//! Manages `/dev/kvm` fd, creates VMs and VCPUs, handles memory mapping.
//!
//! # Safety
//! This module uses raw `libc::ioctl` to interact with the KVM kernel module.
//! All unsafe blocks are documented with `// SAFETY:`.

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, RawFd, OwnedFd};
use std::ptr;

use thiserror::Error;

// ─── Generic KVM ioctl request codes ──────────────────────────────────
//
// These are architecture-independent KVM ioctls (not x86-specific).
// x86-specific ioctls (KVM_GET_REGS, KVM_CREATE_IRQCHIP, etc.) are
// defined in `crate::arch::x86_64::kvm_types` and re-exported here.
//
// SAFETY: These constants come from the Linux kernel UAPI header.
// They are compile-time constants, safe to define.
//
// On x86_64 Linux, _IO(KVMIO, nr) = (0xAE << 8) | nr
#[allow(dead_code)]
const KVM_GET_API_VERSION: u64 = 0x0000ae00u64;       // _IO(KVMIO, 0x00)
#[allow(dead_code)]
const KVM_CREATE_VM: u64 = 0x0000ae01u64;              // _IO(KVMIO, 0x01)
#[allow(dead_code)]
const KVM_CHECK_EXTENSION: u64 = 0x0000ae03u64;        // _IO(KVMIO, 0x03)
#[allow(dead_code)]
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0x0000ae04u64;     // _IO(KVMIO, 0x04)
#[allow(dead_code)]
const KVM_CREATE_VCPU: u64 = 0x0000ae41u64;             // _IO(KVMIO, 0x41)
#[allow(dead_code)]
pub(crate) const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020ae46u64;  // _IOW(KVMIO, 0x46, 32)
#[allow(dead_code)]
const KVM_RUN: u64 = 0x0000ae80u64;                     // _IO(KVMIO, 0x80)

// ─── Re-export arch-specific KVM types from arch module ────────────
pub use crate::arch::kvm_types::*;

/// Errors originating from KVM ioctl operations
#[derive(Error, Debug)]
pub enum KvmError {
    #[error("KVM ioctl failed: {context} — errno {errno}")]
    Ioctl { context: String, errno: i32 },
    #[error("Cannot open /dev/kvm: {0}")]
    Open(#[from] std::io::Error),
    #[error("KVM API version mismatch: got {got}, expected {expected}")]
    ApiVersion { got: i32, expected: i32 },
    #[error("KVM capability {cap} not supported")]
    Capability { cap: u32 },
    #[error("mmap failed: {0}")]
    Mmap(String),
}

/// Result alias for KVM operations
pub type Result<T> = std::result::Result<T, KvmError>;

/// Retrieve errno after a failed ioctl
///
/// # Safety
/// Must be called immediately after a failed libc::ioctl call (ret < 0).
/// `__errno_location()` returns a pointer to the thread-local errno variable,
/// which is always valid to dereference in this context.
#[inline]
pub(crate) fn errno_after_ioctl() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// KVM instance — wraps `/dev/kvm` fd
#[derive(Debug)]
pub struct Kvm {
    fd: OwnedFd,
}

impl Kvm {
    /// Open `/dev/kvm` and verify API version
    ///
    /// # Errors
    /// Returns `KvmError::Open` if `/dev/kvm` cannot be opened,
    /// `KvmError::ApiVersion` if KVM API version is not 12.
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")?;

        let fd = OwnedFd::from(file);

        // SAFETY: fd is a valid KVM fd just opened, KVM_GET_API_VERSION
        // is always safe to call and returns the API version.
        let version = unsafe {
            libc::ioctl(fd.as_raw_fd(), KVM_GET_API_VERSION as libc::c_ulong, 0)
        };
        if version < 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_GET_API_VERSION".into(),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: unsafe { *libc::__errno_location() },
            });
        }
        if version != 12 {
            return Err(KvmError::ApiVersion {
                got: version,
                expected: 12,
            });
        }

        Ok(Self { fd })
    }

    /// Check if a KVM capability is supported
    ///
    /// # Errors
    /// Returns `KvmError::Ioctl` if the ioctl fails.
    pub fn check_capability(&self, cap: u32) -> Result<bool> {
        // SAFETY: fd is a valid KVM fd, KVM_CHECK_EXTENSION takes a capability
        // integer and returns >0 if supported, 0 if not, -1 on error.
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_CHECK_EXTENSION as libc::c_ulong,
                cap as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_CHECK_EXTENSION cap={}", cap),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: unsafe { *libc::__errno_location() },
            });
        }
        Ok(ret > 0)
    }

    /// Create a new VM
    ///
    /// # Errors
    /// Returns `KvmError::Ioctl` if VM creation fails (e.g., EINVAL if KVM
    /// is not in hardware virtualization mode).
    pub fn create_vm(&self) -> Result<Vm> {
        // SAFETY: fd is a valid KVM fd, KVM_CREATE_VM creates a new VM fd.
        // Returns a new fd that we wrap in OwnedFd.
        let vm_fd = unsafe {
            libc::ioctl(self.fd.as_raw_fd(), KVM_CREATE_VM as libc::c_ulong, 0)
        };
        if vm_fd < 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_CREATE_VM".into(),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: unsafe { *libc::__errno_location() },
            });
        }
        // SAFETY: vm_fd is a valid fd from KVM_CREATE_VM
        let vm_fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        Ok(Vm { fd: vm_fd })
    }

    /// Get the size of the kvm_run mmap region
    pub fn vcpu_mmap_size(&self) -> Result<usize> {
        // SAFETY: fd is a valid KVM fd, returns the size needed for kvm_run mmap
        let size = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_GET_VCPU_MMAP_SIZE as libc::c_ulong,
                0,
            )
        };
        if size < 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_GET_VCPU_MMAP_SIZE".into(),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: unsafe { *libc::__errno_location() },
            });
        }
        Ok(size as usize)
    }

    /// Get the host's supported CPUID entries via `KVM_GET_SUPPORTED_CPUID`.
    ///
    /// Delegates to `crate::arch::vcpu::get_supported_cpuid`.
    pub fn get_supported_cpuid(&self) -> Result<Vec<KvmCpuidEntry2Raw>> {
        crate::arch::vcpu::get_supported_cpuid(self.fd.as_raw_fd())
    }

    /// Raw fd for use by child VMs
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// A KVM VM — wraps a VM fd from `KVM_CREATE_VM`
#[derive(Debug)]
pub struct Vm {
    fd: OwnedFd,
}

impl Vm {
    /// Set a user memory region for the VM
    ///
    /// # Safety
    /// `host_addr` must point to a valid mmap region of at least `size` bytes.
    /// `guest_phys_addr` must not overlap with other regions.
    /// `slot` must be unique and < 32 (KVM max slots).
    pub unsafe fn set_memory_region(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        host_addr: *mut u8,
        flags: u32,
    ) -> Result<()> {
        #[repr(C)]
        #[derive(Debug)]
        struct KvmUserspaceMemoryRegion {
            slot: u32,
            flags: u32,
            guest_phys_addr: u64,
            memory_size: u64,
            userspace_addr: u64,
        }

        let region = KvmUserspaceMemoryRegion {
            slot,
            flags,
            guest_phys_addr,
            memory_size,
            userspace_addr: host_addr as u64,
        };

        // SAFETY: caller must ensure host_addr is valid and region doesn't overlap
        let ret = libc::ioctl(
            self.fd.as_raw_fd(),
            KVM_SET_USER_MEMORY_REGION as libc::c_ulong,
            &region as *const _ as *const libc::c_void,
        );
        if ret < 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_SET_USER_MEMORY_REGION".into(),
                errno: *libc::__errno_location(),
            });
        }
        Ok(())
    }

    /// Check if read-only memory slots are supported.
    /// Uses the KVM fd for the capability check. The caller must provide
    /// a valid `kvm_fd` (from `Kvm::fd()`).
    ///
    /// # Safety
    /// `kvm_fd` must be a valid `/dev/kvm` fd returned by `Kvm::new()`.
    /// The fd must remain alive for the duration of this call.
    pub unsafe fn has_readonly_mem(&self, kvm_fd: RawFd) -> Result<bool> {
        // SAFETY: kvm_fd is a valid KVM fd (asserted by caller),
        // KVM_CHECK_EXTENSION with KVM_CAP_READONLY_MEM (81) returns
        // >0 if supported, 0 if not, -1 on error.
        let ret = libc::ioctl(
            kvm_fd,
            KVM_CHECK_EXTENSION as libc::c_ulong,
            81, // KVM_CAP_READONLY_MEM
        );
        if ret < 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_CHECK_EXTENSION cap=81 (READONLY_MEM)".into(),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: *libc::__errno_location(),
            });
        }
        Ok(ret > 0)
    }

    /// Create in-kernel interrupt chipset (PIC, IOAPIC, LAPIC, PIT)
    ///
    /// Delegates to `crate::arch::vm::create_irqchip`.
    pub fn create_irqchip(&self) -> Result<()> {
        crate::arch::vm::create_irqchip(self.fd.as_raw_fd())
    }

    /// Create in-kernel PIT (8254) emulation.
    ///
    /// Delegates to `crate::arch::vm::create_pit`.
    pub fn create_pit(&self) -> Result<()> {
        crate::arch::vm::create_pit(self.fd.as_raw_fd())
    }

    /// Create a Vm from a raw KVM VM fd.
    ///
    /// # Safety
    /// `fd` must be a valid fd returned by `KVM_CREATE_VM`. The caller
    /// must ensure the fd is valid and owned exclusively by this Vm.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY: caller guarantees fd is a valid KVM VM fd.
        // The inner unsafe block is implicit because the function body
        // of an `unsafe fn` is already an unsafe context.
        Self { fd: OwnedFd::from_raw_fd(fd) }
    }

    /// Connect an eventfd to a GSI for interrupt routing.
    ///
    /// When the eventfd is signaled, KVM injects an interrupt on the
    /// specified GSI through the in-kernel irqchip (IOAPIC/PIC).
    ///
    /// This is essential for VFIO INTx passthrough: the physical device's
    /// INTx pin triggers the eventfd (via VFIO_DEVICE_SET_IRQS), and KVM
    /// delivers it to the guest as an IOAPIC interrupt on the given GSI.
    ///
    /// # Arguments
    /// * `irq_fd` — A valid eventfd file descriptor. KVM takes ownership.
    /// * `gsi` — The Global System Interrupt number (0-23 for IOAPIC).
    /// * `resample_fd` — Optional eventfd for resampling (level-triggered).
    ///   When provided, the irqfd is re-armed after the guest issues an EOI.
    ///
    /// # Safety
    /// `self.fd` must be a valid KVM VM fd created with `KVM_CREATE_IRQCHIP`.
    /// `irq_fd` must be a valid eventfd file descriptor.
    /// `resample_fd` if `Some` must be a valid eventfd.
    pub unsafe fn set_irqfd(&self, irq_fd: RawFd, gsi: u32, resample_fd: Option<RawFd>) -> Result<()> {
        let mut flags = 0u32;
        if let Some(_rfd) = resample_fd {
            flags |= KVM_IRQFD_FLAG_RESAMPLE;
        }

        let irqfd = KvmIrqfd {
            fd: irq_fd as u32,
            gsi,
            flags,
            resamplefd: resample_fd.unwrap_or(0) as u32,
            pad: [0u8; 16],
        };

        // SAFETY: caller guarantees self.fd is a valid KVM VM fd,
        // irq_fd is a valid eventfd, and KVM_CREATE_IRQCHIP was called.
        let ret = libc::ioctl(
            self.fd.as_raw_fd(),
            KVM_IRQFD as libc::c_ulong,
            &irqfd as *const _ as *const libc::c_void,
        );
        if ret < 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_IRQFD(gsi={})", gsi),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: *libc::__errno_location(),
            });
        }
        Ok(())
    }

    /// Deassign an irqfd from a GSI via `KVM_IRQFD` with `KVM_IRQFD_FLAG_DEASSIGN`.
    ///
    /// Removes the connection between the GSI and any eventfd previously
    /// registered via `set_irqfd`. After this call, the irqfd will no longer
    /// trigger interrupt injection for this GSI.
    ///
    /// This is a cleanup operation: the eventfd fd field in `KvmIrqfd` is
    /// ignored (set to 0) when the `DEASSIGN` flag is set. The eventfd itself
    /// is not closed — the caller is responsible for closing the eventfd fd.
    ///
    /// KVM automatically cleans up all irqfds when the VM fd is closed. This
    /// explicit deassign is provided for lifecycle hygiene when ordering
    /// matters (e.g., VFIO cleanup before VM fd close).
    ///
    /// # Safety
    /// `self.fd` must be a valid KVM VM fd.
    pub unsafe fn deassign_irqfd(&self, gsi: u32) -> Result<()> {
        let irqfd = KvmIrqfd {
            fd: 0, // ignored when DEASSIGN is set
            gsi,
            flags: KVM_IRQFD_FLAG_DEASSIGN,
            resamplefd: 0,
            pad: [0u8; 16],
        };

        // SAFETY: caller guarantees self.fd is a valid KVM VM fd.
        let ret = libc::ioctl(
            self.fd.as_raw_fd(),
            KVM_IRQFD as libc::c_ulong,
            &irqfd as *const _ as *const libc::c_void,
        );
        if ret < 0 {
            let errno = errno_after_ioctl();
            // ENOSPC or EINVAL means no irqfd was registered for this GSI —
            // this is fine for cleanup operations.
            if errno == libc::ENOSPC || errno == libc::EINVAL {
                return Ok(());
            }
            return Err(KvmError::Ioctl {
                context: format!("KVM_IRQFD(DEASSIGN, gsi={})", gsi),
                errno,
            });
        }
        Ok(())
    }

    /// Save the state of one in-kernel irqchip (PIC master, PIC slave, or IOAPIC)
    ///
    /// Delegates to `crate::arch::vm::get_irqchip`.
    ///
    /// # Safety
    /// Delegates to `crate::arch::vm::get_irqchip`.
    pub unsafe fn get_irqchip(&self, chip_id: u32) -> Result<KvmIrqChipRaw> {
        crate::arch::vm::get_irqchip(self.fd.as_raw_fd(), chip_id)
    }

    /// Restore the state of one in-kernel irqchip (PIC master, PIC slave, or IOAPIC)
    ///
    /// Delegates to `crate::arch::vm::set_irqchip`.
    ///
    /// # Safety
    /// Delegates to `crate::arch::vm::set_irqchip`.
    pub unsafe fn set_irqchip(&self, chip: &KvmIrqChipRaw) -> Result<()> {
        crate::arch::vm::set_irqchip(self.fd.as_raw_fd(), chip)
    }

    /// Assert or deassert an IRQ line (GSI) via KVM_IRQ_LINE.
    /// `level=true` asserts the line, `level=false` deasserts.
    pub fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        let irq_level = KvmIrqLevel {
            irq,
            level: if level { 1 } else { 0 },
        };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                crate::kvm::KVM_IRQ_LINE as libc::c_ulong,
                &irq_level as *const _ as *const libc::c_void,
            )
        };
        if ret != 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_IRQ_LINE(irq={}, level={})", irq, level),
                errno: unsafe { *libc::__errno_location() },
            });
        }
        Ok(())
    }

    /// Inject an MSI interrupt via KVM_SIGNAL_MSI.
    pub fn signal_msi(&self, address_lo: u32, data: u32) -> Result<()> {
        let msi = KvmMsi {
            address_lo,
            address_hi: 0,
            data,
            flags: 0,
            devid: 0,
            pad: [0u8; 11],
        };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                crate::kvm::KVM_SIGNAL_MSI as libc::c_ulong,
                &msi as *const _ as *const libc::c_void,
            )
        };
        if ret != 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_SIGNAL_MSI(addr=0x{address_lo:x}, data=0x{data:x})"),
                errno: unsafe { *libc::__errno_location() },
            });
        }
        Ok(())
    }

    /// Maximum allowed VCPU ID to prevent resource abuse.
    pub const MAX_VCPUS: u64 = 256;

    /// Create a VCPU in this VM
    ///
    /// Validates `id` against `MAX_VCPUS` (256) before calling the ioctl
    /// to prevent crafted `u64::MAX` values from wasting kernel memory
    /// or triggering non-OOM-safe error paths.
    pub fn create_vcpu(&self, id: u64) -> Result<Vcpu> {
        if id >= Self::MAX_VCPUS {
            return Err(KvmError::Ioctl {
                context: format!("KVM_CREATE_VCPU id={} exceeds MAX_VCPUS={}", id, Self::MAX_VCPUS),
                errno: libc::EINVAL,
            });
        }
        // SAFETY: fd is a valid VM fd, KVM_CREATE_VCPU(id) creates a VCPU
        let vcpu_fd = unsafe {
            libc::ioctl(self.fd.as_raw_fd(), KVM_CREATE_VCPU as libc::c_ulong, id)
        };
        if vcpu_fd < 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_CREATE_VCPU id={}", id),
                // SAFETY: __errno_location returns a pointer to the thread-local
                // errno variable, which is always valid to dereference after a failed ioctl.
                errno: unsafe { *libc::__errno_location() },
            });
        }
        // SAFETY: vcpu_fd is a valid fd from KVM_CREATE_VCPU
        let fd = unsafe { OwnedFd::from_raw_fd(vcpu_fd) };
        Ok(Vcpu { fd })
    }

    /// Create a KVM device (e.g., VFIO device).
    ///
    /// Returns a `Device` handle wrapping the device fd.
    /// `device_type` is the KVM device type (e.g., `KVM_DEV_TYPE_VFIO`).
    ///
    /// # Errors
    /// Returns `KvmError::Ioctl` if device creation fails (e.g., unsupported type).
    pub fn create_device(&self, device_type: u32) -> Result<Device> {
        let mut cd = KvmCreateDevice {
            type_: device_type,
            fd: -1,
            flags: 0,
        };

        // SAFETY: fd is a valid VM fd. KVM_CREATE_DEVICE allocates a new fd
        // for the device and writes it to cd.fd.
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_CREATE_DEVICE as libc::c_ulong,
                &mut cd as *mut _ as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_CREATE_DEVICE type={}", device_type),
                errno: errno_after_ioctl(),
            });
        }

        // SAFETY: cd.fd was set by KVM to a valid fd (ret >= 0 guarantees this).
        let fd = unsafe { OwnedFd::from_raw_fd(cd.fd) };
        Ok(Device { fd })
    }

    /// Set a device attribute (e.g., add a VFIO group to a VFIO device).
    ///
    /// # Safety
    /// `addr` must be a valid pointer to a C-compatible structure matching
    /// the attribute `group`/`attr` pair.
    pub unsafe fn set_device_attr(
        &self,
        group: u32,
        attr: u64,
        addr: *const libc::c_void,
    ) -> Result<()> {
        let kda = KvmDeviceAttr {
            flags: 0,
            group,
            attr,
            addr: addr as u64,
        };

        // SAFETY: caller must ensure addr points to valid data matching the
        // attribute semantics. fd is a valid VM fd.
        let ret = libc::ioctl(
            self.fd.as_raw_fd(),
            KVM_SET_DEVICE_ATTR as libc::c_ulong,
            &kda as *const _ as *const libc::c_void,
        );
        if ret < 0 {
            return Err(KvmError::Ioctl {
                context: format!("KVM_SET_DEVICE_ATTR group={} attr={}", group, attr),
                errno: errno_after_ioctl(),
            });
        }
        Ok(())
    }

    /// Set the interrupt routing table via `KVM_SET_GSI_ROUTING`.
    ///
    /// Delegates to `crate::arch::vm::set_gsi_routing`.
    ///
    /// # Safety
    /// Delegates to `crate::arch::vm::set_gsi_routing`.
    #[allow(clippy::manual_slice_size_calculation)] // explicit formula preferred for clarity
    pub unsafe fn set_gsi_routing(&self, entries: &[KvmIrqRoutingEntryRaw]) -> Result<()> {
        crate::arch::vm::set_gsi_routing(self.fd.as_raw_fd(), entries)
    }

    /// Build a complete GSI routing table with IOAPIC + MSI entries.
    ///
    /// Delegates to `crate::arch::vm::build_gsi_routing_table`.
    pub fn build_gsi_routing_table(
        msi_gsi_base: u32,
        msi_count: u32,
        msi_address_lo: u32,
        msi_address_hi: u32,
        msi_data_base: u32,
    ) -> Vec<KvmIrqRoutingEntryRaw> {
        crate::arch::vm::build_gsi_routing_table(
            msi_gsi_base,
            msi_count,
            msi_address_lo,
            msi_address_hi,
            msi_data_base,
        )
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// A KVM device (e.g., VFIO device) — wraps a device fd from `KVM_CREATE_DEVICE`
#[derive(Debug)]
pub struct Device {
    fd: OwnedFd,
}

impl Device {
    /// Get the raw fd for this device
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

// ─── x86_64-specific KVM types ───────────────────────────────────────
//
// All x86_64 KVM register structs (KvmRegsRaw, KvmSregsRaw, etc.),
// MpState, the Pod trait, and x86-specific ioctl constants are now
// defined in `crate::arch::x86_64::kvm_types` and re-exported above
// via `pub use crate::arch::kvm_types::*;`.
//
// MSR constants (MSR_STAR, MSR_LSTAR, etc.) are in
// `crate::arch::x86_64::cpu` and also re-exported through arch module.

// ─── Vcpu ──────────────────────────────────────────────────────────

/// A KVM VCPU — wraps a VCPU fd
#[derive(Debug)]
pub struct Vcpu {
    fd: OwnedFd,
}

impl Vcpu {
    /// Get the exit reason from the kvm_run structure
    ///
    /// # Safety
    /// `kvm_run_ptr` must point to a valid, mmap'd kvm_run structure for this VCPU.
    /// The `exit_reason` field is at offset 8 in `struct kvm_run`.
    #[inline]
    pub unsafe fn exit_reason(kvm_run_ptr: *const u8) -> u32 {
        // SAFETY: caller guarantees kvm_run_ptr points to a valid kvm_run struct.
        // The exit_reason field is at offset 8 (verified via C offsetof).
        unsafe { ptr::read_unaligned(kvm_run_ptr.add(8) as *const u32) }
    }

    /// Get general-purpose registers via `KVM_GET_REGS`
    ///
    /// Delegates to `crate::arch::vcpu::get_regs`.
    pub fn get_regs(&self) -> Result<KvmRegsRaw> {
        crate::arch::vcpu::get_regs(self.fd.as_raw_fd())
    }

    /// Set general-purpose registers via `KVM_SET_REGS`
    ///
    /// Delegates to `crate::arch::vcpu::set_regs`.
    pub fn set_regs(&self, regs: &KvmRegsRaw) -> Result<()> {
        crate::arch::vcpu::set_regs(self.fd.as_raw_fd(), regs)
    }

    /// Get special registers (segments, CRx, EFER, etc.) via `KVM_GET_SREGS`
    ///
    /// Delegates to `crate::arch::vcpu::get_sregs`.
    pub fn get_sregs(&self) -> Result<KvmSregsRaw> {
        crate::arch::vcpu::get_sregs(self.fd.as_raw_fd())
    }

    /// Set CPUID for the VCPU via `KVM_SET_CPUID2`
    ///
    /// Delegates to `crate::arch::vcpu::set_cpuid2`.
    pub fn set_cpuid2(&self, entries: &[KvmCpuidEntry2Raw]) -> Result<()> {
        crate::arch::vcpu::set_cpuid2(self.fd.as_raw_fd(), entries)
    }

    /// Set special registers via `KVM_SET_SREGS`
    ///
    /// Delegates to `crate::arch::vcpu::set_sregs`.
    pub fn set_sregs(&self, sregs: &KvmSregsRaw) -> Result<()> {
        crate::arch::vcpu::set_sregs(self.fd.as_raw_fd(), sregs)
    }

    /// Enter the guest and execute
    ///
    /// # Safety
    /// The VCPU must be properly configured (registers, memory, etc.)
    /// before calling this. Returns EINTR if a signal is received.
    pub unsafe fn run(&self) -> Result<i32> {
        let ret = libc::ioctl(self.fd.as_raw_fd(), KVM_RUN as libc::c_ulong, 0);
        if ret < 0 {
            let errno = *libc::__errno_location();
            // EINTR is normal (signal delivery), don't wrap as error
            if errno == libc::EINTR {
                return Ok(libc::EINTR);
            }
            return Err(KvmError::Ioctl {
                context: "KVM_RUN".into(),
                errno,
            });
        }
        Ok(ret)
    }

    /// Get the VCPU's MP state via `KVM_GET_MP_STATE`
    ///
    /// Delegates to `crate::arch::vcpu::get_mp_state`.
    pub fn get_mp_state(&self) -> Result<MpState> {
        crate::arch::vcpu::get_mp_state(self.fd.as_raw_fd())
    }

    /// Set the VCPU's MP state via `KVM_SET_MP_STATE`
    ///
    /// Delegates to `crate::arch::vcpu::set_mp_state`.
    pub fn set_mp_state(&self, state: MpState) -> Result<()> {
        crate::arch::vcpu::set_mp_state(self.fd.as_raw_fd(), state)
    }

    /// Get the XSAVE area (FPU/SSE/AVX state) via `KVM_GET_XSAVE`
    ///
    /// Delegates to `crate::arch::vcpu::get_xsave`.
    pub fn get_xsave(&self) -> Result<[u8; 4096]> {
        crate::arch::vcpu::get_xsave(self.fd.as_raw_fd())
    }

    /// Set the XSAVE area (FPU/SSE/AVX state) via `KVM_SET_XSAVE`
    ///
    /// # Safety
    /// Delegates to `crate::arch::vcpu::set_xsave`.
    pub unsafe fn set_xsave(&self, xsave: &[u8; 4096]) -> Result<()> {
        crate::arch::vcpu::set_xsave(self.fd.as_raw_fd(), xsave)
    }

    /// Get the XCR registers (XCR0, etc.) via `KVM_GET_XCRS`
    ///
    /// Delegates to `crate::arch::vcpu::get_xcrs`.
    pub fn get_xcrs(&self) -> Result<Vec<(u32, u64)>> {
        crate::arch::vcpu::get_xcrs(self.fd.as_raw_fd())
    }

    /// Set the XCR registers (XCR0, etc.) via `KVM_SET_XCRS`
    ///
    /// # Safety
    /// Delegates to `crate::arch::vcpu::set_xcrs`.
    pub unsafe fn set_xcrs(&self, xcrs: &[(u32, u64)]) -> Result<()> {
        crate::arch::vcpu::set_xcrs(self.fd.as_raw_fd(), xcrs)
    }

    /// Save the MSRs critical for Linux x86_64 operation.
    ///
    /// Delegates to `crate::arch::vcpu::save_critical_msrs`.
    ///
    /// # Safety
    /// The VCPU must be valid. Returns as many MSRs as KVM supports.
    pub unsafe fn save_critical_msrs(&self) -> Result<Vec<(u32, u64)>> {
        crate::arch::vcpu::save_critical_msrs(self.fd.as_raw_fd())
    }

    /// Restore MSRs on the VCPU.
    ///
    /// Delegates to `crate::arch::vcpu::restore_msrs`.
    ///
    /// # Safety
    /// The VCPU must be valid. MSR values must be appropriate for the CPU.
    pub unsafe fn restore_msrs(&self, msrs: &[(u32, u64)]) -> Result<u32> {
        crate::arch::vcpu::restore_msrs(self.fd.as_raw_fd(), msrs)
    }

    /// Get the kvm_run structure pointer via mmap
    ///
    /// # Safety
    /// The returned pointer is valid until the VCPU is destroyed.
    /// Must be called with a valid mmap of the correct size.
    pub unsafe fn kvm_run_ptr(&self, mmap_size: usize) -> Result<*mut u8> {
        let ptr = libc::mmap(
            ptr::null_mut(),
            mmap_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            self.fd.as_raw_fd(),
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(KvmError::Mmap("kvm_run mmap failed".into()));
        }
        Ok(ptr as *mut u8)
    }

    /// Inject a virtual interrupt into the VCPU via `KVM_INTERRUPT`.
    ///
    /// Delegates to `crate::arch::vcpu::inject_interrupt`.
    pub fn inject_interrupt(&self, irq: u32) -> Result<()> {
        crate::arch::vcpu::inject_interrupt(self.fd.as_raw_fd(), irq)
    }

    /// Inject via KVM_SET_VCPU_EVENTS (requires in-kernel irqchip).
    fn signal_vcpu_events(vcpu_fd: RawFd, vector: u8) -> Result<()> {
        // struct kvm_vcpu_events from kernel header (arch/x86/include/uapi/asm/kvm.h:340)
        #[repr(C)]
        struct KvmVcpuEvents {
            exception: [u8; 8],
            interrupt: [u8; 4],
            nmi: [u8; 4],
            sipi_vector: u32,
            flags: u32,
            smi: [u8; 4],
            triple_fault: [u8; 1],
            reserved: [u8; 26],
            exception_has_payload: u8,
            exception_payload: u64,
        }
        const SZ: usize = std::mem::size_of::<KvmVcpuEvents>();
        const KVM_SET_VCPU_EVENTS: u64 =
            0x40000000u64 | (0xAEu64 << 8) | 0xA0u64 | ((SZ as u64) << 16);
        const KVM_GET_VCPU_EVENTS: u64 =
            0x80000000u64 | (0xAEu64 << 8) | 0x9Fu64 | ((SZ as u64) << 16);

        // Read current state to check if previous injected was consumed
        let mut prev: KvmVcpuEvents = unsafe { std::mem::zeroed() };
        let pr = unsafe {
            libc::ioctl(
                vcpu_fd,
                KVM_GET_VCPU_EVENTS,
                &mut prev as *mut _ as *mut libc::c_void,
            )
        };
        let prev_injected = if pr == 0 { prev.interrupt[0] } else { 0xFF };
        if prev_injected != 0 {
            tracing::info!(
                "signal_lapic_irq(0x{:02x}): PREVIOUS injected={} still PENDING! (not consumed by KVM_RUN)",
                vector, prev_injected
            );
        }

        let events = KvmVcpuEvents {
            exception: [0; 8],
            interrupt: [1, vector, 0, 0],
            nmi: [0; 4],
            sipi_vector: 0,
            flags: 0,
            smi: [0; 4],
            triple_fault: [0],
            reserved: [0; 26],
            exception_has_payload: 0,
            exception_payload: 0,
        };
        let ret = unsafe {
            libc::ioctl(
                vcpu_fd,
                KVM_SET_VCPU_EVENTS,
                &events as *const _ as *const libc::c_void,
            )
        };
        if ret != 0 {
            let errno = unsafe { *libc::__errno_location() };
            tracing::info!(
                "signal_lapic_irq(0x{:02x}): KVM_SET_VCPU_EVENTS failed with errno={}",
                vector, errno
            );
            return Err(KvmError::Ioctl {
                context: format!("KVM_SET_VCPU_EVENTS(0x{vector:02x})"),
                errno,
            });
        }
        tracing::info!(
            "signal_lapic_irq(0x{:02x}): KVM_SET_VCPU_EVENTS ok (soft=0)",
            vector,
        );
        Ok(())
    }

    /// Inject an interrupt via KVM_INTERRUPT (works with or without irqchip).
    pub fn signal_lapic_irq(&self, vector: u8) -> Result<()> {
        let vcpu_fd = self.fd.as_raw_fd();
        // Try KVM_INTERRUPT directly (avoids KVM_SET_VCPU_EVENTS which can
        // trigger KVM_EXIT_FAIL_ENTRY with in-kernel irqchip on this kernel).
        match crate::arch::vcpu::inject_interrupt(vcpu_fd, vector as u32) {
            Ok(()) => {
                tracing::info!("signal_lapic_irq(0x{vector:02x}): KVM_INTERRUPT ok");
                Ok(())
            }
            Err(e) => {
                // Fall back to KVM_SET_VCPU_EVENTS
                tracing::info!("signal_lapic_irq(0x{vector:02x}): KVM_INTERRUPT failed ({e:?}), trying KVM_SET_VCPU_EVENTS");
                Self::signal_vcpu_events(vcpu_fd, vector)?;
                Ok(())
            }
        }
    }

    /// Inject an interrupt directly into the LAPIC IRR via KVM_SET_LAPIC,
    /// bypassing PIC/IOAPIC entirely. This sets the IRR bit for the given
    /// vector in the in-kernel LAPIC, which KVM will inject on the next VM entry.
    pub fn inject_lapic_irq(&self, vector: u8) -> Result<()> {
        let vcpu_fd = self.fd.as_raw_fd();
        let mut lapic = [0u8; 1024];
        // KVM_GET_LAPIC = 0x8400ae8e
        let ret = unsafe {
            libc::ioctl(
                vcpu_fd,
                0x8400ae8eu64,
                &mut lapic as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_GET_LAPIC (inject_lapic_irq)".into(),
                errno: unsafe { *libc::__errno_location() },
            });
        }
        // Set IRR bit for the given vector.
        // LAPIC IRR registers are at offsets 0x200/0x210 etc, one 32-bit reg per 32 vectors.
        let irr_reg = 0x200usize + ((vector as usize) / 32) * 0x10;
        let isr_reg = 0x100usize + ((vector as usize) / 32) * 0x10;
        let bit = 1u32 << ((vector as usize) % 32);
        // Clear ISR first (if set) to prevent priority blocking.
        // The guest with acpi=off sends EOI to the PIC, not the LAPIC,
        // and the slave cascade PIC EOI does NOT propagate to the LAPIC
        // on this kernel, leaving the ISR stuck permanently.
        let isr_val = u32::from_le_bytes(lapic[isr_reg..isr_reg + 4].try_into().unwrap());
        if isr_val & bit != 0 {
            lapic[isr_reg..isr_reg + 4].copy_from_slice(&(isr_val & !bit).to_le_bytes());
            tracing::info!("inject_lapic_irq(0x{vector:02x}): cleared ISR bit (was 0x{isr_val:08x})");
        }
        let irr_val = u32::from_le_bytes(lapic[irr_reg..irr_reg + 4].try_into().unwrap());
        if irr_val & bit != 0 {
            tracing::info!("inject_lapic_irq(0x{vector:02x}): IRR bit already set, skipping");
            return Ok(());
        }
        lapic[irr_reg..irr_reg + 4].copy_from_slice(&(irr_val | bit).to_le_bytes());
        tracing::info!("inject_lapic_irq(0x{vector:02x}): setting IRR reg 0x{irr_reg:03x} (was 0x{irr_val:08x})");
        // KVM_SET_LAPIC = 0x4400ae8f
        let ret = unsafe {
            libc::ioctl(
                vcpu_fd,
                0x4400ae8fu64,
                &lapic as *const _ as *const libc::c_void,
            )
        };
        if ret != 0 {
            return Err(KvmError::Ioctl {
                context: "KVM_SET_LAPIC (inject_lapic_irq)".into(),
                errno: unsafe { *libc::__errno_location() },
            });
        }
        tracing::info!("inject_lapic_irq(0x{vector:02x}): KVM_SET_LAPIC ok");
        Ok(())
    }

    /// Clear the LAPIC ISR bit for the given vector without touching IRR.
    /// This prevents the ISR from permanently blocking re-delivery when
    /// the guest's PIC EOI path does not propagate to the LAPIC.
    pub fn clear_lapic_isr(&self, vector: u8) {
        let vcpu_fd = self.fd.as_raw_fd();
        let mut lapic = [0u8; 1024];
        let ret = unsafe {
            libc::ioctl(
                vcpu_fd,
                0x8400ae8eu64,
                &mut lapic as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return;
        }
        let isr_reg = 0x100usize + ((vector as usize) / 32) * 0x10;
        let bit = 1u32 << ((vector as usize) % 32);
        let isr_val = u32::from_le_bytes(lapic[isr_reg..isr_reg + 4].try_into().unwrap());
        if isr_val & bit != 0 {
            lapic[isr_reg..isr_reg + 4].copy_from_slice(&(isr_val & !bit).to_le_bytes());
            unsafe {
                let _ = libc::ioctl(
                    vcpu_fd,
                    0x4400ae8fu64,
                    &lapic as *const _ as *const libc::c_void,
                );
            }
            tracing::info!("clear_lapic_isr(0x{vector:02x}): cleared ISR bit (was 0x{isr_val:08x})");
        }
    }

    /// Dump LAPIC ISR registers for debugging.
    pub fn dump_lapic_isr(&self, label: &str) {
        let vcpu_fd = self.fd.as_raw_fd();
        let mut lapic = [0u8; 1024];
        let ret = unsafe {
            libc::ioctl(
                vcpu_fd,
                0x8400ae8eu64,
                &mut lapic as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return;
        }
        // ISR at offsets 0x100, 0x110, 0x120, ... (32 bits per reg, vectors 0-31, 32-63, ...)
        // Only show registers 0 and 1 (vectors 0-63) as u64
        let isr_lo = u32::from_le_bytes(lapic[0x100..0x104].try_into().unwrap());
        let isr_hi = u32::from_le_bytes(lapic[0x110..0x114].try_into().unwrap());
        let isr_64 = (isr_hi as u64) << 32 | isr_lo as u64;
        let irr_lo = u32::from_le_bytes(lapic[0x200..0x204].try_into().unwrap());
        let irr_hi = u32::from_le_bytes(lapic[0x210..0x214].try_into().unwrap());
        let irr_64 = (irr_hi as u64) << 32 | irr_lo as u64;
        let v59_isr = (isr_hi >> 27) & 1;
        let v59_irr = (irr_hi >> 27) & 1;
        tracing::info!("LAPIC {label}: ISR[0-63]={isr_64:#018x} (v59_isr={v59_isr}) IRR[0-63]={irr_64:#018x} (v59_irr={v59_irr})");
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Enable the LAPIC by setting SVR bit 8 (software enable) and
    /// configure LVT LINT0 for ExtINTA delivery mode (so PIC-originated
    /// interrupts are accepted). Also enables the APIC via MSR 0x1B.
    /// This is necessary when the irqchip is
    /// present because KVM_CREATE_IRQCHIP leaves the LAPIC software-disabled.
    pub fn enable_apic(&self) -> Result<()> {
        // 1) Enable APIC via MSR_IA32_APICBASE (0x1B).
        // Read current value, set enable bit, write back.
        const ENTRY_SIZE: usize = 16; // kvm_msr_entry is 16 bytes
        // KVM_GET_MSRS = _IOWR(KVMIO, 0x88, struct kvm_msrs) = 0xc008ae88
        const KVM_GET_MSRS: u64 = 0xc008ae88u64;
        // KVM_SET_MSRS = _IOW(KVMIO, 0x89, struct kvm_msrs) = 0x4008ae89
        const KVM_SET_MSRS: u64 = 0x4008ae89u64;

        let current_apic_base = {
            let mut buf = vec![0u8; 8 + ENTRY_SIZE];
            unsafe {
                let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
                *nmsrs_ptr = 1;
                let entry = buf.as_mut_ptr().add(8);
                *(entry as *mut u32) = 0x1B; // MSR index
            }
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    KVM_GET_MSRS,
                    buf.as_mut_ptr() as *mut libc::c_void,
                )
            };
            if ret <= 0 {
                return Err(KvmError::Ioctl {
                    context: "KVM_GET_MSRS(APIC_BASE)".into(),
                    errno: unsafe { *libc::__errno_location() },
                });
            }
            unsafe {
                let entry = buf.as_ptr().add(8);
                *(entry.add(8) as *const u64)
            }
        };

        let apic_base_new = current_apic_base | 0x800; // MSR_IA32_APICBASE_ENABLE (bit 11)

        tracing::info!("APIC_BASE MSR: current=0x{current_apic_base:x} new=0x{apic_base_new:x}");

        {
            let mut buf = vec![0u8; 8 + ENTRY_SIZE];
            unsafe {
                let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
                *nmsrs_ptr = 1;
                let entry = buf.as_mut_ptr().add(8);
                *(entry as *mut u32) = 0x1B;
                *(entry.add(8) as *mut u64) = apic_base_new;
            }
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    KVM_SET_MSRS,
                    buf.as_mut_ptr() as *mut libc::c_void,
                )
            };
            if ret <= 0 {
                return Err(KvmError::Ioctl {
                    context: "KVM_SET_MSRS(APIC_BASE)".into(),
                    errno: unsafe { *libc::__errno_location() },
                });
            }
        }

        // Read back to verify
        {
            let mut buf = vec![0u8; 8 + ENTRY_SIZE];
            unsafe {
                let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
                *nmsrs_ptr = 1;
                let entry = buf.as_mut_ptr().add(8);
                *(entry as *mut u32) = 0x1B;
            }
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    KVM_GET_MSRS,
                    buf.as_mut_ptr() as *mut libc::c_void,
                )
            };
            if ret > 0 {
                let verify = unsafe {
                    let entry = buf.as_ptr().add(8);
                    *(entry.add(8) as *const u64)
                };
                tracing::info!("APIC_BASE MSR readback: 0x{verify:x} (enable_bit={})", (verify >> 11) & 1);
            }
        }

        // 2) Force sw_enabled via KVM_SET_MSRS apic_base toggle.
        //    KVM_SET_LAPIC writes SVR bit 8 to apic->regs but KVM does NOT
        //    update the internal apic->sw_enabled flag on most kernel versions.
        //    The MSR write path calls kvm_lapic_set_base() ->
        //    kvm_lapic_update_sw_enabled() which re-evaluates sw_enabled from
        //    SVR bit 8.  We must do this toggle BEFORE KVM_SET_LAPIC because
        //    the disable step calls kvm_lapic_reset() which wipes all LAPIC
        //    registers, including the SVR we just carefully set.  After the
        //    re-enable, sw_enabled=0 (SVR was reset to 0), and then
        //    KVM_SET_LAPIC writes SVR=0x1ff which triggers sw_enabled=1.
        {
            let toggle_value = apic_base_new & !0x800; // clear bit 11 (disable)

            let mut buf = vec![0u8; 8 + ENTRY_SIZE];
            unsafe {
                let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
                *nmsrs_ptr = 1;
                let entry = buf.as_mut_ptr().add(8);
                *(entry as *mut u32) = 0x1Bu32; // MSR_IA32_APICBASE
                *(entry.add(8) as *mut u64) = toggle_value;
            }
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    KVM_SET_MSRS,
                    buf.as_mut_ptr() as *mut libc::c_void,
                )
            };
            if ret <= 0 {
                tracing::warn!("MSR toggle: disable APIC failed: {}", unsafe { *libc::__errno_location() });
            } else {
                tracing::info!("MSR toggle: disabled APIC (0x{toggle_value:x})");
            }

            // Re-enable APIC via MSR
            buf = vec![0u8; 8 + ENTRY_SIZE];
            unsafe {
                let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
                *nmsrs_ptr = 1;
                let entry = buf.as_mut_ptr().add(8);
                *(entry as *mut u32) = 0x1Bu32;
                *(entry.add(8) as *mut u64) = apic_base_new;
            }
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    KVM_SET_MSRS,
                    buf.as_mut_ptr() as *mut libc::c_void,
                )
            };
            if ret <= 0 {
                tracing::warn!("MSR toggle: re-enable APIC failed: {}", unsafe { *libc::__errno_location() });
            } else {
                tracing::info!("MSR toggle: re-enabled APIC (0x{apic_base_new:x})");
            }
        }

        // 3) Re-enable LAPIC via KVM_SET_LAPIC (must come AFTER the MSR toggle,
        //    because the toggle's disable path calls kvm_lapic_reset() which
        //    wipes all LAPIC registers).  Set SVR bit 8 for software enable
        //    and LVT LINT0 to ExtINT delivery for PIC interrupt forwarding.
        //    The snapshot's LAPIC state has SVR=0xff (software-disabled) and
        //    LVT_LINT0=0x10000 (masked, not ExtINT), so we must fix them.
        {
            let mut lapic = [0u8; 1024];
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    0x8400ae8eu64, // KVM_GET_LAPIC
                    &mut lapic as *mut _ as *mut libc::c_void,
                )
            };
            if ret != 0 {
                return Err(KvmError::Ioctl {
                    context: "KVM_GET_LAPIC".into(),
                    errno: unsafe { *libc::__errno_location() },
                });
            }

            // SVR at offset 0xF0: enable bit 8
            let svr_off = 0xF0usize;
            let svr_val = u32::from_le_bytes(lapic[svr_off..svr_off + 4].try_into().unwrap());
            let svr_new = svr_val | (1 << 8); // software enable
            lapic[svr_off..svr_off + 4].copy_from_slice(&svr_new.to_le_bytes());

            // LVT LINT0 at offset 0x330: set ExtINTA delivery mode (bits 8-10 = 7)
            let lint0_off = 0x330usize;
            let lint0_val = u32::from_le_bytes(lapic[lint0_off..lint0_off + 4].try_into().unwrap());
            // Clear bits 8-10 (delivery mode), set to 7 (ExtINT), clear bit 16 (unmask)
            let lint0_new = (lint0_val & !0x10700) | 0x00000700;
            lapic[lint0_off..lint0_off + 4].copy_from_slice(&lint0_new.to_le_bytes());

            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    0x4400ae8fu64, // KVM_SET_LAPIC
                    &lapic as *const _ as *const libc::c_void,
                )
            };
            if ret != 0 {
                return Err(KvmError::Ioctl {
                    context: "KVM_SET_LAPIC".into(),
                    errno: unsafe { *libc::__errno_location() },
                });
            }

            // Readback to verify
            let mut lapic2 = [0u8; 1024];
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    0x8400ae8eu64,
                    &mut lapic2 as *mut _ as *mut libc::c_void,
                )
            };
            if ret == 0 {
                let lint0_v = u32::from_le_bytes(lapic2[lint0_off..lint0_off + 4].try_into().unwrap());
                let svr_v = u32::from_le_bytes(lapic2[0xF0..0xF4].try_into().unwrap());
                tracing::info!("LAPIC readback: SVR=0x{svr_v:x} (enabled={}) LVT_LINT0=0x{lint0_v:x} (masked={} mode={})",
                    (svr_v >> 8) & 1,
                    (lint0_v >> 16) & 1,
                    (lint0_v >> 8) & 7,
                );
                let tpr_val = u32::from_le_bytes(lapic2[0x80..0x84].try_into().unwrap());
                tracing::info!("LAPIC TPR=0x{tpr_val:x} (priority_class={})", (tpr_val >> 4) & 0xF);
                let lapic_id = u32::from_le_bytes(lapic2[0x20..0x24].try_into().unwrap());
                // LVT Timer at offset 0x320
                let timer_lvt = u32::from_le_bytes(lapic2[0x320..0x324].try_into().unwrap());
                let timer_mask = (timer_lvt >> 16) & 1;
                let timer_mode = (timer_lvt >> 17) & 3;
                let timer_vector = timer_lvt & 0xFF;
                tracing::info!("LAPIC TIMER: LVT=0x{timer_lvt:08x} mask={timer_mask} mode={timer_mode} vector=0x{timer_vector:02x}");
                let initial_count = u32::from_le_bytes(lapic2[0x380..0x384].try_into().unwrap());
                let current_count = u32::from_le_bytes(lapic2[0x390..0x394].try_into().unwrap());
                tracing::info!("LAPIC TIMER: initial_count={initial_count} current_count={current_count}");
                tracing::info!("LAPIC ID=0x{lapic_id:x}");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kvm_creation() {
        let kvm = Kvm::new().expect("KVM should be available on this machine");
        let vm = kvm.create_vm().expect("Should create VM");
        let _vcpu = vm.create_vcpu(0).expect("Should create VCPU");
        let size = kvm.vcpu_mmap_size().expect("Should get mmap size");
        assert!(size > 0, "kvm_run mmap size should be > 0");
    }

    #[test]
    fn test_kvm_api_version() {
        let kvm = Kvm::new().expect("KVM should be available");
        // Just check that we can create a VM — API version check is in new()
        let _vm = kvm.create_vm().expect("VM creation");
    }

    #[test]
    fn test_readonly_mem_cap() {
        let kvm = Kvm::new().expect("KVM should be available");
        let vm = kvm.create_vm().expect("VM creation");
        // SAFETY: kvm.fd is a valid /dev/kvm fd, alive for the duration of the call
        let has = unsafe { vm.has_readonly_mem(kvm.fd.as_raw_fd()).unwrap_or(false) };
        // On modern kernels this should be true, but don't fail if not
        println!("KVM_CAP_READONLY_MEM: {}", has);
    }
}
