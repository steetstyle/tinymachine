//! PCI config space access helpers for VFIO devices

use tracing::warn;

use crate::vfio::device::errno_after_ioctl;

/// Read 1/2/4 bytes from VFIO PCI config space via pread.
///
/// Returns 0 on error (treating unreadable config as zero-initialized, matching
/// PCI spec behavior for unimplemented registers). The caller must validate
/// the returned value against expected ranges.
pub fn read_config_u32(dev_fd: std::os::fd::RawFd, config_off: u64, pci_offset: u16, len: usize) -> u32 {
    let file_offset = config_off + pci_offset as u64;
    let mut buf = [0u8; 4];
    let len = len.min(4);
    // SAFETY: pread on valid VFIO fd. Returns -1 on error, handled below.
    let ret = unsafe {
        libc::pread(
            dev_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            len,
            file_offset as i64,
        )
    };
    if ret < 0 {
        warn!(
            "VFIO config read failed at offset 0x{pci_offset:x}: {}",
            std::io::Error::last_os_error(),
        );
        return 0;
    }
    let mut val: u32 = 0;
    for i in 0..(ret as usize).min(len) {
        val |= (buf[i] as u32) << (i * 8);
    }
    val
}

/// Write `len` bytes of `val` (low `len` bytes) to PCI config space at `pci_offset`.
///
/// `len` must be 1, 2, or 4. Uses `pwrite` on the VFIO device fd.
/// The written value uses little-endian byte order.
pub fn write_config_u32(dev_fd: std::os::fd::RawFd, config_off: u64, pci_offset: u16, val: u32, len: usize) -> bool {
    let file_offset = config_off + pci_offset as u64;
    let len = len.min(4);
    let mut buf = [0u8; 4];
    for i in 0..len {
        buf[i] = ((val >> (i * 8)) & 0xFF) as u8;
    }
    // SAFETY: pwrite on valid VFIO fd. buf is initialized with len bytes.
    let ret = unsafe {
        libc::pwrite(
            dev_fd,
            buf.as_ptr() as *const libc::c_void,
            len,
            file_offset as i64,
        )
    };
    if ret < 0 || ret as usize != len {
        warn!(
            "VFIO config write failed at offset 0x{pci_offset:x} (val=0x{val:x}, len={len}): {}",
            std::io::Error::last_os_error(),
        );
        return false;
    }
    true
}

/// Read a 32-bit value from a VFIO BAR region at the given register offset.
pub fn read_bar_u32(dev_fd: std::os::fd::RawFd, bar_index: u32, register_offset: u64) -> Option<u32> {
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

    let mut info = VfioRegionInfo {
        argsz: std::mem::size_of::<VfioRegionInfo>() as u32,
        index: bar_index,
        ..Default::default()
    };

    // SAFETY: dev_fd is a valid VFIO device fd. The ioctl query is standard
    // VFIO API — the kernel fills in size/offset/flags for the given region
    // index. The struct layout matches struct vfio_region_info (32 bytes).
    let ret = unsafe {
        libc::ioctl(
            dev_fd,
            crate::vfio::device::VFIO_DEVICE_GET_REGION_INFO as libc::c_ulong,
            &mut info as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        let errno = errno_after_ioctl();
        warn!(
            "VFIO read_bar_u32: region info query failed for BAR{bar_index} (errno={errno})"
        );
        return None;
    }

    if register_offset + 4 > info.size {
        warn!(
            "VFIO read_bar_u32: BAR{bar_index} size={:#x} too small for offset={:#x}+4",
            info.size, register_offset
        );
        return None;
    }

    let mut buf = [0u8; 4];
    // SAFETY: pread on a valid VFIO fd with validated offset and size.
    let nread = unsafe {
        libc::pread(
            dev_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            4,
            (info.offset + register_offset) as i64,
        )
    };
    if nread < 0 {
        warn!(
            "VFIO read_bar_u32: pread failed BAR{bar_index}+{register_offset:#x}: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    Some(u32::from_le_bytes(buf))
}


/// Parse the MSI capability registers at `cap_offset` in PCI config space.
pub(crate) fn parse_msi_at(dev_fd: std::os::fd::RawFd, config_off: u64, cap_offset: u16) -> Option<crate::vfio::device::MsiConfig> {
    use crate::vfio::device::MsiConfig;

    let max_end = cap_offset + 20;
    if max_end > 256 {
        tracing::trace!("VFIO MSI: capability at 0x{cap_offset:x} exceeds config space");
        return None;
    }

    let msg_ctrl = read_config_u32(dev_fd, config_off, cap_offset + 2, 2);

    let enabled = (msg_ctrl & 0x0001) != 0;
    let is_64bit = (msg_ctrl & 0x0080) != 0;
    let has_mask = (msg_ctrl & 0x0100) != 0;
    let multi_msg_enable = (msg_ctrl >> 4) & 0x7;
    let num_vectors = 1u32 << multi_msg_enable;

    let addr_lo = read_config_u32(dev_fd, config_off, cap_offset + 4, 4);

    let (addr_hi, data_offset) = if is_64bit {
        let hi = read_config_u32(dev_fd, config_off, cap_offset + 8, 4);
        (hi, cap_offset + 12)
    } else {
        (0u32, cap_offset + 8)
    };

    let data = read_config_u32(dev_fd, config_off, data_offset, 2) as u16;

    Some(MsiConfig {
        address_lo: addr_lo,
        address_hi: addr_hi,
        data,
        num_vectors,
        is_64bit,
        has_per_vector_mask: has_mask,
        enabled,
    })
}
