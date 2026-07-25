//! One-shot VBIOS ROM dumper using our VFIO+PCI infrastructure.
//! Run: cargo test --test dump_vbios -- --nocapture 2>&1
use std::fs;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

/// PCI BDF of the target GPU (RTX 4080 Max-Q Mobile)
const GPU_BDF: &str = "0000:01:00.0";

fn main() {
    // Open the VFIO group
    let iommu_group_path = format!("/sys/bus/pci/devices/{GPU_BDF}/iommu_group");
    let group_link = fs::read_link(&iommu_group_path).unwrap();
    let group_num: u32 = group_link
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();

    println!("IOMMU group: {group_num}");

    // Read VFIO PCI config directly from sysfs config file
    let config_path = format!("/sys/bus/pci/devices/{GPU_BDF}/config");
    let mut config = vec![0u8; 4096];
    fs::read(config_path)
        .map(|c| {
            config[..c.len()].copy_from_slice(&c);
        })
        .ok();

    // Read vendor/device IDs
    let vendor = u16::from_le_bytes([config[0], config[1]]);
    let device = u16::from_le_bytes([config[2], config[3]]);
    println!("GPU: {vendor:04x}:{device:04x}");

    // Read ROM BAR from PCI config at offset 0x30
    let rom_bar_raw = u32::from_le_bytes([
        config[0x30],
        config[0x31],
        config[0x32],
        config[0x33],
    ]);
    println!("ROM BAR (config+0x30): 0x{rom_bar_raw:08x}");

    // ── Method 1: Use the VFIO device's resource0 file (BAR0) at offset 0x300000 ──
    // This is where the PCI expansion ROM is shadowed on NVIDIA GPUs (tinygrad method)
    let resource0_path = format!("/sys/bus/pci/devices/{GPU_BDF}/resource0");
    let res0 = fs::metadata(&resource0_path).ok();
    println!("resource0 size: {:?}", res0.map(|m| m.len()));

    // Open resource0 and seek to 0x300000
    let mut f = fs::File::open(&resource0_path).unwrap();
    // Read at offset 0x300000
    let mut buf = vec![0u8; 0x200000]; // 2MB buffer
    match f.read_exact_at(&mut buf, 0x300000) {
        Ok(_) => {
            let sig = u16::from_le_bytes([buf[0], buf[1]]);
            println!("BAR0+0x300000: sig=0x{sig:04x}");
            if sig == 0xAA55 {
                // Parse PCIR header to find actual size
                let pcir_off =
                    u16::from_le_bytes([buf[0x18], buf[0x19]]) as usize;
                println!("PCIR header at offset 0x{pcir_off:x}");
                if pcir_off + 0x12 < buf.len() {
                    let rom_size_blocks =
                        u16::from_le_bytes([
                            buf[pcir_off + 0x10],
                            buf[pcir_off + 0x11],
                        ]);
                    let rom_size = rom_size_blocks as usize * 512;
                    println!("ROM size: {rom_size} bytes ({rom_size_blocks}*512)");
                    let rom_size = rom_size.min(buf.len());

                    // Dump the full ROM
                    let rom_data = &buf[..rom_size];
                    let out_path = "/tmp/vbios_dump.rom";
                    fs::write(out_path, rom_data).unwrap();
                    println!("Saved {rom_size} bytes to {out_path}");

                    // Also copy to the expected location
                    let home = std::env::var("HOME").unwrap_or_default();
                    let dest_dir = Path::new(&home).join(".tinymachine").join("vbios");
                    fs::create_dir_all(&dest_dir).ok();
                    let dest_path = dest_dir.join("Asus.RTX4080Mobile.12288.221219.rom");
                    fs::write(&dest_path, rom_data).ok();
                    println!("Also saved to {dest_path:?}");
                    return;
                }
            } else {
                println!("No VBIOS signature at BAR0+0x300000");
            }
        }
        Err(e) => {
            println!("read_exact_at BAR0+0x300000 failed: {e}");
        }
    }

    // ── Method 2: Try VFIO API directly ──
    println!("Method 1 failed. Trying VFIO API...");
    dump_via_vfio(group_num);
}

fn dump_via_vfio(group_num: u32) {
    use std::os::unix::io::AsRawFd;
    use std::mem;
    use std::ffi::CString;

    let container = fs::File::open("/dev/vfio/vfio").unwrap();
    let group_path = format!("/dev/vfio/{group_num}");
    let group = fs::File::open(&group_path).unwrap();

    // VFIO ioctl constants
    const VFIO_GROUP_GET_STATUS: u64 = 0x80085603; // from linux/vfio.h
    const VFIO_GROUP_SET_CONTAINER: u64 = 0x80085604;
    const VFIO_SET_IOMMU: u64 = 0x80085606;
    const VFIO_GROUP_GET_DEVICE_FD: u64 = 0x80085607;
    const VFIO_DEVICE_GET_INFO: u64 = 0x8004560d;
    const VFIO_DEVICE_GET_REGION_INFO: u64 = 0xc048560e;
    const VFIO_TYPE1_IOMMU: u32 = 1;

    let container_fd = container.as_raw_fd();
    let group_fd = group.as_raw_fd();

    // Get group status
    let mut gs: [u8; 8] = [0; 8]; // argsz=4, flags=4
    let p = gs.as_mut_ptr() as *mut u32;
    unsafe { *p = 8; }
    let ret = unsafe {
        libc::ioctl(group_fd, VFIO_GROUP_GET_STATUS as _, &gs)
    };
    println!("GROUP_GET_STATUS: ret={ret} flags=0x{:x}", unsafe {
        u32::from_ne_bytes([gs[4], gs[5], gs[6], gs[7]])
    });

    // Set container
    let ret = unsafe {
        libc::ioctl(group_fd, VFIO_GROUP_SET_CONTAINER as _, &container_fd)
    };
    println!("SET_CONTAINER: ret={ret}");

    // Set IOMMU type
    let mut iommu_type = VFIO_TYPE1_IOMMU;
    let ret = unsafe {
        libc::ioctl(container_fd, VFIO_SET_IOMMU as _, &iommu_type)
    };
    println!("SET_IOMMU: ret={ret}");

    if ret != 0 {
        // Try without container setup - just get device fd
        let ret = unsafe {
            libc::ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD as _, b"0000:01:00.0\0".as_ptr())
        };
        println!("GET_DEVICE_FD (direct): ret={ret}");
        if ret >= 0 {
            // Got device fd directly!
            let dev_fd = ret;
            read_rom_from_vfio(dev_fd);
            unsafe { libc::close(dev_fd); }
        } else {
            println!("Cannot get VFIO device fd");
        }
        return;
    }

    // Get device fd
    let dev_name = CString::new("0000:01:00.0").unwrap();
    let dev_fd = unsafe {
        libc::ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD as _, dev_name.as_ptr())
    };
    println!("GET_DEVICE_FD: ret={dev_fd}");

    if dev_fd >= 0 {
        read_rom_from_vfio(dev_fd);
        unsafe { libc::close(dev_fd); }
    }
}

fn read_rom_from_vfio(dev_fd: libc::c_int) {
    use std::mem;
    const VFIO_DEVICE_GET_REGION_INFO: u64 = 0xc048560e;

    // Get device info
    let mut di = [0u8; 16];
    let p = di.as_mut_ptr() as *mut u32;
    unsafe { *p = 16; }
    let ret = unsafe {
        libc::ioctl(dev_fd, 0x8004560d, &di)
    };
    println!("DEVICE_GET_INFO: ret={ret}");
    if ret != 0 { return; }
    let num_regions = unsafe {
        u32::from_ne_bytes([di[8], di[9], di[10], di[11]])
    };
    println!("num_regions={num_regions}");

    // Try ROM region (index 6)
    let mut ri = [0u8; 0x20];
    let p = ri.as_mut_ptr() as *mut u32;
    unsafe { *p = 0x20; }
    let p_idx = unsafe { ri.as_mut_ptr().add(4) as *mut u32 };
    unsafe { *p_idx = 6; } // ROM region index
    let ret = unsafe {
        libc::ioctl(dev_fd, VFIO_DEVICE_GET_REGION_INFO as _, &ri)
    };
    println!("ROM REGION_INFO: ret={ret}");
    if ret == 0 {
        let ri_flags = unsafe {
            u32::from_ne_bytes([ri[8], ri[9], ri[10], ri[11]])
        };
        let ri_size = unsafe {
            u64::from_ne_bytes([ri[16], ri[17], ri[18], ri[19], ri[20], ri[21], ri[22], ri[23]])
        };
        let ri_offset = unsafe {
            u64::from_ne_bytes([ri[24], ri[25], ri[26], ri[27], ri[28], ri[29], ri[30], ri[31]])
        };
        println!("ROM: flags=0x{ri_flags:x} size=0x{ri_size:x} offset=0x{ri_offset:x}");

        // Try reading via pread
        let mut buf = vec![0u8; ri_size as usize];
        let n = unsafe {
            libc::pread(dev_fd, buf.as_mut_ptr() as *mut _, ri_size as usize, ri_offset as i64)
        };
        println!("pread ROM: n={n}");
        if n > 0 {
            let sig = u16::from_le_bytes([buf[0], buf[1]]);
            println!("sig=0x{sig:04x}");
            if sig == 0xAA55 {
                let out_path = "/tmp/vbios_dump.rom";
                fs::write(out_path, &buf[..n as usize]).unwrap();
                println!("Saved {} bytes to {out_path}", n);
            }
        }
    } else {
        // Try BAR0 (index 0)
        let mut ri = [0u8; 0x20];
        let p = ri.as_mut_ptr() as *mut u32;
        unsafe { *p = 0x20; }
        let p_idx = unsafe { ri.as_mut_ptr().add(4) as *mut u32 };
        unsafe { *p_idx = 0; }
        let ret = unsafe {
            libc::ioctl(dev_fd, VFIO_DEVICE_GET_REGION_INFO as _, &ri)
        };
        if ret == 0 {
            let ri_size = unsafe {
                u64::from_ne_bytes([ri[16], ri[17], ri[18], ri[19], ri[20], ri[21], ri[22], ri[23]])
            };
            println!("BAR0: size=0x{ri_size:x}");
            // mmap BAR0
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    ri_size as usize,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    dev_fd,
                    0,
                )
            };
            if ptr != libc::MAP_FAILED {
                unsafe {
                    let sig_ptr = (ptr as *const u8).add(0x300000);
                    let sig = *(sig_ptr as *const u16);
                    println!("BAR0+0x300000 sig=0x{sig:04x}");
                    if sig == 0xAA55 {
                        let mut out = vec![0u8; 0x100000];
                        std::ptr::copy_nonoverlapping(sig_ptr, out.as_mut_ptr(), 0x100000);
                        fs::write("/tmp/vbios_dump.rom", &out).unwrap();
                        println!("Saved 1MB from BAR0+0x300000");
                    }
                    libc::munmap(ptr, ri_size as usize);
                }
            } else {
                println!("mmap BAR0 failed");
            }
        }
    }
}
