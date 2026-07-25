//! NVIDIA GPU backend — GSP power pre-init + firmware loading
//!
//! This backend handles NVIDIA-specific VFIO passthrough initialization:
//! 1. Power pre-init after VFIO FLR (waking GSP/PCOPY0 domains)
//! 2. GSP Falcon firmware loading (bootloader IMEM/DMEM)
//! 3. Diagnostics reporting

use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use thiserror::Error;
use tracing::{debug, info, warn};

use crate::vfio::backend::GpuBackend;
use crate::vfio::base::VfioPassthroughBase;
use crate::vfio::device::{errno_after_ioctl, GpuDeviceInfo, VfioError};

// ─── Register offsets (relative to GSP Falcon base 0x118000) ────────
const GSP_BASE: usize = 0x118000;
const CPUCTL: usize = 0x100;
const BOOTVEC: usize = 0x104;
const DMACTL: usize = 0x10c;
const HWCFG2: usize = 0xf4;
const IMEMC: usize = 0x180;
const IMEMD: usize = 0x184;
const DMEMC: usize = 0x1c0;
const DMEMD: usize = 0x1c4;
const GSP_ENGINE_ABS: usize = 0x1103c0;

// ─── GSP Firmware Error ─────────────────────────────────────────────

#[derive(Error, Debug)]
enum GspError {
    #[error("Firmware file not found: {0}")]
    FileNotFound(String),
    #[error("Firmware file too small: {0} bytes")]
    FileTooSmall(usize),
    #[error("Invalid firmware magic: 0x{0:08x} (expected 0x000010de)")]
    InvalidMagic(u32),
    #[error("BAR0 mmap failed")]
    Bar0MmapFailed,
    #[error("IMEM write failed at word {0}")]
    ImemWriteFailed(usize),
    #[error("Falcon did not start (CPUCTL=0x{0:08x})")]
    FalconStartFailed(u32),
    #[error("Falcon engine reset failed")]
    EngineResetFailed,
    #[error("Decompression error: {0}")]
    DecompressError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── NvidiaGpuBackend ───────────────────────────────────────────────

/// NVIDIA GPU backend — handles GSP power init and firmware loading.
#[derive(Debug)]
pub struct NvidiaGpuBackend;

impl GpuBackend for NvidiaGpuBackend {
    fn name(&self) -> &'static str {
        "nvidia-gsp"
    }

    fn matches(device: &GpuDeviceInfo) -> bool {
        device.vendor_id == 0x10de
    }

    fn power_preinit(&self, base: &VfioPassthroughBase) -> std::result::Result<(), VfioError> {
        gpu_power_preinit(base)
    }

    fn load_firmware(&self, base: &VfioPassthroughBase) -> std::result::Result<(), VfioError> {
        gsp_load_firmware(base).map_err(|e| VfioError::Kvm(format!("GSP firmware load failed: {e}")))
    }

    fn post_boot_diagnostics(&self, base: &VfioPassthroughBase) -> String {
        match gsp_read_diagnostics(base) {
            Ok(diag) => diag.to_string(),
            Err(e) => format!("GSP diagnostics unavailable: {e}"),
        }
    }
}

// ─── Power Pre-Init (moved from VfioPassthrough) ────────────────────

/// Power-preinit the GPU after VFIO FLR to enable GSP + PCOPY0 domains.
fn gpu_power_preinit(base: &VfioPassthroughBase) -> std::result::Result<(), VfioError> {
    let bar0 = base
        .bar_regions()
        .iter()
        .find(|b| b.index == 0)
        .ok_or_else(|| VfioError::Ioctl {
            context: "gpu_power_preinit: BAR0 not found in bar_regions".into(),
            errno: 0,
        })?;

    if !bar0.can_mmap || bar0.size < 0x200 {
        return Err(VfioError::Ioctl {
            context: format!(
                "gpu_power_preinit: BAR0 not mmapable or too small (can_mmap={}, size={:#x})",
                bar0.can_mmap, bar0.size
            ),
            errno: 0,
        });
    }

    let dev_fd = base.device_fd().ok_or_else(|| VfioError::Ioctl {
        context: "gpu_power_preinit: device_fd not available".into(),
        errno: 0,
    })?;

    // mmap BAR0
    let bar0_ptr = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            bar0.size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            dev_fd,
            bar0.offset as i64,
        );
        if ptr == libc::MAP_FAILED {
            return Err(VfioError::Ioctl {
                context: format!(
                    "gpu_power_preinit: mmap BAR0 failed at VFIO offset {:#x}: {}",
                    bar0.offset,
                    std::io::Error::last_os_error()
                ),
                errno: errno_after_ioctl(),
            });
        }
        ptr as *mut u8
    };

    const PMC_ENABLE_OFFSET: usize = 0x200;

    // Read current PMC_ENABLE value
    let current_val = unsafe {
        std::ptr::read_volatile(bar0_ptr.add(PMC_ENABLE_OFFSET) as *const u32)
    };

    // Try writing NV_PMC_ENABLE bit 0 (GSP enable)
    let pmc_enable_new = current_val | 1;
    unsafe {
        std::ptr::write_volatile(bar0_ptr.add(PMC_ENABLE_OFFSET) as *mut u32, pmc_enable_new);
    }
    let _pmc_enable_verify = unsafe {
        std::ptr::read_volatile(bar0_ptr.add(PMC_ENABLE_OFFSET) as *const u32)
    };

    // Write NV_PMC_ENABLE_EXT at offset 0x20c
    const PMC_PG_CTRL_OFFSET: usize = 0x20c;
    let pg_ctrl = unsafe {
        std::ptr::read_volatile(bar0_ptr.add(PMC_PG_CTRL_OFFSET) as *const u32)
    };
    const PG_GSP: u32 = 1 << 8;
    let pg_new = pg_ctrl | PG_GSP;
    unsafe {
        std::ptr::write_volatile(bar0_ptr.add(PMC_PG_CTRL_OFFSET) as *mut u32, pg_new);
    }

    // Write 0xFFFFFFFF to register at 0x700
    let reg_700 = unsafe {
        std::ptr::read_volatile(bar0_ptr.add(0x700usize) as *const u32)
    };
    if reg_700 == 0xffffffff {
        unsafe {
            std::ptr::write_volatile(bar0_ptr.add(0x700usize) as *mut u32, 0xffffffffu32);
        }
    }

    try_power_gate_ctrl(bar0_ptr)?;

    // Also try PMC register writes via VFIO fd pwrite
    for &(name, reg_off, write_val) in &[
        ("NV_PMC_ENABLE", 0x200u64, 0x40000102u32),
        ("NV_PMC_PG_CTRL_EXT", 0x20cu64, 0x2000010cu32),
    ] {
        let val_bytes = write_val.to_le_bytes();
        let write_ret = unsafe {
            libc::pwrite(
                dev_fd,
                &val_bytes as *const u8 as *const libc::c_void,
                val_bytes.len(),
                (bar0.offset + reg_off) as i64,
            )
        };
        if write_ret < 0 {
            continue;
        }
    }

    // munmap BAR0
    unsafe {
        libc::munmap(bar0_ptr as *mut libc::c_void, bar0.size as usize);
    }

    Ok(())
}

/// Try to enable the GSP power domain via power-gate control registers.
fn try_power_gate_ctrl(bar0_ptr: *mut u8) -> std::result::Result<(), VfioError> {
    // ── Step 1: Probe NV_PMC_PG_CTRL registers (0x220-0x250) ──
    const PMC_PG_WINDOW: std::ops::Range<usize> = 0x220..0x250;
    for off in PMC_PG_WINDOW.step_by(4) {
        let _val: u32 = unsafe {
            std::ptr::read_volatile(bar0_ptr.add(off) as *const u32)
        };
    }

    // ── Step 2: Probe PBUS MODS registers ──
    const PBUS_BASE: usize = 0x0c0000;
    for module_idx in 0..16u32 {
        let mods_off = PBUS_BASE + 0x200 + (module_idx as usize) * 0x200;
        if mods_off + 4 > 0x1000000 {
            break;
        }
        let mods_val: u32 = unsafe {
            std::ptr::read_volatile(bar0_ptr.add(mods_off) as *const u32)
        };
        let is_poison = (mods_val & 0xbadf0000) == 0xbadf0000;
        if !is_poison && mods_val != 0 {
            unsafe {
                std::ptr::write_volatile(bar0_ptr.add(mods_off) as *mut u32, 0u32);
            }
        }
    }

    try_gsp_engine_reset(bar0_ptr)?;

    Ok(())
}

/// Try to de-assert the GSP falcon engine reset.
fn try_gsp_engine_reset(bar0_ptr: *mut u8) -> std::result::Result<(), VfioError> {
    // Try absolute GSP ENGINE at 0x1103c0
    let gsp_engine_val: u32 = unsafe {
        std::ptr::read_volatile(bar0_ptr.add(GSP_ENGINE_ABS) as *const u32)
    };
    let engine_poison = (gsp_engine_val & 0xbadf0000) == 0xbadf0000;
    if !engine_poison {
        if gsp_engine_val & 1 == 1 {
            unsafe { std::ptr::write_volatile(bar0_ptr.add(GSP_ENGINE_ABS) as *mut u32, 0u32); }
        }
    } else {
        unsafe { std::ptr::write_volatile(bar0_ptr.add(GSP_ENGINE_ABS) as *mut u32, 0u32); }
    }

    // Probe per-falcon bases
    const FALCON_BASES: &[usize] = &[0x118000, 0x110000, 0x11a000];

    for &falcon_base in FALCON_BASES {
        if falcon_base + 0x200 > 0x400000 {
            continue;
        }

        // Per-falcon ENGINE at base + 0x11000
        const PFE_ENGINE: usize = 0x11000;
        if falcon_base + PFE_ENGINE + 4 <= 0x400000 {
            unsafe { std::ptr::write_volatile(bar0_ptr.add(falcon_base + PFE_ENGINE) as *mut u32, 0u32); }

            // Power up CPUCTL
            unsafe { std::ptr::write_volatile(bar0_ptr.add(falcon_base + 0x100) as *mut u32, 0u32); }
            std::thread::sleep(std::time::Duration::from_micros(10));
            unsafe { std::ptr::write_volatile(bar0_ptr.add(falcon_base + 0x100) as *mut u32, 1u32); }
            std::thread::sleep(std::time::Duration::from_micros(10));

            // DMA engine reset: write DMACTL=0
            unsafe {
                std::ptr::write_volatile(bar0_ptr.add(falcon_base + 0x10c) as *mut u32, 0u32);
            }
            std::thread::sleep(std::time::Duration::from_micros(10));
        }
    }

    Ok(())
}

// ─── GSP Firmware Loading (moved from gsp.rs) ───────────────────────

/// Parse the Falcon firmware bootloader from a raw binary buffer.
fn parse_bootloader(data: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>, u32, u32), GspError> {
    if data.len() < 48 {
        return Err(GspError::FileTooSmall(data.len()));
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != 0x000010de {
        return Err(GspError::InvalidMagic(magic));
    }

    let hdr_off = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    if hdr_off + 24 > data.len() {
        return Err(GspError::FileTooSmall(data.len()));
    }
    let bl = &data[hdr_off..hdr_off + 24];
    let dmem_load = u32::from_le_bytes(bl[4..8].try_into().unwrap());
    let code_off = u32::from_le_bytes(bl[8..12].try_into().unwrap()) as usize;
    let code_sz = u32::from_le_bytes(bl[12..16].try_into().unwrap()) as usize;
    let data_off_bl = u32::from_le_bytes(bl[16..20].try_into().unwrap()) as usize;
    let data_sz = u32::from_le_bytes(bl[20..24].try_into().unwrap()) as usize;

    let code_start = hdr_off + code_off;
    let data_start = hdr_off + data_off_bl;

    if code_start + code_sz > data.len() {
        return Err(GspError::FileTooSmall(data.len()));
    }

    let imem_data = data[code_start..code_start + code_sz].to_vec();
    let dmem_data = if data_start + data_sz <= data.len() {
        data[data_start..data_start + data_sz].to_vec()
    } else {
        Vec::new()
    };

    Ok((imem_data, dmem_data, dmem_load, 0u32))
}

/// Decompress a `.zst` firmware file using the `zstd` command.
fn decompress_zst(path: &Path) -> std::result::Result<Vec<u8>, GspError> {
    let output = Command::new("zstd")
        .arg("-d")
        .arg(path)
        .arg("--stdout")
        .output()
        .map_err(|e| GspError::DecompressError(format!("zstd not found: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GspError::DecompressError(format!("zstd failed: {stderr}")));
    }

    Ok(output.stdout)
}

/// Load firmware from a decompressed file path.
fn load_firmware_from_file(path: &Path) -> std::result::Result<(Vec<u8>, Vec<u8>, u32, u32), GspError> {
    let raw = std::fs::read(path)?;
    parse_bootloader(&raw)
}

/// Load firmware from a `.zst` compressed file path.
fn load_firmware_from_zst(path: &Path) -> std::result::Result<(Vec<u8>, Vec<u8>, u32, u32), GspError> {
    let raw = decompress_zst(path)?;
    parse_bootloader(&raw)
}

/// Global mutex to prevent concurrent GSP firmware loading.
static GSP_LOCK: Mutex<()> = Mutex::new(());

/// Load GSP firmware for the given VFIO base session.
fn gsp_load_firmware(base: &VfioPassthroughBase) -> std::result::Result<(), GspError> {
    let bar0 = base
        .bar_regions()
        .iter()
        .find(|b| b.index == 0)
        .ok_or_else(|| GspError::Bar0MmapFailed)?;

    let dev_fd = base.device_fd().ok_or_else(|| GspError::Bar0MmapFailed)?;

    unsafe { load_gsp_firmware_inner(dev_fd, bar0.offset, bar0.size) }
}

/// Load the GSP bootloader into the Falcon and start it.
///
/// # Safety
///
/// - `dev_fd` must be a valid VFIO device fd for the target GPU
/// - The GPU must be in a state where BAR0 is accessible
/// - No other thread may access the GSP Falcon registers during this call
unsafe fn load_gsp_firmware_inner(
    dev_fd: i32,
    bar0_offset: u64,
    bar0_size: u64,
) -> std::result::Result<(), GspError> {
    let _lock = GSP_LOCK.lock();

    let bar0_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bar0_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            dev_fd,
            bar0_offset as i64,
        )
    };

    if bar0_ptr == libc::MAP_FAILED {
        return Err(GspError::Bar0MmapFailed);
    }

    let result = unsafe { gsp_load_inner(bar0_ptr as *mut u8, bar0_size as usize) };

    unsafe {
        libc::munmap(bar0_ptr, bar0_size as usize);
    }

    result
}

/// Inner firmware loading implementation.
///
/// # Safety
///
/// - `bar0_ptr` must point to a valid, writable mmap of BAR0
/// - `bar0_size` must be at least `GSP_BASE + 0x200`
unsafe fn gsp_load_inner(bar0_ptr: *mut u8, bar0_size: usize) -> std::result::Result<(), GspError> {
    if bar0_size < GSP_BASE + 0x200 {
        return Err(GspError::Bar0MmapFailed);
    }

    // 1. Assert + de-assert GSP engine reset
    let engine_reg = bar0_ptr.add(GSP_ENGINE_ABS) as *mut u32;
    let _engine_before = unsafe { std::ptr::read_volatile(engine_reg) };

    unsafe { std::ptr::write_volatile(engine_reg, 1u32); }
    std::thread::sleep(std::time::Duration::from_micros(200));
    unsafe { std::ptr::write_volatile(engine_reg, 0u32); }
    std::thread::sleep(std::time::Duration::from_micros(200));

    // Also reset per-falcon ENGINE at base+0x11000
    let pfe_engine_addr = GSP_BASE + 0x11000;
    if pfe_engine_addr + 4 <= bar0_size {
        let _pfe_engine = bar0_ptr.add(pfe_engine_addr) as *mut u32;
        unsafe { std::ptr::write_volatile(_pfe_engine, 1u32); }
        std::thread::sleep(std::time::Duration::from_micros(100));
        unsafe { std::ptr::write_volatile(_pfe_engine, 0u32); }
        std::thread::sleep(std::time::Duration::from_micros(100));
    }

    // Wait for Falcon to settle after reset
    for attempt in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let hwcfg2_now = unsafe {
            std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + HWCFG2) as *const u32)
        };
        let reset_ready = (hwcfg2_now >> 31) & 1;
        let scrubbing = (hwcfg2_now >> 12) & 1;
        if reset_ready == 1 && scrubbing == 0 {
            break;
        }
    }

    // 2. Wait for Falcon to be ready
    for attempt in 0..100 {
        let hwcfg2 = unsafe {
            std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + HWCFG2) as *const u32)
        };
        let reset_ready = (hwcfg2 >> 31) & 1;
        let scrubbing = (hwcfg2 >> 12) & 1;
        if reset_ready == 1 && scrubbing == 0 {
            break;
        }
        if attempt == 99 {
            return Err(GspError::EngineResetFailed);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // 3. Load IMEM data — find firmware at standard paths
    let fw_paths = [
        "/tmp/gsp_bl.bin",
        "/lib/firmware/nvidia/ad102/gsp/bootloader-570.144.bin.zst",
        "/lib/firmware/nvidia/ad102/gsp/bootloader-535.113.01.bin.zst",
    ];

    let (imem_data, dmem_data, dmem_load_addr, _entry) = {
        let mut loaded = None;
        for path_str in &fw_paths {
            let p = Path::new(path_str);
            if p.exists() {
                let result = if path_str.ends_with(".zst") {
                    load_firmware_from_zst(p)
                } else {
                    load_firmware_from_file(p)
                };
                match result {
                    Ok(fw) => {
                        info!("GSP: loaded firmware from {}", path_str);
                        loaded = Some(fw);
                        break;
                    }
                    Err(e) => {
                        warn!("GSP: failed to load {}: {e}", path_str);
                    }
                }
            }
        }
        loaded.ok_or_else(|| {
            GspError::FileNotFound("no bootloader firmware found at standard paths".into())
        })?
    };

    // 4. Write IMEM via IMEMC/IMEMD
    let imemc_reg = bar0_ptr.add(GSP_BASE + IMEMC) as *mut u32;
    let imemd_reg = bar0_ptr.add(GSP_BASE + IMEMD) as *mut u32;

    for (i, chunk) in imem_data.chunks(4).enumerate() {
        let word = if chunk.len() == 4 {
            u32::from_le_bytes(chunk.try_into().unwrap())
        } else {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(buf)
        };

        let dword_addr = i;
        let blk = dword_addr >> 6;
        let offs = dword_addr & 0x3F;
        let imemc_val = ((offs << 2) | (blk << 8) | (1 << 24)) as u32;

        unsafe {
            std::ptr::write_volatile(imemc_reg, imemc_val);
            std::ptr::write_volatile(imemd_reg, word);
        }
    }

    // 5. Write DMEM data if present
    if !dmem_data.is_empty() {
        let dmemc_reg = bar0_ptr.add(GSP_BASE + DMEMC) as *mut u32;
        let dmemd_reg = bar0_ptr.add(GSP_BASE + DMEMD) as *mut u32;

        for (i, chunk) in dmem_data.chunks(4).enumerate() {
            let word = if chunk.len() == 4 {
                u32::from_le_bytes(chunk.try_into().unwrap())
            } else {
                let mut buf = [0u8; 4];
                buf[..chunk.len()].copy_from_slice(chunk);
                u32::from_le_bytes(buf)
            };

            let dword_addr = (dmem_load_addr / 4) + i as u32;
            let blk = dword_addr >> 6;
            let offs = dword_addr & 0x3F;
            let dmemc_val = ((offs << 2) | (blk << 8) | (1 << 24)) as u32;

            unsafe {
                std::ptr::write_volatile(dmemc_reg, dmemc_val);
                std::ptr::write_volatile(dmemd_reg, word);
            }
        }
    }

    // 6. Set BOOTVEC
    let bootvec_reg = bar0_ptr.add(GSP_BASE + BOOTVEC) as *mut u32;
    unsafe { std::ptr::write_volatile(bootvec_reg, 0u32); }

    // 7. Start the Falcon
    let cpuctl_reg = bar0_ptr.add(GSP_BASE + CPUCTL) as *mut u32;
    unsafe { std::ptr::write_volatile(cpuctl_reg, 2u32); }
    std::thread::sleep(std::time::Duration::from_micros(50));

    let _cpuctl = unsafe { std::ptr::read_volatile(cpuctl_reg) };

    Ok(())
}

// ─── GSP Diagnostics ────────────────────────────────────────────────

struct GspDiagnostics {
    cpuctl: u32,
    bootvec: u32,
    hwcfg2: u32,
    dmactl: u32,
    mailbox0: u32,
    gsp_engine: u32,
    falcon_started: bool,
    falcon_halted: bool,
    reset_ready: bool,
    mem_scrubbing: bool,
    has_riscv: bool,
}

impl std::fmt::Display for GspDiagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GSP Diagnostics:\n\
             \x20 CPUCTL:      {:#010x} (started={}, halted={})\n\
             \x20 BOOTVEC:     {:#010x}\n\
             \x20 HWCFG2:      {:#010x} (riscv={}, scrubbing={}, reset_ready={})\n\
             \x20 DMACTL:      {:#010x}\n\
             \x20 MAILBOX0:    {:#010x}\n\
             \x20 GSP_ENGINE:  {:#010x}",
            self.cpuctl,
            self.falcon_started,
            self.falcon_halted,
            self.bootvec,
            self.hwcfg2,
            self.has_riscv,
            self.mem_scrubbing,
            self.reset_ready,
            self.dmactl,
            self.mailbox0,
            self.gsp_engine,
        )
    }
}

fn gsp_read_diagnostics(base: &VfioPassthroughBase) -> std::result::Result<GspDiagnostics, GspError> {
    let bar0 = base
        .bar_regions()
        .iter()
        .find(|b| b.index == 0)
        .ok_or_else(|| GspError::Bar0MmapFailed)?;

    let dev_fd = base.device_fd().ok_or_else(|| GspError::Bar0MmapFailed)?;

    let bar0_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bar0.size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            dev_fd,
            bar0.offset as i64,
        )
    };

    if bar0_ptr == libc::MAP_FAILED {
        return Err(GspError::Bar0MmapFailed);
    }

    let diag = unsafe { gsp_read_diag_inner(bar0_ptr as *mut u8, bar0.size as usize) };

    unsafe {
        libc::munmap(bar0_ptr, bar0.size as usize);
    }

    diag
}

unsafe fn gsp_read_diag_inner(bar0_ptr: *mut u8, bar0_size: usize) -> std::result::Result<GspDiagnostics, GspError> {
    if bar0_size < GSP_BASE + 0x200 {
        return Err(GspError::Bar0MmapFailed);
    }

    let cpuctl = unsafe { std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + CPUCTL) as *const u32) };
    let bootvec = unsafe { std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + BOOTVEC) as *const u32) };
    let hwcfg2 = unsafe { std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + HWCFG2) as *const u32) };
    let dmactl = unsafe { std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + DMACTL) as *const u32) };
    let mailbox0 = unsafe { std::ptr::read_volatile(bar0_ptr.add(GSP_BASE + 0x40) as *const u32) };
    let gsp_engine = unsafe { std::ptr::read_volatile(bar0_ptr.add(GSP_ENGINE_ABS) as *const u32) };

    Ok(GspDiagnostics {
        cpuctl,
        bootvec,
        hwcfg2,
        dmactl,
        mailbox0,
        gsp_engine,
        falcon_started: (cpuctl & 1) == 1,
        falcon_halted: ((cpuctl >> 4) & 1) == 1,
        reset_ready: ((hwcfg2 >> 31) & 1) == 1,
        mem_scrubbing: ((hwcfg2 >> 12) & 1) == 1,
        has_riscv: ((hwcfg2 >> 10) & 1) == 1,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootloader_valid() {
        let mut fw = Vec::new();
        fw.extend_from_slice(&0x000010deu32.to_le_bytes());
        fw.extend_from_slice(&1u32.to_le_bytes());
        fw.extend_from_slice(&0x100u32.to_le_bytes());
        fw.extend_from_slice(&24u32.to_le_bytes());
        fw.extend_from_slice(&0x100u32.to_le_bytes());
        fw.extend_from_slice(&0x100u32.to_le_bytes());
        fw.extend_from_slice(&5u32.to_le_bytes());
        fw.extend_from_slice(&0x8000u32.to_le_bytes());
        fw.extend_from_slice(&0x30u32.to_le_bytes());
        fw.extend_from_slice(&64u32.to_le_bytes());
        fw.extend_from_slice(&0x100u32.to_le_bytes());
        fw.extend_from_slice(&0u32.to_le_bytes());
        fw.resize(72 + 64, 0);
        for i in 0..16u32 {
            let off = 72 + i as usize * 4;
            fw[off..off + 4].copy_from_slice(&i.to_le_bytes());
        }

        let (imem, dmem, dmem_load, entry) = parse_bootloader(&fw).unwrap();
        assert_eq!(imem.len(), 64);
        assert_eq!(dmem.len(), 0);
        assert_eq!(dmem_load, 0x8000);
        assert_eq!(entry, 0);
    }

    #[test]
    fn test_parse_bootloader_invalid_magic() {
        let data = [0u8; 48];
        let result = parse_bootloader(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bootloader_too_small() {
        let data = [0u8; 4];
        let result = parse_bootloader(&data);
        assert!(result.is_err());
    }
}
