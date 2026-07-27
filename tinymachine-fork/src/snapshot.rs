//! Snapshot save/restore — memory dump + CPU state serialization
//!
//! A snapshot captures the entire VM state after boot so that forks
//! can start from a known good state without rebooting.
//!
//! # Format (Phase 0 — minimal)
//! - Memory dump: raw bytes of guest RAM
//! - CPU state: JSON-serialized register file

use std::fs::File;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

/// Serializable state of a VirtioNetPci device for snapshot save/restore.
///
/// This is saved after the guest kernel has fully initialized the device
/// (written queue PFNs, negotiated features, set DRIVER_OK). On fork,
/// a new TAP fd is connected and the device resumes operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioNetState {
    pub selected_queue: u32,
    pub queue_pfns: [u64; 2],
    pub queue_sizes: [u16; 2],
    pub guest_features: u32,
    pub device_features: u32,
    pub status: u8,
    pub isr: u8,
    pub irq_line: u8,
    pub bar0_shadow: u32,
    pub next_rx_idx: u16,
    pub intr_pending: bool,
}

use crate::arch::{RESERVED_MMIO_REGIONS, XSAVE_SIZE};
pub use crate::arch::target::snapshot_types::{
    CpuState, DescTable, IrqChipState, KvmRegs, KvmSregs, Segment, XsaveBuffer,
};

/// Maximum allowed snapshot memory size (1 GB)
/// Prevents OOM from malicious/corrupted snapshot files.
const MAX_SNAPSHOT_MEMORY_SIZE: u64 = 1_073_741_824;

/// Errors related to snapshot operations
#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid snapshot: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, SnapshotError>;

/// Metadata stored in `meta.json` alongside the snapshot.
///
/// Includes kernel identity for integrity verification: when a snapshot
/// is loaded, the stored `kernel_hash` is compared against the actual
/// kernel file's SHA-256 to detect stale snapshots after a rebuild.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapMeta {
    /// Format version (currently 1)
    pub version: u32,
    /// Guest physical address where memory is loaded
    pub load_addr: u64,
    /// Total size of guest memory in bytes
    pub memory_size: u64,
    /// Format string (e.g., "raw")
    pub format: String,
    /// Whether XSAVE data is present
    pub has_xsave: bool,
    /// Optional blake3 checksum of memory for integrity verification
    pub mem_checksum: Option<String>,
    /// Kernel version used to build this snapshot (e.g., "7.1.4")
    #[serde(default)]
    pub kernel_version: String,
    /// SHA-256 hash of the kernel binary at the time of snapshot creation
    #[serde(default)]
    pub kernel_hash: String,
}

impl SnapMeta {
    /// Create a new SnapMeta with kernel identity information.
    pub fn new(
        load_addr: u64,
        memory_size: u64,
        has_xsave: bool,
        mem_checksum: Option<String>,
        kernel_version: &str,
        kernel_hash: &str,
    ) -> Self {
        Self {
            version: 1,
            load_addr,
            memory_size,
            format: "raw".into(),
            has_xsave,
            mem_checksum,
            kernel_version: kernel_version.to_string(),
            kernel_hash: kernel_hash.to_string(),
        }
    }
}

/// A complete snapshot: memory + CPU state + XSAVE + IRQCHIP
///
/// # Lazy Memory Loading
///
/// `Snapshot::load()` opens the memory file (mem) but does **not** read
/// its contents into RAM. The `memory` field is left empty (`vec![]`).
/// Instead, the file descriptor is kept in `mem_fd` for CoW mmap in
/// `ForkEngine::fork()`. This avoids allocating 512 MB on every load.
///
/// If code needs to access memory contents (e.g. `read_mem()` or `save()`),
/// call `ensure_memory_loaded()` first — it reads from `mem_fd` on demand.
/// Freshly-captured snapshots (from `capture_snapshot()`) always have a
/// populated `memory` Vec.
#[derive(Debug)]
pub struct Snapshot {
    /// Guest physical memory (raw bytes).
    /// Empty (`vec![]`) after `load()`. Populated for fresh captures or
    /// after calling `ensure_memory_loaded()`.
    pub memory: Vec<u8>,
    /// Total size of guest memory (always valid, even when `memory` is empty).
    pub memory_size: u64,
    /// CPU register state
    pub cpu: CpuState,
    /// Guest physical address where memory is loaded (usually 0 or 0x100000)
    pub load_addr: u64,
    /// XSAVE area (FPU/SSE/AVX state on x86) — `XsaveBuffer` bytes.
    /// Stored separately from CPU state JSON as a raw binary file (xsave.bin).
    /// `None` for legacy snapshots or if the host doesn't support XSAVE.
    /// On aarch64, FP/SIMD state is managed via KVM_GET_ONE_REG (placeholder).
    pub xsave: Option<XsaveBuffer>,
    /// In-kernel irqchip states (PIC master, PIC slave, IOAPIC).
    /// Must be saved and restored together with the VM to ensure correct
    /// interrupt delivery after fork. Without this, timer IRQ 0 may not fire.
    pub irqchips: Option<IrqChipState>,
    /// File descriptor for the snapshot mem file.
    /// When `Some`, `ForkEngine::fork()` can `mmap(MAP_PRIVATE, fd)`
    /// to get kernel-level CoW instead of copying `memory` Vec<u8>.
    /// This reduces fork latency from O(RAM) to O(page_table).
    pub mem_fd: Option<File>,
    /// Optional virtio-net device state saved after guest initialization.
    /// Restored on fork so Tier 2 (ForkedVm) inherits guest networking.
    pub virtio_net_state: Option<VirtioNetState>,
    /// Kernel version used to build this snapshot (for integrity verification)
    pub kernel_version: String,
    /// SHA-256 hash of the kernel binary at snapshot creation time
    pub kernel_hash: String,
}

// Manual Clone: File is not Clone, so we skip mem_fd.
impl Clone for Snapshot {
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            memory_size: self.memory_size,
            cpu: self.cpu.clone(),
            load_addr: self.load_addr,
            xsave: self.xsave,
            irqchips: self.irqchips.clone(),
            mem_fd: None, // File is not Clone — reopened on load
            kernel_version: self.kernel_version.clone(),
            kernel_hash: self.kernel_hash.clone(),
            virtio_net_state: self.virtio_net_state.clone(),
        }
    }
}

impl Snapshot {
    /// Save snapshot to a directory
    ///
    /// Files:
    /// - `mem` — raw memory dump
    /// - `state.json` — CPU state JSON
    /// - `meta.json` — metadata (load addr, size, version)
    ///
    /// All files are created with 0o600 permissions (user-only access).
    ///
    /// If `self.memory` is empty (lazy-loaded snapshot), the function
    /// reads guest memory from `self.mem_fd` on demand.
    pub fn save(&self, dir: &Path) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::create_dir_all(dir)?;

        // Write mem file with 0o600 permissions
        let mut mem_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("mem"))?;

        if !self.memory.is_empty() {
            // Fast path: we have the Vec — write directly
            mem_file.write_all(&self.memory)?;
        } else if let Some(ref fd) = self.mem_fd {
            // Lazy path: memory Vec is empty, read from mem_fd and write
            // We need a mutable File to seek+read. Use try_clone to get
            // a separate handle (avoids &mut self).
            let mut reader = fd.try_clone().map_err(SnapshotError::Io)?;
            reader.seek(SeekFrom::Start(0)).map_err(SnapshotError::Io)?;
            let mut buf = vec![0u8; self.memory_size as usize];
            reader.read_exact(&mut buf).map_err(SnapshotError::Io)?;
            mem_file.write_all(&buf)?;
        } else {
            // Neither memory Vec nor mem_fd — error (shouldn't happen)
            return Err(SnapshotError::Invalid(
                "cannot save: snapshot has no memory Vec and no mem_fd".into(),
            ));
        }
        mem_file.sync_all()?;

        // Write state.json with 0o600 permissions
        let mut state_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("state.json"))?;
        state_file.write_all(serde_json::to_string_pretty(&self.cpu)?.as_bytes())?;
        state_file.sync_all()?;

        // Compute blake3 checksum of memory for integrity verification
        let mem_checksum = if !self.memory.is_empty() {
            Some(blake3::hash(&self.memory).to_hex().to_string())
        } else if let Some(ref fd) = self.mem_fd {
            // Read from mem_fd and compute hash on the fly
            use std::io::Read;
            let mut reader = fd.try_clone().map_err(SnapshotError::Io)?;
            reader.seek(SeekFrom::Start(0)).map_err(SnapshotError::Io)?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = [0u8; 65536];
            loop {
                let n = reader.read(&mut buf).map_err(SnapshotError::Io)?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
            }
            Some(hasher.finalize().to_hex().to_string())
        } else {
            None
        };

        // Write meta.json with 0o600 permissions
        let meta = SnapMeta::new(
            self.load_addr,
            self.memory_size,
            self.xsave.is_some(),
            mem_checksum,
            &self.kernel_version,
            &self.kernel_hash,
        );
        let mut meta_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("meta.json"))?;
        meta_file.write_all(serde_json::to_string_pretty(&meta)?.as_bytes())?;
        meta_file.sync_all()?;

        // Write xsave.bin with 0o600 permissions (optional)
        if let Some(xsave) = &self.xsave {
            let mut xsave_file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(dir.join("xsave.bin"))?;
            xsave_file.write_all(xsave)?;
            xsave_file.sync_all()?;
        }

        // Write virtio_net.json (optional — only present when snapshot has networking)
        if let Some(ref vn) = self.virtio_net_state {
            let mut vn_file = std::fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(dir.join("virtio_net.json"))?;
            vn_file.write_all(serde_json::to_string_pretty(vn)?.as_bytes())?;
            vn_file.sync_all()?;
        }

        // Write irqchip0.bin, irqchip1.bin, irqchip2.bin (optional)
        if let Some(chips) = &self.irqchips {
            if let Some(mp) = &chips.master_pic {
                let mut f = std::fs::OpenOptions::new()
                    .write(true).create(true).truncate(true).mode(0o600)
                    .open(dir.join("irqchip0.bin"))?;
                f.write_all(mp.as_slice())?;
                f.sync_all()?;
            }
            if let Some(sp) = &chips.slave_pic {
                let mut f = std::fs::OpenOptions::new()
                    .write(true).create(true).truncate(true).mode(0o600)
                    .open(dir.join("irqchip1.bin"))?;
                f.write_all(sp.as_slice())?;
                f.sync_all()?;
            }
            if let Some(io) = &chips.ioapic {
                let mut f = std::fs::OpenOptions::new()
                    .write(true).create(true).truncate(true).mode(0o600)
                    .open(dir.join("irqchip2.bin"))?;
                f.write_all(io.as_slice())?;
                f.sync_all()?;
            }
        }

        Ok(())
    }

    /// Load snapshot from a directory
    ///
    /// **Lazy memory loading:** The memory file is opened and the fd kept for
    /// CoW mmap (`mem_fd`), but the contents are NOT read into the `memory`
    /// Vec. This avoids allocating 512 MB of RAM on every load. The loaded
    /// snapshot is immediately usable with `ForkEngine::fork()`.
    ///
    /// Call `ensure_memory_loaded()` if you need `read_mem()` or `save()`.
    ///
    /// Validates:
    /// - Memory file size does not exceed MAX_SNAPSHOT_MEMORY_SIZE (1 GB)
    /// - load_addr is page-aligned
    /// - load_addr + memory_size does not overflow u64
    /// - Memory region does not overlap with reserved MMIO regions (IOAPIC, LAPIC)
    pub fn load(dir: &Path) -> Result<Self> {
        // Check file size before reading to prevent OOM
        let mem_path = dir.join("mem");
        let mem_meta = std::fs::metadata(&mem_path)?;
        let memory_size = mem_meta.len();
        if memory_size > MAX_SNAPSHOT_MEMORY_SIZE {
            return Err(SnapshotError::Invalid(format!(
                "snapshot memory size {} exceeds maximum {}",
                memory_size, MAX_SNAPSHOT_MEMORY_SIZE
            )));
        }

        // Open mem file and keep the fd for CoW mmap during fork.
        // Do NOT read the contents into Vec — that would be 512MB alloc.
        let mem_file = File::open(&mem_path)?;

        // Verify file permissions: snapshot files should be user-only (0o600).
        // Group/other readable snapshots could leak guest memory contents
        // (kernel data, credentials, model weights) to other users on the system.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = mem_file.metadata()?.permissions();
            let mode = perms.mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "Snapshot mem file has group/other permissions: {:o}. \
                     Recommended: 0o600 (user-only).",
                    mode
                );
            }
        }

        let cpu: CpuState = {
            let data = std::fs::read_to_string(dir.join("state.json"))?;
            serde_json::from_str(&data)?
        };
        let meta: SnapMeta = {
            let data = std::fs::read_to_string(dir.join("meta.json"))?;
            serde_json::from_str(&data)?
        };

        // Verify mem checksum if present (forward compatibility: old snapshots may not have it)
        if let Some(ref stored_checksum) = meta.mem_checksum {
            use std::io::Read;
            let mut hasher = blake3::Hasher::new();
            let mut buf = [0u8; 65536];
            let mut verify_file = File::open(&mem_path)?;
            loop {
                let n = verify_file.read(&mut buf)?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
            }
            let computed = hasher.finalize().to_hex().to_string();
            if *computed != *stored_checksum {
                return Err(SnapshotError::Invalid(format!(
                    "snapshot mem checksum mismatch: stored={stored_checksum} computed={computed}"
                )));
            }
            tracing::debug!("Snapshot mem checksum OK: {stored_checksum}");
        }

        // Verify kernel hash integrity — if kernel_version and kernel_hash are present,
        // we compare against the actual kernel file on disk.
        if !meta.kernel_version.is_empty() && !meta.kernel_hash.is_empty() {
            let kernel_registry_path = dir.parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .map(|p| p.join("kernel"));
            if let Some(kreg_path) = kernel_registry_path {
                if kreg_path.exists() {
                    let version = &meta.kernel_version;
                    let profile = "base"; // primary check is against vmlinux-base
                    let kernel_path = kreg_path.join(format!("v{version}/vmlinux-{profile}"));

                    if kernel_path.exists() {
                        match crate::kernel_registry::KernelRegistry::verify_kernel_hash(
                            &kernel_path, &meta.kernel_hash,
                        ) {
                            Ok(()) => {
                                tracing::debug!(
                                    "Snapshot kernel integrity OK: version={}, hash={}",
                                    meta.kernel_version, meta.kernel_hash
                                );
                            }
                            Err(e) => {
                                return Err(SnapshotError::Invalid(format!(
                                    "Kernel changed since snapshot (hash mismatch). \
                                     Rebuild with 'tinyos template build': {e}"
                                )));
                            }
                        }
                    } else {
                        return Err(SnapshotError::Invalid(format!(
                            "Snapshot has kernel_version={} but kernel file not found at {}. \
                             Rebuild with 'tinyos template build'.",
                            meta.kernel_version,
                            kernel_path.display(),
                        )));
                    }
                }
            }
        }

        let load_addr = meta.load_addr;

        // Validate load_addr is page-aligned
        if load_addr & 0xFFF != 0 {
            return Err(SnapshotError::Invalid(format!(
                "load_addr 0x{:x} is not page-aligned",
                load_addr
            )));
        }

        // Validate no overflow
        if load_addr.checked_add(memory_size).is_none() {
            return Err(SnapshotError::Invalid(format!(
                "load_addr 0x{:x} + memory_size {} overflows",
                load_addr,
                memory_size
            )));
        }

        // Validate no overlap with reserved MMIO regions
        let end = load_addr + memory_size;
        for &(region_start, region_size) in RESERVED_MMIO_REGIONS {
            let region_end = region_start + region_size;
            if load_addr < region_end && end > region_start {
                return Err(SnapshotError::Invalid(format!(
                    "snapshot memory [0x{:x}, 0x{:x}) overlaps with reserved MMIO region [0x{:x}, 0x{:x})",
                    load_addr, end, region_start, region_end
                )));
            }
        }

        // Try to load xsave.bin (optional — legacy snapshots may not have it)
        let xsave_path = dir.join("xsave.bin");
        let xsave = if xsave_path.exists() {
            let data = std::fs::read(&xsave_path)?;
            if data.len() == XSAVE_SIZE {
                let mut arr = [0u8; XSAVE_SIZE];
                arr.copy_from_slice(&data);
                Some(arr)
            } else {
                return Err(SnapshotError::Invalid(format!(
                    "xsave.bin has {} bytes, expected {XSAVE_SIZE}", data.len()
                )));
            }
        } else {
            None
        };

        // Try to load irqchip files (optional — legacy snapshots may not have them)
        let irqchips = load_irqchips(dir)?;

        // Try to load virtio_net.json (optional — legacy snapshots may not have it)
        let virtio_net_path = dir.join("virtio_net.json");
        let virtio_net_state = if virtio_net_path.exists() {
            let data = std::fs::read_to_string(&virtio_net_path)?;
            serde_json::from_str(&data).ok()
        } else {
            None
        };

        Ok(Self {
            memory: Vec::new(),    // lazy — don't read 512MB into RAM
            memory_size,
            cpu,
            load_addr,
            xsave,
            irqchips,
            mem_fd: Some(mem_file),
            kernel_version: meta.kernel_version,
            kernel_hash: meta.kernel_hash,
            virtio_net_state,
        })
    }

    /// Ensure that `self.memory` is populated.
    ///
    /// After `SnapShot::load()`, the `memory` Vec is empty to avoid
    /// allocating 512 MB of RAM. Call this method before `read_mem()`
    /// or if you need random access to the guest memory contents.
    ///
    /// Has no effect if `memory` is already populated.
    pub fn ensure_memory_loaded(&mut self) -> Result<()> {
        if !self.memory.is_empty() {
            return Ok(()); // already loaded
        }
        if let Some(ref fd) = self.mem_fd {
            use std::io::Read;
            let mut buf = vec![0u8; self.memory_size as usize];
            // Re-open the file to get an independent fd for sequential reading
            // (File is Seek, so seek back to 0 if we reuse. But try_clone is cleaner.)
            let mut reader = fd.try_clone().map_err(SnapshotError::Io)?;
            reader.read_exact(&mut buf).map_err(SnapshotError::Io)?;
            self.memory = buf;
            Ok(())
        } else {
            Err(SnapshotError::Invalid(
                "cannot load memory: no mem_fd available".into(),
            ))
        }
    }

    /// Size of guest memory in bytes (always valid, even with lazy loading).
    pub fn memory_size(&self) -> u64 {
        self.memory_size
    }

    /// Size of snapshot on disk
    pub fn size_on_disk(&self) -> u64 {
        let mut size = self.memory_size
            + std::mem::size_of::<CpuState>() as u64;
        if self.xsave.is_some() {
            size += 4096;
        }
        size
    }

    /// Read a slice of guest memory from the snapshot.
    ///
    /// **Requires:** `self.memory` must be populated (call `ensure_memory_loaded()`
    /// first if the snapshot was loaded via `Snapshot::load()`).
    ///
    /// Returns `None` if the requested range extends beyond the snapshot memory.
    pub fn read_mem(&self, guest_phys: u64, len: usize) -> Option<&[u8]> {
        let offset = guest_phys.checked_sub(self.load_addr)?;
        let offset = offset as usize;
        if self.memory.is_empty() {
            // Lazy-loaded snapshot — caller forgot ensure_memory_loaded()
            return None;
        }
        if offset + len > self.memory.len() {
            return None;
        }
        Some(&self.memory[offset..offset + len])
    }
}

/// Load irqchip state files from a snapshot directory.
/// Each file is 520 bytes (struct kvm_irqchip). Returns None if none exist.
fn load_irqchips(dir: &Path) -> Result<Option<IrqChipState>> {
    let chip0_path = dir.join("irqchip0.bin");
    let chip1_path = dir.join("irqchip1.bin");
    let chip2_path = dir.join("irqchip2.bin");

    if !chip0_path.exists() && !chip1_path.exists() && !chip2_path.exists() {
        return Ok(None);
    }

    let load_chip = |path: &std::path::PathBuf, name: &str| -> Result<Option<Box<[u8; 512]>>> {
        if path.exists() {
            let data = std::fs::read(path)?;
            if data.len() == 512 {
                let mut arr = Box::new([0u8; 512]);
                arr.copy_from_slice(&data);
                Ok(Some(arr))
            } else {
                Err(SnapshotError::Invalid(format!(
                    "{} has {} bytes, expected 512", name, data.len()
                )))
            }
        } else {
            Ok(None)
        }
    };

    Ok(Some(IrqChipState {
        master_pic: load_chip(&chip0_path, "irqchip0.bin")?,
        slave_pic: load_chip(&chip1_path, "irqchip1.bin")?,
        ioapic: load_chip(&chip2_path, "irqchip2.bin")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;
    use std::path::PathBuf;

    #[test]
    fn test_snapshot_roundtrip() {
        let snap = test_helpers::test_snapshot();

        let dir = PathBuf::from("/tmp/tinyos-test-snapshot");
        let _ = std::fs::remove_dir_all(&dir);
        snap.save(&dir).unwrap();

        let mut loaded = Snapshot::load(&dir).unwrap();
        // After lazy load: memory_size is correct, but memory Vec is empty
        assert!(loaded.memory.is_empty(), "lazy load should leave memory empty");
        assert_eq!(loaded.memory_size, snap.memory_size());
        assert_eq!(loaded.cpu.regs.rip, 0x7c00);
        assert_eq!(loaded.cpu.sregs.cs.selector, 0x10);
        // ensure_memory_loaded() reads from the mem_fd
        loaded.ensure_memory_loaded().unwrap();
        assert_eq!(loaded.memory.len(), snap.memory.len());
        assert_eq!(loaded.memory, snap.memory);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
