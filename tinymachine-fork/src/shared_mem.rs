//! EPT Shared Memory — zero-copy read-only shared memory for KVM guests
//!
//! Maps a host memory region into KVM guest physical address space as read-only.
//! Multiple forks share the same physical memory via EPT (Extended Page Tables),
//! enabling zero-copy access to large datasets (LLM models, corpora, etc.)
//! without per-fork duplication.
//!
//! # Design
//! - Host creates a memfd or opens a file, mmap's it `MAP_SHARED`.
//! - `ept_map()` calls `KVM_SET_USER_MEMORY_REGION` with `KVM_MEM_READONLY` flag.
//! - Guest sees the memory at the specified physical address, read-only.
//! - Host can still write via `write()` (the RO restriction applies to guest writes
//!   at the EPT level — host-side writes go through the shared mapping).
//!
//! # Safety
//! This module uses raw `mmap`/`munmap` and raw `ioctl` for KVM operations.
//! Every `unsafe` block is documented with `// SAFETY:`.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

use thiserror::Error;
use tracing::info;

use crate::kvm;

// ─── KVM Constants ────────────────────────────────────────────────────

/// `KVM_MEM_READONLY` flag for `KVM_SET_USER_MEMORY_REGION`.
/// Value from `<linux/kvm.h>`: `(1UL << 1)` = 2.
const KVM_MEM_READONLY: u32 = 2;

/// Base slot number for shared memory regions.
/// Slot 0 is reserved for the primary snapshot memory in the fork engine.
const SHARED_MEM_SLOT_BASE: u32 = 1;

/// Maximum number of shared memory slots available (KVM max is 32).
const MAX_SHARED_SLOTS: u32 = 31;

// ─── Error Types ──────────────────────────────────────────────────────

/// Errors from shared memory operations.
#[derive(Error, Debug)]
pub enum SharedMemError {
    /// Error from the KVM subsystem.
    #[error("KVM error: {0}")]
    Kvm(#[from] kvm::KvmError),

    /// `mmap` syscall failed.
    #[error("mmap failed: {0}")]
    Mmap(String),

    /// `memfd_create` syscall failed.
    #[error("memfd_create failed: {0}")]
    MemfdCreate(String),

    /// I/O error (file operations, ftruncate, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid size specified (zero or overflow).
    #[error("Invalid size: {0}")]
    InvalidSize(String),

    /// No free slot available for EPT mapping.
    #[error("No free slot: all {max} slots are in use")]
    NoFreeSlot { max: u32 },
}

/// Result alias for shared memory operations.
pub type Result<T> = std::result::Result<T, SharedMemError>;

// ─── Shared Memory Region ─────────────────────────────────────────────

/// A shared memory region mapped read-only into KVM guest via EPT.
///
/// The region is created on the host (via file mmap or anonymous memfd)
/// and then injected into KVM guests as a read-only memory region.
/// Multiple VMs can share the same physical memory through EPT.
///
/// # Thread Safety
/// - `Send`: Safe — the region owns its mmap exclusively; moving between
///   threads transfers ownership safely (kernel handles page table coherency).
/// - `Sync`: NOT implemented — concurrent reads via `&self` would race with
///   kernel EPT updates during `KVM_RUN`.
pub struct SharedMemoryRegion {
    /// File descriptor backing the memory (memfd or regular file).
    host_fd: File,
    /// Host virtual address of the mmap'd region.
    /// Mapped `PROT_READ | PROT_WRITE` for host-side writes,
    /// but exposed read-only to guests via EPT.
    host_ptr: *mut u8,
    /// Size of the region in bytes.
    size: u64,
    /// Guest physical address where this region is mapped (0 if unmapped).
    guest_phys: u64,
}

impl std::fmt::Debug for SharedMemoryRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedMemoryRegion")
            .field("host_fd", &self.host_fd.as_raw_fd())
            .field("size", &self.size)
            .field(
                "guest_phys",
                &format_args!("{:#x}", self.guest_phys),
            )
            .field("host_ptr", &self.host_ptr)
            .finish()
    }
}

// SAFETY:
// - `SharedMemoryRegion` owns its mmap'd memory exclusively. The `File` owns
//   the fd, and the `*mut u8` points to the mmap'd region.
// - Moving a `SharedMemoryRegion` between threads transfers ownership of the
//   mmap. The kernel handles page table coherency across threads.
// - `Sync` is deliberately NOT implemented because concurrent reads via `&self`
//   would race with kernel EPT updates during `KVM_RUN`.
unsafe impl Send for SharedMemoryRegion {}

impl Drop for SharedMemoryRegion {
    fn drop(&mut self) {
        if !self.host_ptr.is_null() && self.size > 0 {
            // SAFETY:
            // - `self.host_ptr` was obtained from a successful `mmap` call of
            //   `self.size` bytes in `new()`, `new_anon()`, or `new_custom()`.
            // - No other code holds a reference to this memory after drop.
            // - `munmap` is safe to call on valid mappings; the kernel tracks
            //   the mapping and will unmap it atomically. Double-unmap is
            //   prevented by the `if` guard.
            // - The `File` (`self.host_fd`) is dropped after this, closing the
            //   fd, but the mmap remains valid until munmap'd.
            unsafe {
                libc::munmap(
                    self.host_ptr as *mut libc::c_void,
                    self.size as libc::size_t,
                );
            }
        }
    }
}

impl SharedMemoryRegion {
    /// Create a shared memory region from an existing file.
    ///
    /// Opens the file, mmap's it `MAP_SHARED | PROT_READ`, and prepares it
    /// for EPT injection into KVM guests.
    ///
    /// # Errors
    /// - Returns `SharedMemError::InvalidSize` if the file is empty.
    /// - Returns `SharedMemError::Io` if the file cannot be opened or read.
    /// - Returns `SharedMemError::Mmap` if the mmap call fails.
    pub fn new(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        if size == 0 {
            return Err(SharedMemError::InvalidSize(format!(
                "file '{}' is empty",
                path.display()
            )));
        }

        // SAFETY:
        // - `file` is a valid, open fd from `File::open`.
        // - `MAP_SHARED | PROT_READ` creates a shared read-only mapping of the file
        //   contents. The kernel will read the file's pages on demand.
        // - `mmap` returns `MAP_FAILED` on error, which we check explicitly.
        // - The file's size is non-zero (verified above) and fits in `libc::size_t`.
        let host_ptr = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                size as libc::size_t,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(SharedMemError::Mmap(format!(
                    "mmap of file '{}' ({} bytes) failed",
                    path.display(),
                    size,
                )));
            }
            ptr as *mut u8
        };

        info!(
            target: "tinyos::shared_mem",
            "mmap'd shared memory from '{}': {} bytes at {:p}",
            path.display(),
            size,
            host_ptr,
        );

        Ok(Self {
            host_fd: file,
            host_ptr,
            size,
            guest_phys: 0,
        })
    }

    /// Create an anonymous shared memory region of the given size.
    ///
    /// Uses `memfd_create` to obtain an anonymous file descriptor, sets its
    /// size with `ftruncate`, and mmap's it `MAP_SHARED | PROT_READ | PROT_WRITE`.
    /// The region is zero-initialized.
    ///
    /// # Errors
    /// - Returns `SharedMemError::InvalidSize` if `size` is 0.
    /// - Returns `SharedMemError::MemfdCreate` if `memfd_create` fails.
    /// - Returns `SharedMemError::Mmap` if the mmap call fails.
    pub fn new_anon(size: u64) -> Result<Self> {
        if size == 0 {
            return Err(SharedMemError::InvalidSize(
                "anonymous region size must be > 0".into(),
            ));
        }

        // SAFETY:
        // - `memfd_create` is a Linux syscall (since kernel 3.17) that creates an
        //   anonymous file and returns a valid fd. The name is only used for
        //   debugging (appears in `/proc/self/fd/`).
        // - `MFD_CLOEXEC` ensures the fd is closed on `exec()` (security best practice).
        // - On error, returns -1 and sets errno.
        let fd = unsafe {
            // This hardcoded string has no null bytes, so CString::new cannot fail.
            let name =
                CString::new("tinyos-shared-mem").unwrap();
            let ret = libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC);
            if ret < 0 {
                return Err(SharedMemError::MemfdCreate(
                    "memfd_create syscall returned -1".into(),
                ));
            }
            ret
        };

        // SAFETY: `fd` is a valid fd from `memfd_create` (checked above).
        let file = unsafe { File::from_raw_fd(fd) };

        // Set the size of the memfd. `set_len` corresponds to `ftruncate`.
        file.set_len(size)?;

        // SAFETY:
        // - `file` is a valid fd from `memfd_create`, now with `size` bytes.
        // - `MAP_SHARED | PROT_READ | PROT_WRITE` creates a shared read-write mapping
        //   on the host side. We map RW so the host can write data into the region
        //   (via `write()`) before or while guests access it read-only via EPT.
        // - The guest only sees the region as read-only (enforced by `KVM_MEM_READONLY`
        //   in `ept_map()`). The host's RW mapping is independent of the guest's EPT
        //   permissions.
        // - `mmap` returns `MAP_FAILED` on error.
        let host_ptr = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(SharedMemError::Mmap(format!(
                    "mmap of anonymous shared memory ({} bytes) failed",
                    size,
                )));
            }
            ptr as *mut u8
        };

        info!(
            target: "tinyos::shared_mem",
            "created anonymous shared memory: {} bytes at {:p}",
            size,
            host_ptr,
        );

        Ok(Self {
            host_fd: file,
            host_ptr,
            size,
            guest_phys: 0,
        })
    }

    /// Map this shared region into a KVM guest as read-only via EPT.
    ///
    /// Calls `KVM_SET_USER_MEMORY_REGION` with the `KVM_MEM_READONLY` flag.
    /// The region becomes visible to the guest at `guest_phys` with read-only
    /// permissions enforced by the EPT hardware.
    ///
    /// # Arguments
    /// * `vm` - The KVM VM to map into (must have a valid VM fd).
    /// * `guest_phys` - The guest physical address where the region should appear.
    /// * `slot_offset` - Offset from `SHARED_MEM_SLOT_BASE` (0 = first shared slot).
    ///   Must be < `MAX_SHARED_SLOTS` to avoid exceeding KVM's max slot count.
    ///
    /// # Errors
    /// - Returns `SharedMemError::NoFreeSlot` if `slot_offset >= MAX_SHARED_SLOTS`.
    /// - Returns `SharedMemError::Kvm` if the KVM ioctl fails (e.g., slot conflict,
    ///   overlapping region, invalid guest_phys).
    pub fn ept_map(&self, vm: &kvm::Vm, kvm_fd: RawFd, guest_phys: u64, slot_offset: u32) -> Result<()> {
        if slot_offset >= MAX_SHARED_SLOTS {
            return Err(SharedMemError::NoFreeSlot {
                max: MAX_SHARED_SLOTS,
            });
        }

        let slot = SHARED_MEM_SLOT_BASE + slot_offset;

        // CRITICAL: Verify that the host kernel supports KVM_MEM_READONLY.
        // If the kernel does NOT support this capability, KVM silently ignores
        // the readonly flag and maps the region as read-write, allowing guest
        // code to corrupt shared data (LLM model weights, datasets) visible
        // to all other tenants. This is a sandbox escape / cross-tenant data
        // corruption vulnerability.
        //
        // See: https://docs.kernel.org/virt/kvm/api.html#kvm-cap-readonly-mem
        // SAFETY: kvm_fd must be a valid /dev/kvm fd (caller guarantees this).
        if unsafe { !vm.has_readonly_mem(kvm_fd).unwrap_or(false) } {
            return Err(SharedMemError::Kvm(kvm::KvmError::Capability {
                cap: kvm::KVM_CAP_READONLY_MEM,
            }));
        }

        // SAFETY:
        // - `self.host_ptr` points to a valid mmap region of `self.size` bytes
        //   (verified in `new()`, `new_anon()`, etc.).
        // - `vm` is a valid KVM VM handle (owned by the caller, typically a `ForkedVm`).
        // - `KVM_MEM_READONLY` (flag=2) marks the region read-only in the guest's EPT.
        //   The guest will trigger an EPT violation on write attempts.
        // - `slot` must not conflict with other regions; the caller is responsible
        //   for slot allocation (slot 0 = snapshot, slots 1+ = shared regions).
        unsafe {
            vm.set_memory_region(
                slot,
                guest_phys,
                self.size,
                self.host_ptr,
                KVM_MEM_READONLY,
            )?;
        }

        info!(
            target: "tinyos::shared_mem",
            "EPT-mapped shared memory: {} bytes at guest phys {:#x} (slot {}, RO)",
            self.size,
            guest_phys,
            slot,
        );

        Ok(())
    }

    /// Write data into the shared region at the given offset.
    ///
    /// This modifies the host-side memory, which is then visible to all
    /// guest VMs that have this region EPT-mapped as read-only.
    ///
    /// # Important
    /// RO at the EPT level means guests cannot write to this memory.
    /// The **host** can still write through this method (the host-side
    /// mmap is `PROT_READ | PROT_WRITE`). This allows the orchestrator
    /// to update shared data (e.g., model weights) without unmapping.
    ///
    /// # Errors
    /// Returns `SharedMemError::InvalidSize` if `offset + data.len()` exceeds
    /// the region size or if the offset arithmetic overflows.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| SharedMemError::InvalidSize("offset overflow".into()))?;

        if end > self.size {
            return Err(SharedMemError::InvalidSize(format!(
                "write of {} bytes at offset {} exceeds region size {}",
                data.len(),
                offset,
                self.size,
            )));
        }

        // SAFETY:
        // - `self.host_ptr` is a valid mmap region of `self.size` bytes,
        //   mapped `PROT_READ | PROT_WRITE`.
        // - `offset + data.len() <= self.size` is verified above, so the
        //   destination range is entirely within the mapped region.
        // - `data.as_ptr()` and `self.host_ptr.add(offset)` do not overlap
        //   (copy_nonoverlapping precondition). Since `data` is a separate
        //   allocation, overlap is impossible.
        // - The write is visible to all guest VMs sharing this region because
        //   the mmap is `MAP_SHARED` — the kernel ensures coherency.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.host_ptr.add(offset as usize),
                data.len(),
            );
        }

        Ok(())
    }

    /// Read data from the shared region at the given offset.
    ///
    /// Returns a `Vec<u8>` of `len` bytes from the region.
    ///
    /// # Errors
    /// Returns `SharedMemError::InvalidSize` if the read range exceeds the region.
    pub fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| SharedMemError::InvalidSize("read offset overflow".into()))?;

        if end > self.size {
            return Err(SharedMemError::InvalidSize(format!(
                "read of {} bytes at offset {} exceeds region size {}",
                len, offset, self.size,
            )));
        }

        let mut buf = vec![0u8; len];

        // SAFETY:
        // - `self.host_ptr` is a valid mmap region of `self.size` bytes.
        // - `offset + len <= self.size` verified above.
        // - The source and destination do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.host_ptr.add(offset as usize),
                buf.as_mut_ptr(),
                len,
            );
        }

        Ok(buf)
    }

    /// Return the host pointer (for direct read access by other Rust code).
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The returned pointer is not used after `self` is dropped.
    /// - Reads through the pointer are safe with concurrent `KVM_RUN` on
    ///   any guest sharing this region.
    pub unsafe fn as_ptr(&self) -> *mut u8 {
        self.host_ptr
    }

    /// Size of the shared region in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Guest physical address where this region is mapped (0 if not yet mapped).
    pub fn guest_phys(&self) -> u64 {
        self.guest_phys
    }

    /// The raw file descriptor backing this shared memory.
    pub fn raw_fd(&self) -> std::os::raw::c_int {
        self.host_fd.as_raw_fd()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_mem_new_anon() {
        let region = SharedMemoryRegion::new_anon(4096).expect("should create 4K region");
        assert_eq!(region.size(), 4096);
        assert!(!region.host_ptr.is_null());
        assert_eq!(region.guest_phys(), 0);
    }

    #[test]
    fn test_shared_mem_write_and_read() {
        let mut region = SharedMemoryRegion::new_anon(4096).unwrap();
        let data = b"hello shared memory!";
        region.write(0, data).unwrap();

        let read_back = region.read(0, data.len()).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_shared_mem_write_at_offset() {
        let mut region = SharedMemoryRegion::new_anon(4096).unwrap();
        region.write(100, b"offset-data").unwrap();

        let read_back = region.read(100, 11).unwrap();
        assert_eq!(read_back, b"offset-data");

        // Data before offset should still be zero
        let before = region.read(0, 100).unwrap();
        assert_eq!(before, vec![0u8; 100]);
    }

    #[test]
    fn test_shared_mem_write_past_end() {
        let mut region = SharedMemoryRegion::new_anon(100).unwrap();
        let result = region.write(99, b"too long"); // writes 9 bytes at offset 99 → exceeds 100
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_mem_zero_size_rejected() {
        let result = SharedMemoryRegion::new_anon(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_mem_from_file() {
        // Create a temp file
        let dir = std::env::temp_dir().join("tinyos-test-shared-mem");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.data");
        std::fs::write(&path, b"shared memory file content").unwrap();

        let region = SharedMemoryRegion::new(&path).expect("should create from file");
        assert!(region.size() > 0);

        // Clean up
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_shared_mem_read_exact() {
        let mut region = SharedMemoryRegion::new_anon(64).unwrap();
        let pattern: Vec<u8> = (0..64).collect();
        region.write(0, &pattern).unwrap();

        let read = region.read(10, 20).unwrap();
        assert_eq!(read, pattern[10..30]);
    }

    #[test]
    fn test_shared_mem_read_past_end() {
        let region = SharedMemoryRegion::new_anon(10).unwrap();
        let result = region.read(5, 10); // offset 5 + len 10 = 15 > 10
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_mem_is_send() {
        // Compile-time check: SharedMemoryRegion implements Send.
        // If Send were not implemented, this would fail to compile.
        fn assert_send<T: Send>() {}
        assert_send::<SharedMemoryRegion>();
    }

    #[test]
    fn test_shared_mem_drop_doesnt_crash() {
        // Create and drop a region — should not panic or leak
        let region = SharedMemoryRegion::new_anon(1024).unwrap();
        drop(region);
        // If we get here, drop succeeded
    }

    #[test]
    fn test_shared_mem_fd_is_valid() {
        let region = SharedMemoryRegion::new_anon(4096).unwrap();
        let fd = region.raw_fd();
        assert!(fd >= 0);

        // Verify fd is valid by fstat
        // SAFETY: fd is from memfd_create or open, both return valid fds.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd, &mut stat) };
        assert_eq!(ret, 0, "fstat should succeed on valid fd");
    }
}
