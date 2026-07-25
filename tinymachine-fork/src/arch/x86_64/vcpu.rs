//! x86_64-specific KVM Vcpu ioctl operations.
//!
//! These free functions wrap architecture-specific KVM ioctls that operate
//! on a VCPU fd. They are extracted from `crate::kvm::Vcpu` so that
//! architecture-agnostic code can dispatch to the correct implementation.
//!
//! Each function takes `vcpu_fd: RawFd` as the first parameter, allowing
//! the `Vcpu` struct in `kvm.rs` to delegate to these without exposing
//! its internal fd.
//!
//! # Safety
//! All functions use raw `libc::ioctl` to interact with the KVM kernel module.
//! Unsafe blocks are documented with `// SAFETY:`.

use std::os::fd::RawFd;
use std::ptr;

use crate::kvm::{errno_after_ioctl, KvmError, MpState, Result};
use crate::arch::cpu::CRITICAL_MSRS;
use crate::arch::kvm_types::*;

// ─── KVM-level CPUID query (uses /dev/kvm fd, not VCPU fd) ────────

/// Get the host's supported CPUID entries via `KVM_GET_SUPPORTED_CPUID`.
///
/// Returns all CPUID entries that the host KVM supports. These can be
/// passed directly to `set_cpuid2()` for a minimal guest setup.
///
/// Uses a generously large initial buffer (100 entries) because KVM doesn't
/// reliably report the required nent on the first probe call.
///
/// Note: This operates on the `/dev/kvm` fd (`kvm_fd`), not a VCPU fd.
/// It is placed here because CPUID is an x86 concept and the result feeds
/// directly into `set_cpuid2()`.
pub fn get_supported_cpuid(kvm_fd: RawFd) -> Result<Vec<KvmCpuidEntry2Raw>> {
    const DEFAULT_NENT: usize = 100;
    let entry_size = std::mem::size_of::<KvmCpuidEntry2Raw>();
    let header_size = std::mem::size_of::<KvmCpuid2Raw>();

    // Build the request buffer (zero-initialized for safe casting to KVM structs)
    let total_size = header_size + DEFAULT_NENT * entry_size;
    let mut buf: Vec<u8> = vec![0u8; total_size];

    // Write header with nent
    // SAFETY: buf has at least header_size bytes, aligned for KvmCpuid2Raw
    unsafe {
        let hdr = buf.as_mut_ptr() as *mut KvmCpuid2Raw;
        ptr::write(hdr, KvmCpuid2Raw {
            nent: DEFAULT_NENT as u32,
            padding: 0,
        });
    }

    // SAFETY: kvm_fd is a valid KVM fd, buf contains a valid kvm_cpuid2 with
    // enough space for DEFAULT_NENT entries.
    let ret = unsafe {
        libc::ioctl(
            kvm_fd,
            KVM_GET_SUPPORTED_CPUID as libc::c_ulong,
            buf.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_GET_SUPPORTED_CPUID".into(),
            errno: errno_after_ioctl(),
        });
    }

    // Read back the actual nent and entries
    // SAFETY: buf contains a valid kvm_cpuid2 structure returned by KVM
    unsafe {
        let hdr = buf.as_ptr() as *const KvmCpuid2Raw;
        let actual_nent = (*hdr).nent as usize;
        let mut entries = Vec::with_capacity(actual_nent);
        for i in 0..actual_nent {
            let offset = header_size + i * entry_size;
            // SAFETY: offset + entry_size <= total_size (KVM wrote at most DEFAULT_NENT entries)
            let entry_ptr = buf.as_ptr().add(offset) as *const KvmCpuidEntry2Raw;
            entries.push(ptr::read(entry_ptr));
        }
        Ok(entries)
    }
}

/// ─── x86_64 KVM MSR entry size ──────────────────────────────────
const KVM_MSR_ENTRY_SIZE: u32 = 16;

// ─── General-purpose registers ────────────────────────────────────

/// Get general-purpose registers via `KVM_GET_REGS`
pub fn get_regs(vcpu_fd: RawFd) -> Result<KvmRegsRaw> {
    let mut regs = KvmRegsRaw::default();
    // SAFETY: vcpu_fd is a valid VCPU fd. regs is a POD struct that the kernel
    // will fill with register values. The ioctl copies sizeof(KvmRegsRaw)=144
    // bytes from kernel to the struct.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_GET_REGS as libc::c_ulong,
            &mut regs as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_GET_REGS".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(regs)
}

/// Set general-purpose registers via `KVM_SET_REGS`
pub fn set_regs(vcpu_fd: RawFd, regs: &KvmRegsRaw) -> Result<()> {
    // SAFETY: vcpu_fd is a valid VCPU fd. regs is a POD struct with valid register
    // values for the guest. The kernel copies sizeof(KvmRegsRaw)=144 bytes
    // from the struct to the VCPU's register state.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_REGS as libc::c_ulong,
            regs as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_SET_REGS".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

// ─── Special registers (segments, CRx, EFER) ──────────────────────

/// Get special registers (segments, CRx, EFER, etc.) via `KVM_GET_SREGS`
pub fn get_sregs(vcpu_fd: RawFd) -> Result<KvmSregsRaw> {
    let mut sregs = KvmSregsRaw::default();
    // SAFETY: vcpu_fd is a valid VCPU fd. sregs is a POD struct that the kernel
    // will fill with segment/control register values. Size 312 bytes.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_GET_SREGS as libc::c_ulong,
            &mut sregs as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_GET_SREGS".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(sregs)
}

/// Set special registers via `KVM_SET_SREGS`
pub fn set_sregs(vcpu_fd: RawFd, sregs: &KvmSregsRaw) -> Result<()> {
    // SAFETY: vcpu_fd is a valid VCPU fd. sregs is a POD struct with valid
    // segment/control register values for the guest. Size 312 bytes.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_SREGS as libc::c_ulong,
            sregs as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_SET_SREGS".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

// ─── CPUID ─────────────────────────────────────────────────────────

/// Set CPUID for the VCPU via `KVM_SET_CPUID2`
///
/// Must be called before `KVM_RUN` and before `KVM_SET_SREGS` if the
/// CPUID affects the execution mode (e.g., long mode).
///
/// `entries` contains the CPUID leaves to set. At minimum, leaf
/// `0x80000001` with `EDX[29]=1` (LM bit) is needed for 64-bit long mode.
pub fn set_cpuid2(vcpu_fd: RawFd, entries: &[KvmCpuidEntry2Raw]) -> Result<()> {
    let header_size = std::mem::size_of::<KvmCpuid2Raw>();
    let entry_size = std::mem::size_of::<KvmCpuidEntry2Raw>();
    #[allow(clippy::manual_slice_size_calculation)] // explicit formula preferred for clarity
    let total_size = header_size + entries.len() * entry_size;

    // Allocate a buffer for the header + entries (zero-initialized for safe casting).
    let mut buf: Vec<u8> = vec![0u8; total_size];

    // Write header
    // SAFETY: buf.as_mut_ptr() is aligned and has room for KvmCpuid2Raw.
    unsafe {
        let header_ptr = buf.as_mut_ptr() as *mut KvmCpuid2Raw;
        ptr::write(header_ptr, KvmCpuid2Raw {
            nent: entries.len() as u32,
            padding: 0,
        });
    }

    // Write entries
    for (i, entry) in entries.iter().enumerate() {
        let offset = header_size + i * entry_size;
        // SAFETY: buf has total_size bytes, offset + entry_size <= total_size.
        // The pointer is properly aligned for KvmCpuidEntry2Raw.
        unsafe {
            let entry_ptr = buf.as_mut_ptr().add(offset) as *mut KvmCpuidEntry2Raw;
            ptr::write(entry_ptr, entry.clone());
        }
    }

    // SAFETY: vcpu_fd is a valid VCPU fd. buf contains a valid kvm_cpuid2
    // structure followed by nent entries.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_CPUID2 as libc::c_ulong,
            buf.as_ptr() as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_SET_CPUID2".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

// ─── MP state ─────────────────────────────────────────────────────

/// Get the VCPU's MP state via `KVM_GET_MP_STATE`
pub fn get_mp_state(vcpu_fd: RawFd) -> Result<MpState> {
    let mut raw: u32 = 0;
    // SAFETY: vcpu_fd is a valid VCPU fd. raw is a u32 that the kernel fills.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_GET_MP_STATE as libc::c_ulong,
            &mut raw as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_GET_MP_STATE".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(MpState::from_raw(raw))
}

/// Set the VCPU's MP state via `KVM_SET_MP_STATE`
pub fn set_mp_state(vcpu_fd: RawFd, state: MpState) -> Result<()> {
    let raw = state.to_raw();
    // SAFETY: vcpu_fd is a valid VCPU fd. raw is a u32 with valid MP state.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_MP_STATE as libc::c_ulong,
            &raw as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_SET_MP_STATE".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

// ─── XSAVE (FPU/SSE/AVX state) ────────────────────────────────────

/// Get the XSAVE area (FPU/SSE/AVX state) via `KVM_GET_XSAVE`
///
/// Returns a 4096-byte buffer containing the XSAVE data in x86 XSAVE format.
pub fn get_xsave(vcpu_fd: RawFd) -> Result<[u8; 4096]> {
    let mut xsave = [0u8; 4096];
    // SAFETY: vcpu_fd is a valid VCPU fd. xsave is a 4096-byte buffer that KVM fills.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_GET_XSAVE as libc::c_ulong,
            &mut xsave as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_GET_XSAVE".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(xsave)
}

/// Set the XSAVE area (FPU/SSE/AVX state) via `KVM_SET_XSAVE`
///
/// # Safety
/// `xsave` must contain valid x86 XSAVE data for the guest VCPU.
/// Typically obtained from a previous `get_xsave()` call.
pub unsafe fn set_xsave(vcpu_fd: RawFd, xsave: &[u8; 4096]) -> Result<()> {
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_XSAVE as libc::c_ulong,
            xsave.as_ptr() as *const libc::c_void,
        )
    };
    if ret < 0 {
        let errno = errno_after_ioctl();
        if errno == libc::EINVAL || errno == libc::ENXIO {
            // Some kernels/hypervisors don't support XSAVE restore
            return Ok(());
        }
        return Err(KvmError::Ioctl {
            context: "KVM_SET_XSAVE".into(),
            errno,
        });
    }
    Ok(())
}

// ─── XCR registers (XCR0, etc.) ───────────────────────────────────

/// Get the XCR registers (XCR0, etc.) via `KVM_GET_XCRS`
///
/// Returns a list of (xcr_number, value) pairs.
pub fn get_xcrs(vcpu_fd: RawFd) -> Result<Vec<(u32, u64)>> {
    // struct kvm_xcrs from kernel header:
    //   __u32 nr_xcrs;               // offset 0
    //   __u32 flags;                 // offset 4
    //   struct kvm_xcr xcrs[16];     // offset 8, each 16 bytes
    //   __u64 padding[16];           // offset 264
    // Total: 4 + 4 + 16*16 + 16*8 = 392 bytes
    // struct kvm_xcr: { __u32 xcr; __u32 reserved; __u64 value; } = 16 bytes
    let mut buf = [0u8; 392];
    // SAFETY: vcpu_fd is a valid VCPU fd. buf is properly sized for kvm_xcrs struct.
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_GET_XCRS as libc::c_ulong,
            &mut buf as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_GET_XCRS".into(),
            errno: errno_after_ioctl(),
        });
    }
    // Parse the result
    let nr_xcrs = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let mut result = Vec::with_capacity(nr_xcrs as usize);
    // Entries start at offset 8 (after nr_xcrs + flags), each 16 bytes
    for i in 0..nr_xcrs as usize {
        let off = 8 + i * 16;
        let xcr = u32::from_ne_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let value = u64::from_ne_bytes([
            buf[off+8], buf[off+9], buf[off+10], buf[off+11],
            buf[off+12], buf[off+13], buf[off+14], buf[off+15],
        ]);
        result.push((xcr, value));
    }
    Ok(result)
}

/// Set the XCR registers (XCR0, etc.) via `KVM_SET_XCRS`
///
/// # Safety
/// `xcrs` must contain valid (xcr_number, value) pairs for the guest VCPU.
/// Typically obtained from a previous `get_xcrs()` call.
pub unsafe fn set_xcrs(vcpu_fd: RawFd, xcrs: &[(u32, u64)]) -> Result<()> {
    if xcrs.is_empty() {
        return Ok(());
    }
    let nr = xcrs.len().min(16);
    // struct kvm_xcrs from kernel header:
    //   __u32 nr_xcrs;               // offset 0
    //   __u32 flags;                 // offset 4
    //   struct kvm_xcr xcrs[16];     // offset 8, each 16 bytes
    //   __u64 padding[16];           // offset 264
    // Total: 4 + 4 + 16*16 + 16*8 = 392 bytes
    let mut buf = [0u8; 392];
    // Write header
    buf[0..4].copy_from_slice(&(nr as u32).to_ne_bytes());
    // flags = 0 (already zero-initialized)
    // Write entries — entries start at offset 8 (after nr_xcrs + flags)
    for (i, &(xcr_val, xcr_data)) in xcrs.iter().enumerate().take(nr) {
        let off = 8 + i * 16;
        buf[off..off+4].copy_from_slice(&xcr_val.to_ne_bytes());
        // pad/reserved [off+4..off+8] = 0 (already zero-initialized)
        buf[off+8..off+16].copy_from_slice(&xcr_data.to_ne_bytes());
    }
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_XCRS as libc::c_ulong,
            &buf as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        let errno = errno_after_ioctl();
        if errno == libc::EINVAL || errno == libc::ENXIO {
            // Some kernels/hypervisors don't support XCRS restore
            tracing::warn!("KVM_SET_XCRS not supported (errno={}), XCRS NOT restored", errno);
            return Ok(());
        }
        return Err(KvmError::Ioctl {
            context: "KVM_SET_XCRS".into(),
            errno,
        });
    }
    Ok(())
}

// ─── MSRs (Model-Specific Registers) ──────────────────────────────

/// Save the MSRs critical for Linux x86_64 operation.
///
/// These include syscall entry MSRs (STAR, LSTAR, CSTAR, FMASK),
/// segment bases (GS_BASE, KERNEL_GS_BASE), SYSENTER registers,
/// TSC, PAT, and MISC_ENABLE.
///
/// # Safety
/// The VCPU must be valid. Returns as many MSRs as KVM supports.
pub unsafe fn save_critical_msrs(vcpu_fd: RawFd) -> Result<Vec<(u32, u64)>> {
    let entry_size = KVM_MSR_ENTRY_SIZE as usize;
    let buf_size = 8 + CRITICAL_MSRS.len() * entry_size;
    let mut buf: Vec<u8> = vec![0u8; buf_size];

    // SAFETY: buffer is properly sized for KVM API.
    unsafe {
        let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
        *nmsrs_ptr = CRITICAL_MSRS.len() as u32;

        for (i, &idx) in CRITICAL_MSRS.iter().enumerate() {
            let entry = buf.as_mut_ptr().add(8 + i * entry_size);
            *(entry as *mut u32) = idx;
        }
    }

    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_GET_MSRS as libc::c_ulong,
            buf.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret < 0 {
        let errno = errno_after_ioctl();
        if errno == libc::EINVAL || errno == libc::ENXIO {
            return Ok(Vec::new());
        }
        return Err(KvmError::Ioctl {
            context: "KVM_GET_MSRS".into(),
            errno,
        });
    }

    let n_read = ret as usize;
    let mut result = Vec::with_capacity(n_read);
    for i in 0..n_read {
        unsafe {
            let entry = buf.as_ptr().add(8 + i * entry_size);
            let idx = *(entry as *const u32);
            let data = *(entry.add(8) as *const u64);
            result.push((idx, data));
        }
    }
    Ok(result)
}

/// Restore MSRs on the VCPU.
///
/// Returns the number of MSRs successfully written.
///
/// # Safety
/// The VCPU must be valid. MSR values must be appropriate for the CPU.
pub unsafe fn restore_msrs(vcpu_fd: RawFd, msrs: &[(u32, u64)]) -> Result<u32> {
    if msrs.is_empty() {
        return Ok(0);
    }

    let entry_size = KVM_MSR_ENTRY_SIZE as usize;
    let buf_size = 8 + msrs.len() * entry_size;
    let mut buf: Vec<u8> = vec![0u8; buf_size];

    // SAFETY: buffer is properly sized for KVM API.
    unsafe {
        let nmsrs_ptr = buf.as_mut_ptr() as *mut u32;
        *nmsrs_ptr = msrs.len() as u32;

        for (i, &(idx, data)) in msrs.iter().enumerate() {
            let entry = buf.as_mut_ptr().add(8 + i * entry_size);
            *(entry as *mut u32) = idx;
            *(entry.add(8) as *mut u64) = data;
        }
    }

    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_SET_MSRS as libc::c_ulong,
            buf.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret < 0 {
        let errno = errno_after_ioctl();
        if errno == libc::EINVAL || errno == libc::ENXIO {
            return Ok(0);
        }
        return Err(KvmError::Ioctl {
            context: "KVM_SET_MSRS".into(),
            errno,
        });
    }
    Ok(ret as u32)
}

// ─── Interrupt injection ─────────────────────────────────────────

// ─── Fork helpers: CPUID filtering ─────────────────────────────────

/// Filter CPUID entries for fork — clear xstate_bv-related features.
///
/// Every feature that adds an `xstate_bv` bit must be cleared to prevent
/// `XRSTOR #GP` on fork: if the kernel saved fpstate during boot with these
/// bits set, and the fork removes them from XCR0/CPUID, XRSTOR faults.
///
/// Called once during `ForkEngine::new()` after the host CPUID is cached.
pub fn filter_cpuid_for_fork(entries: &mut [KvmCpuidEntry2Raw]) {
    for entry in entries.iter_mut() {
        if entry.function == 7 && entry.index == 0 {
            // xstate_bv bits to prevent: PKRU(bit8), CET_U(bit9), CET_S(bit10), LBR(bit11)
            entry.ecx &= !(1u32 << 4);   // PKU → xstate_bv bit 8
            entry.ecx &= !(1u32 << 5);   // WAITPKG (no xstate_bv, but kernel delay hangs)
            entry.ecx &= !(1u32 << 7);   // CET_U/user_shstk → xstate_bv bit 9
            entry.ecx &= !(1u32 << 11);  // CET_SS → xstate_bv bit 10 (IA32_XSS)
            entry.edx &= !(1u32 << 15);  // Arch LBR → xstate_bv bit 11 (IA32_XSS)
            entry.edx &= !(1u32 << 20);  // CET_IBT → same CET family
            break;
        }
    }
}

// ─── Fork helpers: XSAVE buffer construction ──────────────────────

/// Build a clean XSAVE buffer matching XCR0.
///
/// Constructs a 4096-byte XSAVE buffer with only x87|SSE|AVX bits set
/// in `xstate_bv` (matching `XCR0` bits 0|1|2 = 0x207). Uses non-compacted
/// format (`xcomp_bv = 0`), which is the standard XSAVE format.
///
/// # Background
///
/// We CANNOT skip XSAVE entirely because:
///   1. A fresh VCPU has KVM's default zero XSAVE state
///   2. The kernel's fpstate structures were saved in the snapshot with
///      specific `xstate_bv` bits matching the boot XCR0
///   3. When the kernel tries XRSTOR from a task's fpstate, the HW
///      validates the saved `xstate_bv` against the actual XSAVE buffer.
///      If the buffer is all zeros (default), XRSTOR #GP's.
///
/// We also CANNOT blindly restore the snapshot's XSAVE because the
/// host CPU may have `xstate_bv` bits (e.g., MPX, AVX-512) that exceed
/// XCR0. XRSTOR #GP's when `xstate_bv` has bits not enabled in XCR0.
///
/// Solution: construct a clean XSAVE buffer that matches XCR0:
///   `xstate_bv = 0x207` (x87 | SSE | AVX), all other bits zero.
/// The kernel will do lazy FPU init from this clean state.
///
/// Reference: Intel SDM Vol 1, Chapter 13 — XSAVE/XRSTOR state components.
pub fn build_clean_xsave(xcr0_value: u64) -> [u8; 4096] {
    let mut clean_xsave = [0u8; 4096];
    // Bytes 512-519: xstate_bv (little-endian). Set bits matching XCR0.
    // xstate_bv must be a subset of XCR0 to avoid #GP on XRSTOR.
    let xstate_bv = xcr0_value & 0x207; // mask to only x87|SSE|AVX
    clean_xsave[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
    // Bytes 520-527: xcomp_bv = 0 (non-compacted format, standard XSAVE)
    // XCOMP_BV bit 63 set = compacted format. We use standard format.
    clean_xsave
}

/// Inject a virtual interrupt into the VCPU via `KVM_INTERRUPT`.
///
/// Used to wake a VCPU from HLT state after forking from a post-boot
/// snapshot where the guest is idle.
///
/// `irq` is the interrupt vector (0-255). IRQ 0 = PIT timer interrupt.
///
/// # Errors
/// Returns `KvmError::Ioctl` if the ioctl fails.
pub fn inject_interrupt(vcpu_fd: RawFd, irq: u32) -> Result<()> {
    // struct kvm_interrupt { __u32 irq; };
    #[repr(C)]
    struct KvmInterrupt {
        irq: u32,
    }
    let interrupt_arg = KvmInterrupt { irq };
    // SAFETY: vcpu_fd is a valid VCPU fd. KvmInterrupt is a POD struct matching
    // the kernel's `struct kvm_interrupt` (just { __u32 irq; }).
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            KVM_INTERRUPT as libc::c_ulong,
            &interrupt_arg as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        let err = errno_after_ioctl();
        tracing::error!(
            "KVM_INTERRUPT(irq={}) failed: ret={}, errno={}, fd={}",
            irq, ret, err, vcpu_fd,
        );
        return Err(KvmError::Ioctl {
            context: format!("KVM_INTERRUPT(irq={})", irq),
            errno: err,
        });
    }
    Ok(())
}
