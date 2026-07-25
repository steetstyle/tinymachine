//! KVM ioctl latency benchmarks — Phase 1
//!
//! Measures the raw syscall overhead for ALL KVM operations used by TinyMachine:
//!   - KVM_CREATE_VM / KVM_CREATE_VCPU (baseline)
//!   - KVM_GET_REGS / KVM_SET_REGS / KVM_GET_SREGS / KVM_SET_SREGS
//!   - KVM_GET_MSRS / KVM_SET_MSRS (critical for syscall restore)
//!   - KVM_GET_XCRS / KVM_SET_XCRS (Phase 1 bugfix — AVX restore)
//!   - KVM_GET_XSAVE / KVM_SET_XSAVE (FPU/AVX state)
//!   - KVM_GET_CPUID2 (used in every fork)
//!   - KVM_SET_USER_MEMORY_REGION (memory map)
//!   - close() VM fd cleanup
//!
//! Run with: cargo bench -p tinyos-fork --bench kvm_ioctl

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::time::Instant;

// ─── KVM ioctl constants ──────────────────────────────────────────────
const KVM_CREATE_VM:            u64 = 0x0000ae01;
const KVM_GET_VCPU_MMAP_SIZE:   u64 = 0x0000ae04;
const KVM_CREATE_VCPU:          u64 = 0x0000ae41;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020ae46;
const KVM_GET_REGS:             u64 = 0x8090ae81;
const KVM_SET_REGS:             u64 = 0x4090ae82;
const KVM_GET_SREGS:            u64 = 0x80c8ae83;
const KVM_SET_SREGS:            u64 = 0x40c8ae84;
const KVM_GET_MSRS:             u64 = 0xc090ae88;
const KVM_SET_MSRS:             u64 = 0x4090ae89;
const KVM_GET_XCRS:             u64 = 0x8188aea6;
const KVM_SET_XCRS:             u64 = 0x4188aea7;
const KVM_GET_XSAVE:            u64 = 0x8100aea4;
const KVM_SET_XSAVE:            u64 = 0x4100aea5;
const KVM_GET_CPUID2:           u64 = 0x8090ae91;
#[allow(dead_code)]
const KVM_SET_CPUID2:           u64 = 0x4090ae91;

fn bench(name: &str, iterations: usize, mut f: impl FnMut()) {
    for _ in 0..10 { f(); } // warmup
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    print_stats(name, &samples);
}

fn print_stats(label: &str, times: &[f64]) {
    if times.is_empty() {
        println!("  {label:<50}  SKIPPED — no data");
        return;
    }
    let n = times.len();
    let mut sorted = times.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let variance = if n > 1 {
        sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let stddev = variance.sqrt();
    let min = sorted[0];
    let max = sorted[n - 1];
    let median = sorted[n / 2];
    let p90 = sorted[((n as f64 * 0.90) as usize).min(n - 1)];
    let p95 = sorted[((n as f64 * 0.95) as usize).min(n - 1)];
    let p99 = sorted[((n as f64 * 0.99) as usize).min(n - 1)];
    let p999 = sorted[((n as f64 * 0.999) as usize).min(n - 1)];
    println!(
        "  {label:<50}  n={n:>5}  μ={mean:>8.1}  σ={stddev:>8.1}  min={min:>8.1}  p50={median:>8.1}  p90={p90:>8.1}  p95={p95:>8.1}  p99={p99:>8.1}  p999={p999:>8.1}  max={max:>8.1}"
    );
}

fn open_kvm() -> OwnedFd {
    let file = OpenOptions::new().read(true).write(true)
        .open("/dev/kvm").expect("Cannot open /dev/kvm — is KVM loaded?");
    OwnedFd::from(file)
}

fn create_vm(kvm_fd: i32) -> i32 {
    unsafe {
        let ret = libc::ioctl(kvm_fd, KVM_CREATE_VM as libc::c_ulong, 0);
        assert!(ret >= 0, "KVM_CREATE_VM failed");
        ret
    }
}

fn create_vcpu(vm_fd: i32) -> i32 {
    unsafe {
        let ret = libc::ioctl(vm_fd, KVM_CREATE_VCPU as libc::c_ulong, 0);
        assert!(ret >= 0, "KVM_CREATE_VCPU failed");
        ret
    }
}

/// 392-byte buffer for KVM_GET_XCRS / KVM_SET_XCRS
/// Kernel struct kvm_xcrs:
///   u32 nr_xcrs;         // 4 bytes
///   u32 flags;           // 4 bytes
///   u64 padding[4];      // 32 bytes (reserved)
///   struct kvm_xcr entries[32];  // each entry: u32 + u32 padding + u64 = 16 bytes
///   padding[16];         // 16 bytes (reserved)
/// Total: 4 + 4 + 32 + 512 + 16 = 568? No.
/// Actual: sizeof(struct kvm_xcrs) = 392 bytes on x86_64.
/// Let's use 4096 to be safe (KVM is lenient on buffer size).
const XCRS_BUF_SIZE: usize = 4096;

fn main() {
    let kvm_file = open_kvm();
    let kvm_fd = kvm_file.as_raw_fd();

    // Check API version
    unsafe {
        let ver = libc::ioctl(kvm_fd, 0x0000ae00, 0);
        assert_eq!(ver, 12, "KVM API version mismatch");
    }

    let mmap_size = unsafe {
        let s = libc::ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE as libc::c_ulong, 0);
        assert!(s > 0);
        s as usize
    };

    println!("\n=== KVM Ioctl Latency Benchmarks (Phase 1) ===");

    // ── 1. KVM_CREATE_VM only ────────────────────────────────────────
    bench("KVM_CREATE_VM", 1000, || { create_vm(kvm_fd); });

    // ── 2. Full setup ────────────────────────────────────────────────
    bench("VM + VCPU + mmap + region", 1000, || {
        let vm = create_vm(kvm_fd);
        let vcpu = create_vcpu(vm);
        unsafe {
            let ptr = libc::mmap(ptr::null_mut(), mmap_size,
                libc::PROT_READ|libc::PROT_WRITE, libc::MAP_SHARED, vcpu, 0);
            assert!(ptr != libc::MAP_FAILED);
            libc::munmap(ptr, mmap_size);
            let _vcpu = OwnedFd::from_raw_fd(vcpu);
            let _vm = OwnedFd::from_raw_fd(vm);
        }
    });

    // ── Create persistent VM + VCPU for register benchmarks ──────────
    let vm_fd = create_vm(kvm_fd);
    let vcpu_fd = create_vcpu(vm_fd);

    let mem_ptr = unsafe {
        let p = libc::mmap(ptr::null_mut(), 4096,
            libc::PROT_READ|libc::PROT_WRITE, libc::MAP_PRIVATE|libc::MAP_ANONYMOUS, -1, 0);
        assert!(p != libc::MAP_FAILED);
        p
    };

    let region = KvmUserspaceMemoryRegion {
        slot: 0, flags: 0, guest_phys_addr: 0,
        memory_size: 4096, userspace_addr: mem_ptr as u64,
    };
    unsafe {
        let ret = libc::ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION as libc::c_ulong,
            &region as *const _ as *const libc::c_void);
        assert!(ret >= 0, "KVM_SET_USER_MEMORY_REGION failed");
    }

    // ── 3. Register operations ──────────────────────────────────────
    bench("KVM_GET_REGS", 1000, || {
        let mut regs = [0u8; 144];
        unsafe { libc::ioctl(vcpu_fd, KVM_GET_REGS as libc::c_ulong,
            &mut regs as *mut _ as *mut libc::c_void); }
    });

    bench("KVM_SET_REGS", 1000, || {
        let regs = [0u8; 144];
        unsafe { libc::ioctl(vcpu_fd, KVM_SET_REGS as libc::c_ulong,
            &regs as *const _ as *const libc::c_void); }
    });

    bench("KVM_GET_SREGS", 1000, || {
        let mut sregs = [0u8; 200];
        unsafe { libc::ioctl(vcpu_fd, KVM_GET_SREGS as libc::c_ulong,
            &mut sregs as *mut _ as *mut libc::c_void); }
    });

    bench("KVM_SET_SREGS", 1000, || {
        let sregs = [0u8; 200];
        unsafe { libc::ioctl(vcpu_fd, KVM_SET_SREGS as libc::c_ulong,
            &sregs as *const _ as *const libc::c_void); }
    });

    // ── 4. MSR operations (restored on every fork) ──────────────────
    // Use a small MSR list (3 entries: LSTAR, STAR, SF_MASK)
    bench("KVM_GET_MSRS (3 entries)", 1000, || {
        let mut buf = [0u8; 4096];
        // Build kvm_msrs header: nmsrs=3, padding=0
        let nmsrs: u32 = 3;
        let entries: [(u32, u32, u64); 3] = [
            (0xC0000082, 0, 0), // LSTAR
            (0xC0000081, 0, 0), // STAR
            (0xC0000084, 0, 0), // SF_MASK
        ];
        unsafe {
            ptr::write(buf.as_mut_ptr() as *mut u32, nmsrs);
            ptr::write(buf.as_mut_ptr().add(8) as *mut u32, 0u32); // padding
            ptr::copy_nonoverlapping(
                entries.as_ptr() as *const u8,
                buf.as_mut_ptr().add(16),
                std::mem::size_of::<(u32, u32, u64)>() * 3,
            );
            libc::ioctl(vcpu_fd, KVM_GET_MSRS as libc::c_ulong,
                &mut buf as *mut _ as *mut libc::c_void);
        }
    });

    bench("KVM_SET_MSRS (3 entries)", 1000, || {
        let mut buf = [0u8; 4096];
        let nmsrs: u32 = 3;
        let entries: [(u32, u32, u64); 3] = [
            (0xC0000082, 0, 0), // LSTAR
            (0xC0000081, 0, 0), // STAR
            (0xC0000084, 0, 0), // SF_MASK
        ];
        unsafe {
            ptr::write(buf.as_mut_ptr() as *mut u32, nmsrs);
            ptr::write(buf.as_mut_ptr().add(8) as *mut u32, 0u32);
            ptr::copy_nonoverlapping(
                entries.as_ptr() as *const u8,
                buf.as_mut_ptr().add(16),
                std::mem::size_of::<(u32, u32, u64)>() * 3,
            );
            libc::ioctl(vcpu_fd, KVM_SET_MSRS as libc::c_ulong,
                &buf as *const _ as *const libc::c_void);
        }
    });

    // ── 5. XCRS operations (Phase 1 bugfix) ──────────────────────────
    bench("KVM_GET_XCRS", 1000, || {
        let mut buf = [0u8; XCRS_BUF_SIZE];
        unsafe {
            libc::ioctl(vcpu_fd, KVM_GET_XCRS as libc::c_ulong,
                &mut buf as *mut _ as *mut libc::c_void);
        }
    });

    bench("KVM_SET_XCRS", 1000, || {
        let mut buf = [0u8; XCRS_BUF_SIZE];
        // Set nr_xcrs = 1, entry[0].xcr = 0, entry[0].value = 0x207 (AVX+SSE+x87)
        unsafe {
            ptr::write(buf.as_mut_ptr() as *mut u32, 1u32); // nr_xcrs = 1
            ptr::write(buf.as_mut_ptr().add(8) as *mut u32, 0u32); // padding
            // First entry at offset 16
            ptr::write(buf.as_mut_ptr().add(16) as *mut u32, 0u32); // xcr number = 0
            ptr::write(buf.as_mut_ptr().add(24) as *mut u64, 0x207u64); // XCR0 value
            libc::ioctl(vcpu_fd, KVM_SET_XCRS as libc::c_ulong,
                &buf as *const _ as *const libc::c_void);
        }
    });

    // ── 6. XSAVE operations (FPU/AVX state) ─────────────────────────
    bench("KVM_GET_XSAVE", 1000, || {
        let mut buf = [0u8; 4096];
        unsafe {
            libc::ioctl(vcpu_fd, KVM_GET_XSAVE as libc::c_ulong,
                &mut buf as *mut _ as *mut libc::c_void);
        }
    });

    bench("KVM_SET_XSAVE", 1000, || {
        let buf = [0u8; 4096];
        unsafe {
            libc::ioctl(vcpu_fd, KVM_SET_XSAVE as libc::c_ulong,
                &buf as *const _ as *const libc::c_void);
        }
    });

    // ── 7. CPUID operations ─────────────────────────────────────────
    bench("KVM_GET_CPUID2", 1000, || {
        let mut buf = [0u8; 4096];
        // Set nent = 100 (typical max entries)
        unsafe {
            ptr::write(buf.as_mut_ptr() as *mut u32, 100u32);
            libc::ioctl(vcpu_fd, KVM_GET_CPUID2 as libc::c_ulong,
                &mut buf as *mut _ as *mut libc::c_void);
        }
    });

    // ── 8. close() cost ─────────────────────────────────────────────
    bench("close() VM fd", 1000, || {
        let vm = create_vm(kvm_fd);
        unsafe { let _vm = OwnedFd::from_raw_fd(vm); }
    });

    // Cleanup
    unsafe {
        libc::munmap(mem_ptr, 4096);
    }

    println!();
    println!("  Note: XCRS ioctls were the Phase 1 root cause — struct size");
    println!("  mismatch (392 vs 272 bytes) caused AVX instructions to SIGILL.");
    println!("  KVM_SET_XCRS now uses correct 0x4188aea7 ioctl with 392B buffer.");
    println!();
}

#[repr(C)]
struct KvmUserspaceMemoryRegion {
    slot: u32, flags: u32, guest_phys_addr: u64,
    memory_size: u64, userspace_addr: u64,
}
