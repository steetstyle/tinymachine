//! x86_64 Architecture Paths and Constants — `ArchPaths` trait impl.
//!
//! Consolidates all x86_64-specific paths (QEMU binary, ld-linux, lib paths)
//! and constants (audit arch, timer) in one place. When adding aarch64,
//! create `arch/aarch64/paths.rs` with equivalent definitions.
//!
//! # Usage
//!
//! Use `crate::arch::paths::*` or `crate::arch::target::paths::*` to access
//! arch-specific constants. New code should prefer the `ArchPaths` trait so
//! that callers remain arch-independent.

/// x86_64 architecture name string
pub const ARCH_NAME: &str = "x86_64";

/// QEMU system binary name for this architecture.
/// NOTE: When porting to aarch64, this must become "qemu-system-aarch64".
pub const QEMU_BINARY: &str = "/usr/bin/qemu-system-x86_64";

/// Alternate QEMU binary search paths (checked after the default).
pub const QEMU_ALT_BINARIES: &[&str] = &[
    "/usr/local/bin/qemu-system-x86_64",
    "/usr/libexec/qemu-kvm",
];

/// QEMU package name for installation error messages.
pub const QEMU_PACKAGE_NAME: &str = "qemu-system-x86-64";

/// Dynamic linker path inside the guest initrd.
/// x86_64: `/lib64/ld-linux-x86-64.so.2`
/// aarch64: `/lib/ld-linux-aarch64.so.1`
pub const LD_LINUX_PATH: &str = "/lib64/ld-linux-x86-64.so.2";

/// Architecture-specific library path used in LD_LIBRARY_PATH and cpio builds.
/// x86_64: `/usr/lib/x86_64-linux-gnu`
/// aarch64: `/usr/lib/aarch64-linux-gnu`
pub const LIB_ARCH_PATH: &str = "/usr/lib/x86_64-linux-gnu";

/// Kernel boot architecture directory (used in /boot and config paths).
/// x86_64: `x86_64`; aarch64: `aarch64`
pub const KERNEL_ARCH_DIR: &str = "x86_64";

/// seccomp audit architecture value.
/// x86_64: 0xc000003e; aarch64: 0xc00000b7
pub const AUDIT_ARCH: u32 = 0xc000003e;

/// Busybox download URL for this architecture.
/// x86_64: `busybox-x86_64`; aarch64: `busybox-aarch64`
pub const BUSYBOX_ARCH: &str = "x86_64-linux-musl";

/// Kernel image name for this architecture.
/// x86_64: `vmlinux`; aarch64: `Image` (or `vmlinuz`)
pub const KERNEL_IMAGE_NAME: &str = "vmlinux";

/// Measure CPU ticks using rdtsc (x86_64).
/// On aarch64, this would use `cntvct_el0`.
#[inline(always)]
pub fn read_timer() -> u64 {
    // SAFETY: rdtsc is always safe on x86_64; it reads a HW counter
    // with no side effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Estimate TSC frequency from /proc/cpuinfo.
/// On aarch64, this would read `/sys/devices/system/cpu/cpu0/cpu_freq`.
pub fn tsc_khz() -> u64 {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
        s.lines().find_map(|line| {
            if line.starts_with("cpu MHz") {
                let mhz: f64 = line.split(':').nth(1)?.trim().parse().ok()?;
                Some((mhz * 1000.0) as u64)
            } else {
                None
            }
        })
    });
    cpuinfo.unwrap_or(2_200_000) // default: 2.2 GHz
}
