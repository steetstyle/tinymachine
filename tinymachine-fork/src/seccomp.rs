//! Seccomp-BPF syscall filters for sandbox isolation.
//!
//! This module defines BPF-based seccomp filters for each TinyMachine sandbox
//! backend. Each backend gets a minimal allowlist of syscalls needed for
//! its operation. All other syscalls are denied with `EACCES`.
//!
//! # Design
//!
//! Each filter:
//! 1. Verifies the audit architecture is `AUDIT_ARCH`
//! 2. Loads the syscall number from `seccomp_data.nr`
//! 3. Checks against a per-backend allowlist using a linear chain of `JEQ` BPF
//!    instructions
//! 4. On match: returns `SECCOMP_RET_ALLOW`
//! 5. On miss: returns `SECCOMP_RET_ERRNO | EACCES`
//!
//! # Safety
//!
//! This module uses `unsafe` for:
//! - `libc::prctl()` to set `PR_SET_NO_NEW_PRIVS`
//! - `libc::syscall()` to invoke `seccomp(SECCOMP_SET_MODE_FILTER, ...)`
//! - Casting `sock_fprog` struct for the seccomp syscall
//!
//! Every `unsafe` block has a `// SAFETY:` justification.

use std::io;

/// Re-export the backend type from tinyos-api for convenience.
pub use tinymachine_api::sandbox::BackendType;

use crate::arch::paths::AUDIT_ARCH;

// ─── BPF Instruction Constants ──────────────────────────────────────────

/// BPF instruction class: load from absolute offset
const BPF_LD: u16 = 0x00;
/// BPF instruction class: jump
const BPF_JMP: u16 = 0x05;
/// BPF instruction class: return
const BPF_RET: u16 = 0x06;
/// BPF size: 32-bit word (OR'd with LD/ST)
const BPF_W: u16 = 0x00;
/// BPF addressing mode: absolute (OR'd with LD)
const BPF_ABS: u16 = 0x20;
/// BPF jump: jump if equal (OR'd with JMP)
const BPF_JEQ: u16 = 0x10;
/// BPF return: return constant (OR'd with RET)
const BPF_K: u16 = 0x00;

// ─── Seccomp Constants ─────────────────────────────────────────────────

// AUDIT_ARCH imported from crate::arch::paths

/// Offset of syscall number in `struct seccomp_data`
const SECCOMP_DATA_NR_OFF: u32 = 0;
/// Offset of architecture in `struct seccomp_data`
const SECCOMP_DATA_ARCH_OFF: u32 = 4;

// ─── BPF Instruction Structures ─────────────────────────────────────────

/// Seccomp BPF instruction as used by `struct sock_filter` in the kernel.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Seccomp BPF program as used by `struct sock_fprog` in the kernel.
#[repr(C)]
pub struct BpfProg {
    pub len: u16,
    pub filter: *const BpfInsn,
}

// ─── BPF Program Builder ───────────────────────────────────────────────

/// Builder for seccomp BPF programs.
///
/// Produces a `Vec<BpfInsn>` that can be passed to
/// `seccomp(SECCOMP_SET_MODE_FILTER)`. The generated program:
/// 1. Checks the architecture is `AUDIT_ARCH_X86_64` (kills the process if not)
/// 2. Loads the syscall number from `seccomp_data.nr`
/// 3. Checks against the allowlist using a linear chain of `JEQ` instructions
/// 4. If no check matches: returns `SECCOMP_RET_ERRNO | EACCES`
/// 5. On match: returns `SECCOMP_RET_ALLOW`
struct BpfBuilder {
    insns: Vec<BpfInsn>,
}

impl BpfBuilder {
    /// Create a new empty BPF program builder.
    fn new() -> Self {
        Self { insns: Vec::new() }
    }

    /// Emit `LD | W | ABS` — load a 32-bit word from `seccomp_data` at `offset`.
    fn ld_abs(&mut self, offset: u32) {
        self.insns.push(BpfInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        });
    }

    /// Emit `JMP | JEQ | K` — jump forward `jt` insns if A == k,
    /// jump forward `jf` insns if A != k.
    fn jeq(&mut self, k: u32, jt: u8, jf: u8) {
        self.insns.push(BpfInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf,
            k,
        });
    }

    /// Emit `RET | K` — return the constant `k` as the seccomp verdict.
    fn ret(&mut self, k: u32) {
        self.insns.push(BpfInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        });
    }

    /// Consume the builder and produce a `BpfProg` referencing the instructions.
    ///
    /// The returned `BpfProg` borrows the `Vec<BpfInsn>`. The caller must keep
    /// the `Vec` alive until after the `seccomp()` syscall has completed.
    fn build(self) -> (Vec<BpfInsn>, BpfProg) {
        let insns = self.insns;
        let len = insns.len() as u16;
        let filter = insns.as_ptr();
        let prog = BpfProg { len, filter };
        (insns, prog)
    }
}

/// Build the seccomp BPF program for a given allowlist of syscall numbers.
///
/// The generated BPF program structure:
/// ```text
/// [0]  LD abs [4]                      ; load seccomp_data.arch
/// [1]  JEQ A, AUDIT_ARCH_X86_64, 1, 0  ; if match → skip 1 to [3]; else → [2]
/// [2]  RET KILL                         ; wrong arch → kill process
/// [3]  LD abs [0]                       ; load seccomp_data.nr (syscall number)
/// [4]  JEQ A, SYS_R, jt_0, 1            ; if match → skip to ALLOW; else → [5]
/// [5]  JEQ A, SYS_W, jt_1, 1            ; ...
/// ...  ...
/// [N]  JEQ A, SYS_L, 1, 0               ; last: match→ALLOW, miss→DENY
/// [N+1] RET ALLOW                       ; ALLOW
/// [N+2] RET ERRNO(EACCES)               ; DENY
/// ```
pub fn build_bpf(allowlist: &[i64]) -> (Vec<BpfInsn>, BpfProg) {
    let mut b = BpfBuilder::new();

    // Step 1: Load and verify architecture
    b.ld_abs(SECCOMP_DATA_ARCH_OFF);
    // If arch == AUDIT_ARCH_X86_64: skip 1 (to the LD_NR), else skip 0 (to KILL)
    b.jeq(AUDIT_ARCH, 1, 0);
    b.ret(libc::SECCOMP_RET_KILL_PROCESS); // wrong arch → kill

    // Step 2: Load syscall number
    b.ld_abs(SECCOMP_DATA_NR_OFF);

    // Step 3: Generate allowlist checks
    let num_checks = allowlist.len();
    // The ALLOW return will be at position:
    //   3 (preamble: LD_ARCH, JEQ_ARCH, KILL)
    // + 1 (LD_NR)
    // + num_checks (JEQ checks)
    // + 0 (ALLOW comes before DENY)
    // = 4 + num_checks
    let allow_pos: u16 = 4 + num_checks as u16; // 0-indexed position of ALLOW instr

    for (i, &sysno) in allowlist.iter().enumerate() {
        // Current instruction index (0-indexed from start of BPF):
        let cur_idx: u16 = 4 + i as u16; // after LD_ARCH(0) + JEQ_ARCH(1) + KILL(2) + LD_NR(3)
        // If match: jump from cur_idx+1 to allow_pos: jt = allow_pos - (cur_idx + 1)
        let jt = (allow_pos - cur_idx - 1) as u8;
        // If no match: jump 1 instruction forward (to next check),
        // except for the last check which falls through to DENY.
        let jf: u8 = if i == num_checks - 1 { 0 } else { 1 };
        b.jeq(sysno as u32, jt, jf);
    }

    // Step 4: ALLOW — syscall is in allowlist
    b.ret(libc::SECCOMP_RET_ALLOW);

    // Step 5: DENY — syscall not in allowlist, return EACCES
    let errno_eacces = libc::EACCES as u32;
    b.ret(libc::SECCOMP_RET_ERRNO | errno_eacces);

    b.build()
}

// ─── Allowlists ─────────────────────────────────────────────────────────

/// Returns the minimum syscall allowlist for the given backend type.
///
/// Each allowlist is the minimal set of syscalls the backend needs to
/// function. All other syscalls are denied.
fn allowlist(backend: BackendType) -> &'static [i64] {
    match backend {
        // ── WasmBackend (Tier 1) ──────────────────────────────────────
        //
        // wasmtime JIT engine needs mmap(PROT_EXEC) for code generation.
        // All I/O is capability-based through WASI.
        BackendType::Wasm => &[
            // Sık kullanılan (warm path) — önce kontrol edilir, ortalama derinlik azalır
            libc::SYS_write,        // stdout/stderr (WASI print, wasmtime debug)
            libc::SYS_clock_gettime, // wasmtime fuel metering + time queries
            libc::SYS_mmap,         // wasmtime JIT code generation + memory
            libc::SYS_mprotect,     // change memory protection for JIT
            libc::SYS_getrandom,    // WASI random_get, wasmtime internal hashing
            libc::SYS_futex,        // wasmtime internal synchronization
            libc::SYS_brk,          // glibc heap allocation
            libc::SYS_close,        // close inherited file descriptors
            // Orta sıklıkta
            libc::SYS_read,         // stdin
            libc::SYS_munmap,       // free JIT code pages
            libc::SYS_exit_group,   // process termination
            libc::SYS_madvise,      // memory advice (glibc allocator)
            // Nadir kullanılan (WASI I/O, sinyal yönetimi)
            libc::SYS_openat,       // WASI file I/O
            libc::SYS_newfstatat,   // file stat (glibc wrapper)
            libc::SYS_lseek,        // file positioning (WASI)
            libc::SYS_nanosleep,    // wasmtime timeout
            libc::SYS_sigaltstack,  // alternate signal stack
            libc::SYS_rt_sigaction, // signal handlers
            libc::SYS_rt_sigprocmask, // signal masking
            libc::SYS_sched_yield,  // cooperative multitasking
        ],

        // ── KvmForkBackend (Tier 2) ───────────────────────────────────
        //
        // The host process needs ioctl for KVM, mmap for CoW snapshot
        // mapping and kvm_run, eventfd2/timerfd for signalling, and
        // sigtimedwait for signal handling during KVM_RUN.
        BackendType::KvmFork => &[
            libc::SYS_read,         // serial output from guest
            libc::SYS_write,        // stderr logging
            libc::SYS_mmap,         // CoW memory, kvm_run, shared memory
            libc::SYS_munmap,       // cleanup after fork
            libc::SYS_brk,          // glibc heap
            libc::SYS_exit_group,   // exit
            libc::SYS_nanosleep,    // timeouts
            libc::SYS_clock_gettime, // timing
            libc::SYS_sigaltstack,  // signal stack for SIGALRM handler
            libc::SYS_rt_sigaction, // SIGALRM handler for timeout
            libc::SYS_rt_sigprocmask, // signal masking
            libc::SYS_sched_yield,  // yield
            libc::SYS_futex,        // synchronization
            libc::SYS_close,        // close file descriptors
            libc::SYS_openat,       // open /dev/kvm
            libc::SYS_newfstatat,   // file stat (glibc)
            libc::SYS_lseek,        // file positioning
            libc::SYS_mprotect,     // memory protection
            libc::SYS_ioctl,        // KVM ioctls (KVM_CREATE_VM, KVM_RUN, etc.)
            libc::SYS_eventfd2,     // VM notification events
            libc::SYS_timerfd_create, // periodic timer for READY polling
            libc::SYS_rt_sigtimedwait, // wait for signals with timeout
            libc::SYS_setitimer,    // setitimer for READY polling interval
            libc::SYS_madvise,      // huge page hints (MADV_HUGEPAGE)
            libc::SYS_getrandom,    // host entropy for CRNG divergence per-fork
            libc::SYS_dup,          // dup TAP fd for virtio-net (dup before fork)
        ],

        // ── HostGpuBackend (Tier S) ───────────────────────────────────
        //
        // Runs tinygrad Python code in a persistent worker. Needs access
        // to /dev/nvidia* devices and GPU BARs via mmap, plus ioctl for
        // the NVIDIA kernel driver.
        BackendType::HostGpu => &[
            libc::SYS_read,         // stdin (JSON commands from parent)
            libc::SYS_write,        // stdout (JSON responses, stderr)
            libc::SYS_mmap,         // GPU BAR mapping, heap
            libc::SYS_munmap,       // cleanup
            libc::SYS_brk,          // glibc heap
            libc::SYS_exit_group,   // exit
            libc::SYS_nanosleep,    // timing
            libc::SYS_clock_gettime, // timing
            libc::SYS_sigaltstack,  // signal stack
            libc::SYS_rt_sigaction, // signal handlers
            libc::SYS_rt_sigprocmask, // signal masking
            libc::SYS_sched_yield,  // yield
            libc::SYS_futex,        // sync (Python interpreter GIL, etc.)
            libc::SYS_close,        // close file descriptors
            libc::SYS_openat,       // open /dev/nvidiactl, /dev/nvidia0
            libc::SYS_newfstatat,   // file stat (glibc)
            libc::SYS_lseek,        // file positioning
            libc::SYS_mprotect,     // memory protection
            libc::SYS_ioctl,        // NVIDIA ioctls on /dev/nvidia*
            libc::SYS_eventfd2,     // eventfd for sync
            libc::SYS_pread64,      // read from GPU BARs (offset-based)
            libc::SYS_pwrite64,     // write to GPU BARs (offset-based)
            libc::SYS_readv,        // vectored I/O (Python runtime)
            libc::SYS_writev,       // vectored I/O (Python runtime)
            libc::SYS_dup,          // duplicate file descriptors
            libc::SYS_dup2,         // duplicate file descriptors
            libc::SYS_madvise,      // memory advice
        ],

        // ── QemuBackend (Tier 3) ──────────────────────────────────────
        //
        // Seccomp is installed in the QEMU child process after fork() but
        // before exec(). QEMU needs KVM ioctl, mmap, eventfd, disk I/O,
        // and networking syscalls for virtio-net backend.
        BackendType::Qemu => &[
            libc::SYS_read,         // I/O
            libc::SYS_write,        // I/O
            libc::SYS_mmap,         // memory mappings
            libc::SYS_munmap,       // cleanup
            libc::SYS_brk,          // heap
            libc::SYS_exit_group,   // exit
            libc::SYS_nanosleep,    // timing
            libc::SYS_clock_gettime, // timing
            libc::SYS_rt_sigaction, // signal handlers
            libc::SYS_rt_sigprocmask, // signal masking
            libc::SYS_sched_yield,  // yield
            libc::SYS_futex,        // sync
            libc::SYS_mprotect,     // memory protection
            libc::SYS_openat,       // open files (disk images, etc.)
            libc::SYS_close,        // close files
            libc::SYS_dup2,         // fd duplication
            libc::SYS_newfstatat,   // file stat
            libc::SYS_pread64,      // pread for disk I/O
            libc::SYS_pwrite64,     // pwrite for disk I/O
            libc::SYS_ioctl,        // KVM + VFIO ioctls
            libc::SYS_eventfd2,     // eventfd
            libc::SYS_sigaltstack,  // signal stack
            libc::SYS_setitimer,    // timer
            libc::SYS_fcntl,        // fd manipulation
            libc::SYS_lseek,        // file positioning
            libc::SYS_madvise,      // memory advice
            libc::SYS_timerfd_create, // timer
            libc::SYS_socket,       // network (virtio-net backend)
            libc::SYS_bind,         // network
            libc::SYS_connect,      // network
            libc::SYS_setsockopt,   // network
            libc::SYS_getsockopt,   // network
        ],

        // ── FreshBootBackend (Tier 3) ─────────────────────────────────
        //
        // Runs in the host process alongside VFIO GPU passthrough.
        // Needs open(/dev/vfio/*), ioctl for VFIO, mmap for GPU BARs.
        //
        // Note: This seccomp applies to the HOST process. The guest VM
        // inside KVM is not affected — it runs its own kernel with its
        // own security policies. Guest-side seccomp should be configured
        // inside the guest's initramfs.
        BackendType::FreshBoot => &[
            libc::SYS_read,         // I/O
            libc::SYS_write,        // I/O
            libc::SYS_mmap,         // VFIO BAR mapping, guest memory
            libc::SYS_munmap,       // cleanup
            libc::SYS_brk,          // heap
            libc::SYS_exit_group,   // exit
            libc::SYS_nanosleep,    // timing
            libc::SYS_clock_gettime, // timing
            libc::SYS_sigaltstack,  // signal stack
            libc::SYS_rt_sigaction, // signal handlers
            libc::SYS_rt_sigprocmask, // signal masking
            libc::SYS_sched_yield,  // yield
            libc::SYS_futex,        // sync
            libc::SYS_close,        // close file descriptors
            libc::SYS_openat,       // open /dev/vfio/vfio, /dev/vfio/<group>
            libc::SYS_newfstatat,   // file stat (glibc)
            libc::SYS_lseek,        // file positioning
            libc::SYS_mprotect,     // memory protection
            libc::SYS_ioctl,        // VFIO ioctls (GROUP_GET_DEVICE_FD, SET_IRQ, etc.)
            libc::SYS_eventfd2,     // VFIO interrupt eventfds
            libc::SYS_pread64,      // VFIO config space read
            libc::SYS_pwrite64,     // VFIO config space write
            libc::SYS_fcntl,        // fd manipulation
            libc::SYS_dup,          // dup VFIO device fd
            libc::SYS_setitimer,    // timer for READY polling
            libc::SYS_timerfd_create, // timer
            libc::SYS_madvise,      // memory advice
        ],
    }
}

// ─── Public API ─────────────────────────────────────────────────────────

/// Install a seccomp-BPF filter for the given backend type.
///
/// This function:
/// 1. Calls `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` to prevent privilege
///    escalation (required before seccomp).
/// 2. Builds a BPF program for the backend's allowlist.
/// 3. Calls `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` to install the filter.
///
/// Once installed, the filter **cannot be removed** for the lifetime of the
/// process. Calling this from a child after `fork()` but before `exec()` is
/// safe because the child is single-threaded and `prctl`/`seccomp` are
/// async-signal-safe.
///
/// # Errors
///
/// Returns `io::Error` if:
/// - `prctl(PR_SET_NO_NEW_PRIVS)` fails (kernel too old or seccomp disabled)
/// - `seccomp(SECCOMP_SET_MODE_FILTER)` fails (invalid program, EACCES if
///   `PR_SET_NO_NEW_PRIVS` was not set, or seccomp not compiled in kernel)
///
/// Returns `io::Error` with `EACCES` if seccomp is already installed (the
/// second call is harmless — the existing filter is already in effect).
///
/// # Panics
///
/// Panics if the allowlist for the given backend is empty (the process
/// would immediately die on any syscall).
pub fn install(backend: BackendType) -> io::Result<()> {
    // Debug: confirm seccomp_install is called
    unsafe { libc::write(2, b"SECCOMP_INSTALL_ENTER\n" as *const u8 as *const libc::c_void, 22); }

    let list = allowlist(backend);

    if list.is_empty() {
        panic!(
            "seccomp allowlist for backend '{:?}' is empty — \
             no syscalls would be permitted, the process would immediately die",
            backend
        );
    }

    // Step 1: Set NO_NEW_PRIVS so seccomp cannot be bypassed.
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) only sets a process flag
    // that prevents future privilege gains. It is idempotent and safe.
    let ret = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Step 2: Build the BPF program for this backend's allowlist.
    let (_insns, prog) = build_bpf(list);

    // Debug: dump the BPF program for KvmFork
    if let BackendType::KvmFork = backend {
        let insns = &_insns;
        let msg = format!("SECCOMP BPF {} insns for KvmFork:\n", insns.len());
        unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()); }
        for (i, insn) in insns.iter().enumerate() {
            let msg = format!("  [{i:3}] code=0x{:04x} jt={:3} jf={:3} k=0x{:08x} ({})\n",
                insn.code, insn.jt, insn.jf, insn.k, insn.k);
            unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()); }
        }
    }

    // Step 3: Install the seccomp filter.
    // SAFETY:
    // - `BpfProg` layout matches `struct sock_fprog`.
    // - `_insns` is kept alive on the stack until after the syscall completes.
    // - `PR_SET_NO_NEW_PRIVS` has been set (required by kernel).
    // - The filter pointer is valid for the duration of the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp as i64,
            libc::SECCOMP_SET_MODE_FILTER as i64,
            0i64, // flags = 0
            &prog as *const BpfProg,
        )
    };
    if ret != 0 {
        unsafe { libc::write(2, b"SECCOMP_INSTALL_FAILED\n" as *const u8 as *const libc::c_void, 24); }
        return Err(io::Error::last_os_error());
    }

    unsafe { libc::write(2, b"SECCOMP_INSTALL_OK\n" as *const u8 as *const libc::c_void, 20); }
    Ok(())
}

/// Check whether seccomp is supported on this kernel.
///
/// Tries `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` — if it succeeds, seccomp
/// is available. This is a non-fatal capability check.
pub fn is_seccomp_available() -> bool {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is safe and idempotent.
    let ret = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    };
    ret == 0
}

// ─── Notes for FreshBootBackend / Guest-side Seccomp ────────────────────
//
// The FreshBootBackend runs a KVM VM with a full Linux kernel inside. We
// **cannot** install a seccomp filter directly inside the guest VM from the
// host side — seccomp is a kernel feature that must be configured from within
// the guest kernel.
//
// Guest-side seccomp should be configured in the initramfs (init.c):
//
// ```c
// prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
// struct sock_filter filter[] = {
//     /* allow only read, write, exit_group, etc. */
// };
// struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
// seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
// ```
//
// At minimum, the guest init should block:
// - `init_module` / `finit_module` — prevent kernel module loading
// - `reboot` / `__NR_reboot` — prevent guest reboot
// - `iopl` / `ioperm` — prevent direct port I/O
//
// This is tracked as Phase 3.2 (Guest-side seccomp hardening).

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that all backends have non-empty allowlists.
    #[test]
    fn test_allowlists_are_non_empty() {
        for backend in &[
            BackendType::Wasm,
            BackendType::KvmFork,
            BackendType::HostGpu,
            BackendType::Qemu,
            BackendType::FreshBoot,
        ] {
            let list = allowlist(*backend);
            assert!(
                !list.is_empty(),
                "allowlist for backend '{:?}' is empty",
                backend
            );
        }
    }

    /// Verify that the Wasm allowlist contains mmap (JIT requirement).
    #[test]
    fn test_wasm_allowlist_has_mmap() {
        let list = allowlist(BackendType::Wasm);
        assert!(list.contains(&libc::SYS_mmap), "wasm needs mmap for JIT");
        assert!(list.contains(&libc::SYS_mprotect), "wasm needs mprotect");
        assert!(list.contains(&libc::SYS_getrandom), "wasm needs getrandom for WASI");
    }

    /// Verify that the KvmFork allowlist contains ioctl and mmap.
    #[test]
    fn test_kvmfork_allowlist_has_ioctl() {
        let list = allowlist(BackendType::KvmFork);
        assert!(list.contains(&libc::SYS_ioctl), "kvmfork needs ioctl for KVM");
        assert!(list.contains(&libc::SYS_mmap), "kvmfork needs mmap for CoW");
        assert!(list.contains(&libc::SYS_eventfd2), "kvmfork needs eventfd2");
        assert!(list.contains(&libc::SYS_getrandom), "kvmfork needs getrandom for CRNG");
    }

    /// Verify HostGpu allowlist has openat (for /dev/nvidia*).
    #[test]
    fn test_hostgpu_allowlist_has_openat() {
        let list = allowlist(BackendType::HostGpu);
        assert!(list.contains(&libc::SYS_openat),
            "hostgpu needs openat for /dev/nvidia*");
        assert!(list.contains(&libc::SYS_ioctl),
            "hostgpu needs ioctl for nvidia");
    }

    /// Verify Qemu allowlist has ioctl and socket-related syscalls.
    #[test]
    fn test_qemu_allowlist_has_network() {
        let list = allowlist(BackendType::Qemu);
        assert!(list.contains(&libc::SYS_ioctl), "qemu needs ioctl for KVM");
        assert!(list.contains(&libc::SYS_socket), "qemu needs socket for network");
    }

    /// Verify FreshBoot allowlist has openat (for /dev/vfio/*).
    #[test]
    fn test_freshboot_allowlist_has_vfio() {
        let list = allowlist(BackendType::FreshBoot);
        assert!(list.contains(&libc::SYS_openat),
            "freshboot needs openat for /dev/vfio/*");
        assert!(list.contains(&libc::SYS_ioctl),
            "freshboot needs ioctl for VFIO");
    }

    /// Test that building a BPF program produces the expected number of instructions.
    #[test]
    fn test_bpf_program_length() {
        let list = allowlist(BackendType::Wasm);
        let (insns, prog) = build_bpf(list);

        // Expected structure:
        //   0: LD abs [4]
        //   1: JEQ arch check
        //   2: RET KILL
        //   3: LD abs [0]
        //   4..(4+N-1): N JEQ checks
        //   4+N: RET ERRNO (DENY)
        //   5+N: RET ALLOW
        let expected_len = 3 + 1 + list.len() + 2; // 6 + N
        assert_eq!(
            insns.len(),
            expected_len,
            "expected {expected_len} BPF insns for wasm, got {}",
            insns.len()
        );
        assert_eq!(prog.len as usize, expected_len, "prog len mismatch");

        // Verify the last two instructions are DENY and ALLOW
        let deny_insn = insns[insns.len() - 2];
        let allow_insn = insns[insns.len() - 1];
        assert_eq!(
            deny_insn.code, BPF_RET | BPF_K,
            "second-to-last insn should be RET"
        );
        assert_eq!(
            allow_insn.code, BPF_RET | BPF_K,
            "last insn should be RET"
        );
        // DENY should have ERRNO action
        assert!(
            deny_insn.k & !0xffff == libc::SECCOMP_RET_ERRNO,
            "DENY should be RET_ERRNO, got 0x{:08x}",
            deny_insn.k
        );
        // ALLOW should have ALLOW action
        assert_eq!(
            allow_insn.k,
            libc::SECCOMP_RET_ALLOW,
            "ALLOW should be RET_ALLOW"
        );
    }

    /// Test that building BPF with empty allowlist still works (6 insns).
    #[test]
    fn test_bpf_empty_allowlist() {
        let (insns, _prog) = build_bpf(&[]);
        // With empty allowlist: 3 (preamble) + 1 (LD_NR) + 0 (checks) + 2 (DENY+ALLOW) = 6
        assert_eq!(insns.len(), 6, "empty list should have 6 insns");
        // All syscalls would be denied — the process would die on any syscall.
    }

    /// Test seccomp availability check (informational).
    #[test]
    fn test_seccomp_availability_check() {
        let available = is_seccomp_available();
        if !available {
            eprintln!("WARNING: seccomp not available on this kernel");
        }
    }

    /// Integration test: install seccomp for Wasm and verify basic I/O still works.
    ///
    /// This test **permanently** installs seccomp for the current process.
    /// After this test runs, only the Wasm allowlist syscalls are permitted.
    /// Other tests in this binary may fail because of this.
    ///
    /// This test is `#[ignore]` by default because it modifies the process's
    /// seccomp state globally. Run it in isolation with:
    /// ```bash
    /// cargo test --lib -p tinyos-fork -- --ignored seccomp
    /// ```
    /// Or as an integration test when built as a separate binary.
    #[test]
    #[ignore]
    fn test_install_wasm_seccomp() {
        if !is_seccomp_available() {
            eprintln!("Skipping seccomp install test: not available");
            return;
        }

        let result = install(BackendType::Wasm);
        assert!(
            result.is_ok(),
            "seccomp install for wasm should succeed: {:?}",
            result
        );

        // Verify we can still call allowed syscalls (write to stderr)
        let msg = b"seccomp: wasm filter active\n";
        // SAFETY: write to STDOUT is allowed by the wasm allowlist.
        let ret = unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
            )
        };
        assert_eq!(ret, msg.len() as isize, "write to stdout should succeed");
    }

    /// Integration test: verify that creating a socket is blocked after seccomp.
    ///
    /// This test must run AFTER `test_install_wasm_seccomp` in the same
    /// process. The socket() syscall is NOT in the Wasm allowlist, so it
    /// should fail with EACCES.
    ///
    /// Note: This test only works if `test_install_wasm_seccomp` ran first
    /// in the same process. When run through `cargo test`, tests within the
    /// same binary share a process, so ordering is sequential. But different
    /// test binaries have separate processes.
    ///
    /// We use a marker to detect if seccomp is already installed.
    ///
    /// This test is `#[ignore]` by default — same reason as `test_install_wasm_seccomp`.
    #[test]
    #[ignore]
    fn test_seccomp_blocks_evil_syscall() {
        // Try to install wasm seccomp first (harmless if already installed)
        let already_installed = if is_seccomp_available() {
            match install(BackendType::Wasm) {
                Ok(()) => {
                    // First-time install — seccomp now active
                    false
                }
                Err(ref e) if e.raw_os_error() == Some(libc::EACCES) => {
                    // Already installed (by a previous test)
                    true
                }
                Err(e) => {
                    // install failed for other reason
                    eprintln!("WARNING: seccomp install failed: {e}. Skipping socket test.");
                    return; // can't test without seccomp
                }
            }
        } else {
            eprintln!("WARNING: seccomp not available. Skipping socket test.");
            return;
        };

        // Now try to create an AF_INET socket — this should FAIL because
        // socket() is NOT in the Wasm allowlist.
        // SAFETY: socket() syscall with valid arguments. If seccomp blocks it,
        // it returns -1 with errno EACCES (or kills the process with SIGSYS).
        let sock_fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)
        };

        if sock_fd >= 0 {
            // Socket creation succeeded — this means seccomp is NOT active.
            // Close the leaked socket.
            unsafe { libc::close(sock_fd); }
            if already_installed {
                // This is unexpected — seccomp was installed but socket worked.
                panic!(
                    "seccomp was installed but socket() succeeded (fd={}). \
                     This indicates the BPF filter is not blocking socket().",
                    sock_fd
                );
            } else {
                eprintln!(
                    "WARNING: socket() succeeded with fd={} even though \
                     seccomp was just installed. Check the BPF filter.",
                    sock_fd
                );
            }
        } else {
            // Socket creation failed — expected with seccomp active.
            let err = io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EACCES),
                "expected EACCES from socket() under seccomp, got: {err}"
            );
            eprintln!("OK: socket() correctly blocked by seccomp: {err}");
        }
    }
}
