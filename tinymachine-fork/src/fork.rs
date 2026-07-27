//! CoW Fork Engine — the heart of TinyMachine sandbox creation
//!
//! Combines KVM lifecycle, snapshot loading, and CoW memory mapping
//! to achieve <0.5ms fork latency.
//!
//! # CoW Design
//! 1. Parent VM boots once, snapshot is taken
//! 2. Each fork: `mmap(MAP_PRIVATE)` the snapshot memory → kernel CoW
//! 3. KVM_CREATE_VM + KVM_SET_USER_MEMORY_REGION with CoW'd memory
//! 4. KVM_CREATE_VCPU + restore CPU state
//! 5. KVM_RUN → code executes in a fresh sandbox

use std::cell::RefCell;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use tracing::{info, trace};

use crate::arch::*;
use crate::arch::port::Uart16550;
use crate::kvm::{self, Kvm, Vm, Vcpu, KvmCpuidEntry2Raw};
use crate::net::virtio_net_pci::VirtioNetPci;
use crate::shared_mem::SharedMemoryRegion;
use crate::snapshot::Snapshot;
use crate::serial::SerialPort;
use crate::seccomp::{install as seccomp_install, BackendType as SeccompBackend};

/// Set to true when a signal interrupts KVM_RUN so we can log progress
static SIGNAL_INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Signal handler for SIGUSR1 — marks the atomic flag to trigger progress logging.
/// SAFETY: AtomicBool is signal-safe per POSIX signal safety requirements.
extern "C" fn sigusr1_handler(_signo: libc::c_int) {
    SIGNAL_INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Errors from fork operations
#[derive(Error, Debug)]
pub enum ForkError {
    #[error("KVM error: {0}")]
    Kvm(#[from] kvm::KvmError),
    #[error("Snapshot error: {0}")]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    #[error("Serial error: {0}")]
    Serial(#[from] crate::serial::SerialError),
    #[error("Fork limit reached: max {max} forks")]
    ForkLimit { max: usize },
    #[error("Guest execution error: exit reason {reason:?}")]
    GuestExit { reason: u32 },
    #[error("Shared memory error: {0}")]
    SharedMem(String),
}

impl From<crate::shared_mem::SharedMemError> for ForkError {
    fn from(e: crate::shared_mem::SharedMemError) -> Self {
        ForkError::SharedMem(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ForkError>;

// ─── Scope guard for mmap'd memory ──────────────────────────────────
// Ensures mapped memory is freed when `fork()` encounters an error
// before constructing the final `ForkedVm`.
struct MmapGuard {
    ptr: *mut u8,
    size: usize,
    armed: bool,
}

impl MmapGuard {
    fn new(ptr: *mut u8, size: usize) -> Self {
        Self { ptr, size, armed: true }
    }

    /// Disarm the guard — the caller takes ownership of the mmap.
    fn disarm(mut self) -> (*mut u8, usize) {
        self.armed = false;
        (self.ptr, self.size)
    }
}

impl Drop for MmapGuard {
    fn drop(&mut self) {
        if self.armed && !self.ptr.is_null() {
            // SAFETY: ptr was obtained from a previous successful mmap of size bytes.
            // munmap is safe to call here because:
            // 1. We only unmap if we still own the mapping (armed == true).
            // 2. ptr.is_null() check prevents munmap of null.
            // 3. Linux guarantees munmap succeeds for valid mappings.
            // Log munmap failures — silent leaks indicate double-free or corruption.
            let ret = unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size as libc::size_t)
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!(
                    "MmapGuard::drop: munmap({:p}, {}) failed: {}",
                    self.ptr, self.size, err
                );
            }
        }
    }
}



// UART16550 emulation moved to arch/x86_64/port.rs (x86_64) / arch/aarch64/port.rs (stub).
// Imported above as `use crate::arch::port::Uart16550`.

/// A forked sandbox — ready to execute code
pub struct ForkedVm {
    pub vm: Vm,
    pub vcpu: Vcpu,
    pub kvm_run_ptr: *mut u8,
    pub kvm_run_size: usize,
    pub serial: SerialPort,
    pub memory_ptr: *mut u8,
    pub memory_size: u64,
    /// If true, HLT is treated as idle-wait (inject IRQ, continue).
    /// If false, HLT is treated as completion (return Ok(())).
    /// Set `true` for post-boot kernels with init, `false` for stubs.
    pub post_boot: bool,
    /// If true, KVM_CREATE_IRQCHIP was called (in-kernel irqchip is active).
    /// When true, use set_irq_line() instead of signal_lapic_irq() for
    /// interrupt delivery, as KVM_SET_VCPU_EVENTS interrupt injection is
    /// silently ignored and may cause VMENTRY failures.
    pub enable_irqchip: bool,
    /// If true (default), inject 64 bytes of host CSPRNG into ENTROPY_BUF_PHYS
    /// before each KVM_RUN so that each fork diverges the kernel CRNG differently.
    /// If false, write zeros instead — all forks start with identical CRNG state.
    /// Set to `false` via `--measure` flag for CRNG decorrelation experiments.
    pub entropy_divergence: bool,
    /// Optional virtio-net device for network support.
    /// When present, MMIO exits in VIRTIO_MMIO_ADDR range are dispatched to it.
    pub virtio_net: Option<RefCell<VirtioNetPci>>,
}

// SAFETY:
// - KVM fds (vm, vcpu) are thread-safe at kernel level — ioctl on KVM fds is safe
// - kvm_run_ptr and memory_ptr are *mut u8: reading them requires `unsafe`,
//   writing to them requires `&mut self`.
// - SerialPort is Send + Sync (only contains VecDeque)
// - Sync is NOT implemented because kvm_run points to MAP_SHARED memory that
//   the kernel writes to during KVM_RUN. Concurrent reads via `&ForkedVm`
//   would race with kernel writes, causing torn reads. Only `Send` is safe
//   because moving a ForkedVm between threads transfers exclusive ownership.
unsafe impl Send for ForkedVm {}

impl std::fmt::Debug for ForkedVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkedVm")
            .field("vm", &self.vm)
            .field("vcpu", &self.vcpu)
            .field("kvm_run_size", &self.kvm_run_size)
            .field("serial", &self.serial)
            .field("memory_size", &self.memory_size)
            .finish()
    }
}

// SAFETY: ForkedVm holds mmap'd memory that must be munmap'd on drop.
// kvm_run_ptr is from mmap(MAP_SHARED, KVM vcpu fd), memory_ptr is from
// mmap(MAP_PRIVATE|MAP_ANONYMOUS). Both must be unmapped with their respective sizes.
impl Drop for ForkedVm {
    fn drop(&mut self) {
        unsafe {
            if !self.memory_ptr.is_null() {
                libc::munmap(
                    self.memory_ptr as *mut libc::c_void,
                    self.memory_size as libc::size_t,
                );
            }
            if !self.kvm_run_ptr.is_null() {
                libc::munmap(
                    self.kvm_run_ptr as *mut libc::c_void,
                    self.kvm_run_size as libc::size_t,
                );
            }
        }
    }
}

impl ForkedVm {
    /// Measure fork latency using the architecture's cycle counter
    /// (rdtsc on x86_64, cntvct on aarch64).
    pub fn measure_fork_latency(&self) -> u64 {
        read_timer()
    }

    /// Validate that a given memory range [base, base+len) is within the
    /// guest memory region. Returns an error with a descriptive message
    /// if the range overflows or exceeds `self.memory_size`.
    fn validate_memory_range(&self, base: usize, len: usize, _label: &str) -> Result<()> {
        let end = base.checked_add(len).ok_or({
            ForkError::GuestExit {
                reason: 0xBADC, // memory range overflow
            }
        })?;
        let mem_end = self.memory_size as usize;
        if end > mem_end {
            return Err(ForkError::GuestExit {
                reason: 0xBADD, // memory range exceeds allocation
            });
        }
        Ok(())
    }

    /// Run the forked VM until the guest init writes "READY" to the ready
    /// signal location (`OUT_BUF_PHYS + READY_SIGNAL_OFFSET`).
    ///
    /// The guest init uses a userspace polling loop: it reads CMD_BUF via
    /// /dev/mem, executes code, writes output to OUT_BUF, writes "READY",
    /// then spins in userspace for ~500-1000µs before repeating. Since all
    /// /dev/mem accesses are handled in-hardware by EPT (no KVM exit), the
    /// VCPU never exits to userspace during normal operation. We use a
    /// 500µs setitimer interval to periodically kick the VCPU out of KVM_RUN
    /// and check guest memory for READY.
    ///
    /// Because the init spends >99% of time in userspace (the spin loop),
    /// there's a >99% probability that the timer catches the VCPU in
    /// userspace — which means NO kernel locks are held.
    ///
    /// Takes `&mut self` because KVM_RUN mutates kvm_run state.
    /// Calling twice on the same ForkedVm without resetting is UB.
    ///
    /// # Safety
    /// The VCPU must be properly configured (registers, memory, etc.)
    /// before calling this. Returns errors for KVM_EXIT_FAIL_ENTRY and
    /// unexpected exits.
    pub unsafe fn run_until_ready(&mut self) -> Result<()> {
        let vcpu = &self.vcpu;
        let start = std::time::Instant::now();
        let mut uart = Uart16550::new();
        let mut io_count: u64 = 0;
        let mut tick_count: u64 = 0;

        // Ensure the VCPU is in RUNNABLE state before the first KVM_RUN.
        let _ = vcpu.set_mp_state(kvm::MpState::Runnable);

        // Install SIGALRM handler for 500µs READY polling.
        // SAFETY: sigusr1_handler is a valid extern "C" signal handler function.
        // CRITICAL: We must NOT use SA_RESTART because KVM_RUN (an ioctl) needs to
        // return EINTR when SIGALRM fires. With SA_RESTART (which `signal()` uses
        // on modern Linux), the kernel would automatically restart KVM_RUN and
        // we'd never see the signal.
        let handler = sigusr1_handler as *const () as usize;
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler;
            sa.sa_flags = 0; // NO SA_RESTART — we need syscall interruption
            libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        }
        // Set 500µs interval timer for periodic READY polling.
        // With the fast C init (non-volatile PAUSE loop), the guest exec
        // takes ~2-4ms. The 500µs timer adds at most 500µs of latency.
        // SAFETY: setitimer with valid itimerval is always safe.
        unsafe {
            let itv = libc::itimerval {
                it_interval: libc::timeval { tv_sec: 0, tv_usec: 500 },
                it_value: libc::timeval { tv_sec: 0, tv_usec: 50 },
            };
            libc::setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut());
        }

        loop {
            // Check timeout (30 seconds)
            if start.elapsed() > std::time::Duration::from_secs(30) {
                unsafe { Self::disarm_timer(); }
                let serial_out = String::from_utf8_lossy(uart.output());
                tracing::info!("TIMEOUT — guest did not complete READY within 30s");
                tracing::info!("Serial output captured ({} chars): {:?}",
                    uart.output().len(), serial_out);
                return Err(ForkError::GuestExit {
                    reason: 0xDEAD, // custom timeout
                });
            }

            // Drain TAP fd before each KVM_RUN so the guest sees fresh data.
            if let Some(net) = self.virtio_net.as_ref() {
                let mut net = net.borrow_mut();
                let was_read = net.isr;
                net.try_rx();
                if net.isr != was_read {
                    if self.enable_irqchip {
                        vcpu.inject_lapic_irq(0x3b);
                    }
                }
            }

            let ret = unsafe { vcpu.run()? };
            // Clear LAPIC ISR for vector 0x3B after every KVM_RUN to unblock
            // the timer (same priority class 3) and enable re-delivery.
            // With PIC-only routing the guest never sends LAPIC EOI.
            if self.enable_irqchip {
                vcpu.clear_lapic_isr(0x3b);
            }

            if ret == libc::EINTR {
                // SIGALRM tick — check READY
                if SIGNAL_INTERRUPTED.swap(false, Ordering::SeqCst) {
                    tick_count += 1;

                    // On every timer tick, try virtio RX polling to drain TAP fd.
                    if tick_count < 5 || tick_count.is_multiple_of(500) {
                        tracing::info!("FORK TICK #{} elapsed={:?}", tick_count, start.elapsed());
                    }
                    if let Some(net) = self.virtio_net.as_ref() {
                        let mut net = net.borrow_mut();
                        let was_read = net.isr;
                        net.try_rx();
                        if net.isr != was_read {
                            if self.enable_irqchip {
                                vcpu.inject_lapic_irq(0x3b);
                            } else {
                                let _ = vcpu.signal_lapic_irq(0x3b);
                            }
                        }
                    }

                    // Periodic progress logging every 1000 ticks (~500ms)
                    if tick_count.is_multiple_of(1000) {
                        if let Ok(r) = vcpu.get_regs() {
                            // Dump CMD_BUF, OUT_BUF, and READY location
                            let read_buf = |addr: u64, max: usize| -> String {
                                let mut out = String::new();
                                for i in 0..max.min(64) {
                                    let byte = unsafe { std::ptr::read(self.memory_ptr.add(addr as usize + i)) };
                                    if byte == 0 { break; }
                                    if byte.is_ascii_graphic() || byte == b' ' || byte == b'\n' {
                                        out.push(byte as char);
                                    } else {
                                        out.push_str(&format!("\\x{:02x}", byte));
                                    }
                                }
                                out
                            };
                            let cmd = read_buf(CMD_BUF_PHYS, 128);
                            let out = read_buf(OUT_BUF_PHYS, 128);
                            let ready = read_buf(OUT_BUF_PHYS + READY_SIGNAL_OFFSET, 6);
                            let serial_out = String::from_utf8_lossy(uart.output());
                            tracing::info!("FORK RUN: tick={} rip=0x{:x} rflags=0x{:x} io_count={} cmd=[{}] out=[{}] ready=[{}] serial=[{:?}] elapsed={:?}",
                                tick_count, r.rip, r.rflags, io_count, cmd, out, ready, serial_out, start.elapsed());
                        }
                    }
                    if self.check_ready() {
                        unsafe { Self::disarm_timer(); }
                        tracing::info!("READY signal detected (fork exec completed)");
                        return Ok(());
                    }
                }
                continue;
            }

            let reason = unsafe { Vcpu::exit_reason(self.kvm_run_ptr) };
            match reason {
                kvm::KVM_EXIT_IO => {
                    io_count += 1;
                    // SAFETY: kvm_run_ptr points to a valid kvm_run mmap.
                    let (direction, size, port, _count, data_offset) =
                        unsafe { crate::arch::exit::read_io_info(self.kvm_run_ptr) };
                    // Log every 500th IO exit to see port access patterns
                    if io_count.is_multiple_of(500) {
                        let dir_str = if direction == 0 { "IN" } else { "OUT" };
                        tracing::debug!("IO#{:06} {} port=0x{:x} size={}", io_count, dir_str, port, size);
                    }
                    // After each IO exit, try virtio RX polling (deliver pending packets)
                    if let Some(net) = self.virtio_net.as_ref() {
                        let mut net = net.borrow_mut();
                        let was_read = net.isr;
                        net.try_rx();
                        if net.isr != was_read {
                            if self.enable_irqchip {
                                vcpu.inject_lapic_irq(0x3b);
                            } else {
                                let _ = vcpu.signal_lapic_irq(0x3b);
                            }
                        }
                    }
                    // Periodic serial output dump
                    if io_count % 2000 == 0 && io_count > 0 {
                        let serial_out = String::from_utf8_lossy(uart.output());
                        if !serial_out.is_empty() {
                            tracing::info!("[serial @ io_count={}] {:?}", io_count, serial_out);
                        }
                    }
                    if direction == 0 {
                        // IN: guest reads from port — provide default values
                        // SAFETY: data_offset is within the kvm_run mmap.
                        unsafe {
                            let data_ptr = self.kvm_run_ptr.add(data_offset);
                            for i in 0..size {
                                let val: u8 = match port {
                                    // PCI config data: no device
                                    PCI_CONFIG_PORT_START..=PCI_CONFIG_PORT_END => 0xFF,
                                    // Serial ports: use UART emulation (offset from COM1_BASE)
                                    UART_PORT_START..=UART_PORT_END => {
                                        let offset = port - COM1_BASE;
                                        uart.read_reg(offset)
                                    }
                                    // PIT counter 0: no in-kernel PIT
                                    PIT_DATA0..=PIT_DATA2 => 0x00,
                                    // PIC: all masked
                                    PIC_MASTER_CMD..=PIC_MASTER_DATA | PIC_SLAVE_CMD..=PIC_SLAVE_DATA => 0xFF,
                                    PIT_COMMAND | PPI_PORT_B => 0x00,
                                    _ => 0x00,
                                };
                                std::ptr::write(data_ptr.add(i), val);
                            }
                        }
                    } else {
                        // OUT: guest writes to port — drain serial output
                        // SAFETY: data_offset is within the kvm_run mmap.
                        unsafe {
                            let data_ptr = self.kvm_run_ptr.add(data_offset);
                            let val = std::ptr::read(data_ptr as *const u8);
                            if let UART_PORT_START..=UART_PORT_END = port {
                                let offset = port - COM1_BASE;
                                uart.write_reg(offset, val);
                            }
                        }
                    }
                    // After IO, check READY
                    if io_count.is_multiple_of(1000) && self.check_ready() {
                        unsafe { Self::disarm_timer(); }
                        tracing::info!("READY signal detected after IO exit #{}", io_count);
                        return Ok(());
                    }
                    continue;
                }
                kvm::KVM_EXIT_HLT => {
                    // Guest kernel entered idle loop (no runnable processes).
                    // Check READY first — if init wrote READY before HLT, we're done.
                    if self.check_ready() {
                        unsafe { Self::disarm_timer(); }
                        tracing::info!("READY signal detected after HLT (fork exec completed)");
                        return Ok(());
                    }
                    // If not ready, the guest is just idle — the init process is
                    // waiting for a child (e.g., Python) to finish via waitpid.
                    // We inject a raw interrupt vector 0x20 (timer IRQ) to wake
                    // the guest out of HLT. Without an in-kernel irqchip there is
                    // no PIT to generate timer interrupts automatically.
                    //
                    // KVM_INTERRUPT works WITHOUT an irqchip (it injects a raw
                    // vector into the VCPU). If an irqchip IS present, this call
                    // silently fails with ENODEV — but then the PIT handles it.
                    let _ = vcpu.set_mp_state(kvm::MpState::Runnable);
                    if let Err(e) = vcpu.inject_interrupt(0x20) {
                        tracing::debug!("inject_interrupt(0x20) failed: {e} (continuing)");
                    }
                    continue;
                }
                kvm::KVM_EXIT_MMIO => {
                    let phys_addr = unsafe {
                        std::ptr::read(self.kvm_run_ptr.add(32) as *const u64)
                    };
                    let mmio_len = unsafe {
                        std::ptr::read(self.kvm_run_ptr.add(48) as *const u32)
                    };
                    let is_write = unsafe {
                        std::ptr::read(self.kvm_run_ptr.add(52) as *const u8)
                    } != 0;

                    use crate::arch::layout::{VIRTIO_MMIO_ADDR, VIRTIO_MMIO_SIZE};
                    if phys_addr >= VIRTIO_MMIO_ADDR && phys_addr < VIRTIO_MMIO_ADDR + VIRTIO_MMIO_SIZE {
                        if let Some(ref net_cell) = self.virtio_net {
                            let offset = (phys_addr - VIRTIO_MMIO_ADDR) as u32;
                            let mut net = net_cell.borrow_mut();
                            if !is_write {
                                let val = net.mmio_read(offset);
                                let data_ptr = self.kvm_run_ptr.add(40);
                                for i in 0..mmio_len.min(4) as usize {
                                    unsafe { std::ptr::write(data_ptr.add(i), ((val >> (i * 8)) & 0xFF) as u8) };
                                }
                            } else {
                                let mut val = 0u32;
                                let data_ptr = self.kvm_run_ptr.add(40);
                                for i in 0..mmio_len.min(4) as usize {
                                    val |= (unsafe { std::ptr::read(data_ptr.add(i)) } as u32) << (i * 8);
                                }
                                net.mmio_write(offset, val);
                                // After each MMIO write (kick), deliver pending RX packets
                                let was_read = net.isr;
                                net.try_rx();
                                if net.isr != was_read {
                                    if self.enable_irqchip {
                                        vcpu.inject_lapic_irq(0x3b);
                                    } else {
                                        let _ = vcpu.signal_lapic_irq(0x3b);
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    // Unhandled MMIO — ignore (return 0xFF for reads)
                    if !is_write {
                        let data_ptr = self.kvm_run_ptr.add(40);
                        for i in 0..mmio_len.min(8) as usize {
                            unsafe { std::ptr::write(data_ptr.add(i), 0xFFu8) };
                        }
                    }
                    continue;
                }
                kvm::KVM_EXIT_SHUTDOWN => {
                    unsafe { Self::disarm_timer(); }
                    tracing::info!("KVM_EXIT_SHUTDOWN — guest completed (poweroff or triple-fault)");
                    return Ok(());
                }
                kvm::KVM_EXIT_FAIL_ENTRY => {
                    unsafe { Self::disarm_timer(); }
                    let hw_fail = unsafe {
                        std::ptr::read(self.kvm_run_ptr.add(32) as *const u64)
                    };
                    tracing::error!(
                        "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason=0x{:x}",
                        hw_fail,
                    );
                    return Err(ForkError::GuestExit {
                        reason: kvm::KVM_EXIT_FAIL_ENTRY,
                    });
                }
                r => {
                    unsafe { Self::disarm_timer(); }
                    tracing::info!("UNEXPECTED EXIT reason={}", r);
                    return Err(ForkError::GuestExit { reason: r });
                }
            }
        }
    }

    /// Disarm the setitimer timer (cancel pending timer).
    /// SAFETY: setitimer with zero itimerval is always safe.
    unsafe fn disarm_timer() {
        let zero_itv = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: 0, tv_usec: 0 },
        };
        libc::setitimer(libc::ITIMER_REAL, &zero_itv, std::ptr::null_mut());
    }

    /// Run the forked VM until it executes a HLT instruction.
    /// Used by stub tests where the VM is a simple userspace program
    /// that HLTs to signal completion.
    ///
    /// # Safety
    /// The VCPU must be properly configured (registers, memory, etc.)
    /// before calling this.
    pub unsafe fn run_until_hlt(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                return Err(ForkError::GuestExit { reason: 0xDEAD });
            }
            match unsafe { self.vcpu.run() } {
                Ok(ret) if ret == libc::EINTR => continue,
                Ok(_) => {},
                Err(e) => return Err(ForkError::Kvm(e)),
            }
            let reason = unsafe { Vcpu::exit_reason(self.kvm_run_ptr) };
            match reason {
                kvm::KVM_EXIT_HLT => return Ok(()),
                kvm::KVM_EXIT_SHUTDOWN => return Ok(()),
                _ => return Err(ForkError::GuestExit { reason }),
            }
        }
    }

    /// Check if the guest has written "READY" to the ready signal location
    /// (`OUT_BUF_PHYS + READY_SIGNAL_OFFSET`).
    ///
    /// Returns true if the 5 bytes at the ready location equal "READY".
    ///
    /// # Safety
    /// Accesses guest memory via memory_ptr. Called from within the KVM_RUN
    /// loop where memory_ptr is guaranteed to be a valid mmap'd region.
    fn check_ready(&self) -> bool {
        const READY_ADDR: u64 = OUT_BUF_PHYS + READY_SIGNAL_OFFSET;
        // Validate bounds
        if let Err(e) = self.validate_memory_range(READY_ADDR as usize, 5, "check_ready") {
            tracing::warn!("check_ready bounds check failed: {e}");
            return false;
        }
        // SAFETY: validate_memory_range confirmed (READY_ADDR..READY_ADDR+5)
        // is within memory_size. memory_ptr is a valid mmap'd allocation.
        let mut ready = [0u8; 5];
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.memory_ptr.add(READY_ADDR as usize),
                ready.as_mut_ptr(),
                5,
            );
        }
        &ready == b"READY"
    }

    /// Read guest memory at a given physical address.
    ///
    /// Returns `None` if the address range extends beyond guest memory.
    /// NOTE: Assumes `load_addr == 0`, so `memory_ptr[guest_phys]` maps to
    /// guest physical `guest_phys`. If load_addr != 0, offset by load_addr.
    /// # Safety
    /// `guest_phys + len` must be within `[0, self.memory_size)`.
    pub unsafe fn read_guest_mem(&self, guest_phys: u64, len: usize) -> Option<&[u8]> {
        let end = guest_phys as usize + len;
        if end > self.memory_size as usize {
            return None;
        }
        // NOTE: if snapshot.load_addr != 0, offset by load_addr
        Some(unsafe {
            std::slice::from_raw_parts(self.memory_ptr.add(guest_phys as usize), len)
        })
    }

    /// Inject code into the command buffer, run the VM, and read output — all in one call.
    ///
    /// This is the standard entry point for executing code on a forked VM.
    /// It consolidates the bounds checks + unsafe pointer operations + run + output parse
    /// into a single safe-ish API so callers don't duplicate unsafe code.
    ///
    /// # Steps
    /// 1. Bounds check `CMD_BUF_PHYS + BUF_MAX ≤ memory_size`
    /// 2. Bounds check `OUT_BUF_PHYS + BUF_MAX ≤ memory_size`
    /// 3. Copy code bytes to `CMD_BUF_PHYS` + null-terminate
    /// 4. Call `run_until_ready()`
    /// 5. Read output from `OUT_BUF_PHYS`
    /// 6. Trim trailing whitespace, convert to `String`
    ///
    /// # Safety
    /// The VCPU must be properly configured before calling this (regs, memory, etc.).
    /// `run_until_ready()` has its own safety contract — see its documentation.
    pub unsafe fn run_code(&mut self, code: &str) -> std::result::Result<String, String> {
        // SAFETY: prepare_vm_for_execution borrows memory_ptr/memory_size
        // from self without aliasing — we pass raw pointers.
        crate::boot::prepare_vm_for_execution(
            self.memory_ptr,
            self.memory_size,
            self.entropy_divergence,
            code,
        )?;

        // SAFETY: We own &mut self, so no concurrent KVM_RUN.
        self.run_until_ready()
            .map_err(|e| format!("VM run failed: {e}"))?;

        // SAFETY: read_vm_output only reads from guest memory.
        let output = crate::boot::read_vm_output(self.memory_ptr, self.memory_size);

        // Append entropy tail bytes for process_replay divergence detection.
        // init.c writes 4 entropy bytes at OUT_BUF + BUF_MAX - 8.
        // SAFETY: BUF_MAX is at least 4096, so BUF_MAX - 8 + 4 < BUF_MAX
        // is well within bounds (checked by prepare_vm_for_execution).
        use crate::arch::{BUF_MAX, OUT_BUF_PHYS};
        let ptr = self.memory_ptr.add(OUT_BUF_PHYS as usize);
        let ent_tail: [u8; 4] = [
            std::ptr::read(ptr.add(BUF_MAX as usize - 8)),
            std::ptr::read(ptr.add(BUF_MAX as usize - 7)),
            std::ptr::read(ptr.add(BUF_MAX as usize - 6)),
            std::ptr::read(ptr.add(BUF_MAX as usize - 5)),
        ];
        Ok(format!(
            "{}ENTROPY:{:02x}{:02x}{:02x}{:02x}",
            output, ent_tail[0], ent_tail[1], ent_tail[2], ent_tail[3]
        ))
    }
}

/// The fork engine — manages the parent VM and spawns children
#[derive(Debug)]
pub struct ForkEngine {
    pub kvm: Kvm,
    pub snapshot: Snapshot,
    pub vcpu_mmap_size: usize,
    /// If true, creates in-kernel PIT/PIC/IOAPIC/LAPIC on each forked VM.
    /// Required for the real kernel (timer interrupts), but NOT for stub
    /// kernels which lack an IDT and would hang on PIT interrupts during HLT.
    pub enable_irqchip: bool,
    /// Cached CPUID entries from the host (avoids KVM_GET_SUPPORTED_CPUID ioctl per fork).
    cpuid_cache: Vec<KvmCpuidEntry2Raw>,
    /// Shared memory regions to inject into every forked VM (EPT zero-copy).
    /// Each entry is (region, guest_phys_addr).
    shared_regions: Vec<(SharedMemoryRegion, u64)>,
    /// Optional TAP file descriptor for real network access.
    /// When set, virtio-net will be able to send/receive packets to the host network.
    /// Must be set before calling `fork()`.
    tap_fd: Option<i32>,
}

impl ForkEngine {
    /// Create a new fork engine from a booted VM snapshot
    pub fn new(kvm: Kvm, snapshot: Snapshot, vcpu_mmap_size: usize) -> Self {
        // Pre-fetch and cache CPUID entries once — avoids KVM_GET_SUPPORTED_CPUID ioctl per fork.
        let mut cpuid_cache = kvm.get_supported_cpuid().unwrap_or_default();

        // Apply CPUID filters (delegated to arch module).
        // Every feature that adds an xstate_bv bit must be cleared here to prevent
        // XRSTOR #GP on fork: if the kernel saved fpstate during boot with these
        // bits set, and the fork removes them from XCR0/CPUID, XRSTOR faults.
        crate::arch::vcpu::filter_cpuid_for_fork(&mut cpuid_cache);

        info!(
            "ForkEngine created: snapshot {}MB, {} CPUID entries cached",
            snapshot.memory_size / (1024 * 1024),
            cpuid_cache.len(),
        );
        Self {
            kvm,
            snapshot,
            vcpu_mmap_size,
            enable_irqchip: false,
            cpuid_cache,
            shared_regions: Vec::new(),
            tap_fd: None,
        }
    }

    /// Register a shared memory region to be EPT-mapped into every forked VM.
    ///
    /// The region appears at `guest_phys` in the guest's physical address space
    /// as read-only memory. All forks share the same physical pages (zero-copy).
    ///
    /// Slot numbers start at 1 (slot 0 is always the primary snapshot memory).
    pub fn add_shared_region(&mut self, region: SharedMemoryRegion, guest_phys: u64) {
        self.shared_regions.push((region, guest_phys));
    }

    /// Set a TAP file descriptor for real network access.
    /// The fd is duplicated immediately (before seccomp is installed).
    pub fn set_tap_fd(&mut self, fd: i32) {
        unsafe { libc::write(2, b"SET_TAP_FD_ENTER\n" as *const u8 as *const libc::c_void, 18); }
        let dup_fd = unsafe { libc::dup(fd) };
        unsafe { libc::write(2, b"SET_TAP_FD_DUP_DONE\n" as *const u8 as *const libc::c_void, 21); }
        self.tap_fd = Some(if dup_fd < 0 { fd } else { dup_fd });
        unsafe { libc::write(2, b"SET_TAP_FD_EXIT\n" as *const u8 as *const libc::c_void, 17); }
    }

    /// List registered shared memory regions (region, guest_phys).
    pub fn shared_regions(&self) -> &[(SharedMemoryRegion, u64)] {
        &self.shared_regions
    }

    /// Fork a new sandbox from the snapshot
    ///
    /// 1. Create new VM with KVM_CREATE_VM
    /// 2. mmap(MAP_PRIVATE) snapshot memory → CoW
    /// 3. Set memory region on new VM
    /// 4. Create VCPU
    /// 5. mmap kvm_run
    /// 6. Restore CPU state
    /// 7. Return ready-to-run ForkedVm
    ///
    /// # Safety
    ///
    /// All resources (mmap'd memory, VCPU fd) are wrapped in scope guards
    /// so that if any step fails, previously allocated resources are freed.
    pub fn fork(&self) -> Result<ForkedVm> {
        let start_ticks = read_timer();

        // 1. Create VM
        let vm = self.kvm.create_vm()?;

        // 2. CoW mmap: create a private mapping backed by the snapshot mem file
        //    (kernel-level CoW — no memcpy needed, only dirty pages are copied)
        // SAFETY:
        // - mmap with MAP_PRIVATE and the snapshot mem_fd creates a file-backed mapping.
        //   The kernel maps file pages read-only. First write by the guest triggers a
        //   page fault and the kernel copies ONLY the touched page (true CoW).
        // - When mem_fd is None (tests or fresh snapshots), fall back to anonymous + memcpy.
        let mem_size = self.snapshot.memory_size;
        let mem_ptr = if let Some(ref mem_fd) = self.snapshot.mem_fd {
            unsafe {
                let ptr = libc::mmap(
                    ptr::null_mut(),
                    mem_size as libc::size_t,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE,
                    mem_fd.as_raw_fd(),
                    0,
                );
                if ptr == libc::MAP_FAILED {
                    return Err(ForkError::Kvm(kvm::KvmError::Mmap(
                        "fork CoW mmap from mem_fd failed".into(),
                    )));
                }
                ptr as *mut u8
            }
        } else {
            // Fallback: anonymous + memcpy (for tests or fresh snapshots without mem_fd)
            if self.snapshot.memory.is_empty() {
                return Err(ForkError::Kvm(kvm::KvmError::Mmap(
                    "fork fallback: snapshot memory Vec is empty and no mem_fd".into(),
                )));
            }
            unsafe {
                let ptr = libc::mmap(
                    ptr::null_mut(),
                    mem_size as libc::size_t,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if ptr == libc::MAP_FAILED {
                    return Err(ForkError::Kvm(kvm::KvmError::Mmap(
                        "fork anonymous mmap failed".into(),
                    )));
                }
                ptr::copy_nonoverlapping(
                    self.snapshot.memory.as_ptr(),
                    ptr as *mut u8,
                    self.snapshot.memory.len(),
                );
                ptr as *mut u8
            }
        };

        // Huge page hint: ask the kernel to use 2MB transparent huge pages
        // for this CoW mapping. This reduces EPT page table depth from 4→3
        // (or 4→2 for 2MB-aligned regions), cutting per-VM page table
        // overhead from ~100KB to ~30-40KB.
        // MADV_HUGEPAGE is a hint — the kernel may ignore it if THP is
        // disabled or if memory is fragmented. Non-fatal on failure.
        // SAFETY: mem_ptr is a valid mmap'd region of mem_size bytes.
        // madvise is always safe on a valid mmap region — it only changes
        // kernel page table management hints, not memory contents.
        unsafe {
            let ret = libc::madvise(
                mem_ptr as *mut libc::c_void,
                mem_size as libc::size_t,
                libc::MADV_HUGEPAGE,
            );
            if ret != 0 {
                tracing::trace!(
                    "madvise(MADV_HUGEPAGE) ignored (non-fatal): errno={}",
                    *libc::__errno_location(),
                );
            }
        }

        // Wrap in scope-guard: if anything fails before ForkedVm is constructed,
        // the mmap'd memory will be freed automatically.
        let mem_guard = MmapGuard::new(mem_ptr, mem_size as usize);

        let after_mmap = read_timer();

        // 3. Set memory region on new VM
        // SAFETY: mem_ptr is a valid mmap region of mem_size bytes
        unsafe {
            vm.set_memory_region(
                0,                                 // slot 0
                self.snapshot.load_addr,           // guest phys addr
                mem_size,                          // size
                mem_ptr,                           // host addr
                0,                                 // flags (RW)
            )?;
        }

        // 4. Inject shared memory regions (EPT zero-copy) into the new VM.
        //    Each shared region gets an incremental slot starting at 1.
        //    Slot 0 is always the primary snapshot memory set above.
        for (i, (region, guest_phys)) in self.shared_regions.iter().enumerate() {
            let slot_offset = i as u32; // 0 → slot 1, 1 → slot 2, etc.
            region.ept_map(&vm, self.kvm.as_raw_fd(), *guest_phys, slot_offset)?;
        }

        // 5. Optionally create in-kernel IRQ chip (PIT + PIC + IOAPIC + LAPIC)
        // Must be BEFORE VCPU creation (KVM_CREATE_IRQCHIP returns EINVAL if
        // VCPUs already exist). Required for real kernel timer interrupts.
        //
        // NOTE: On Linux 6.x, KVM_CREATE_IRQCHIP creates PIC/IOAPIC/LAPIC but
        // NOT the PIT. We must additionally create the in-kernel PIT via
        // KVM_CREATE_PIT2 so that PIT timer interrupts are generated.
        //
        // On aarch64, interrupt controller setup uses GICv3 (KVM_CREATE_DEVICE
        // with KVM_DEV_TYPE_ARM_VGIC_V3). The PIC/IOAPIC model is x86-specific.
        #[cfg(target_arch = "x86_64")]
        if self.enable_irqchip {
            vm.create_irqchip()?;
            vm.create_pit()?;
            // Configure the PIT for 100Hz periodic timer interrupts. Without
            // this, the fresh PIT from KVM_CREATE_PIT2 has default state (no
            // periodic output) and the guest kernel's scheduler never ticks.
            if let Err(e) = crate::arch::vm::set_pit2(vm.as_raw_fd()) {
                tracing::warn!("set_pit2 failed: {e} (timer interrupts may not work)");
            }

            // Restore irqchip state (PIC master, PIC slave, IOAPIC) from snapshot.
            // A fresh KVM_CREATE_IRQCHIP initializes the PIC with all interrupts
            // masked (IMR=0xFF). The guest kernel expects specific unmasked interrupts
            // (e.g., timer IRQ 0). Without restoration, timer IRQs won't fire and the
            // guest will idle forever.
            if let Some(chips) = &self.snapshot.irqchips {
                let restore_one = |chip_id: u32, data: &Option<Box<[u8; 512]>>| {
                    if let Some(d) = data {
                        let raw = crate::kvm::KvmIrqChipRaw { chip_id, dummy: *d.as_ref(), ..Default::default() };
                        // SAFETY: vm is a valid VM fd, chip data came from a prior
                        // KVM_GET_IRQCHIP on the same VM configuration.
                        unsafe {
                            if let Err(e) = vm.set_irqchip(&raw) {
                                tracing::warn!("Failed to restore irqchip {chip_id}: {e}");
                            }
                        }
                    }
                };
                restore_one(crate::kvm::KVM_IRQCHIP_PIC_MASTER, &chips.master_pic);
                restore_one(crate::kvm::KVM_IRQCHIP_PIC_SLAVE, &chips.slave_pic);
                restore_one(crate::kvm::KVM_IRQCHIP_IOAPIC, &chips.ioapic);

                // The guest booted with acpi=off, so it uses the PIC (8259), not the
                // IOAPIC.  KVM_IRQ_LINE asserts on both PIC and IOAPIC, but we need
                // the IOAPIC path to work (it uses the non-destructive LAPIC IRR
                // mechanism).  Mask IRQ 11 on the slave PIC (set IMR bit 3) to
                // prevent the ExtInt INTA cycle from destroying PIC state.
                // The IOAPIC entry (patched below) will deliver via LAPIC IRR.
                {
                    let master_back = unsafe { vm.get_irqchip(crate::kvm::KVM_IRQCHIP_PIC_MASTER) };
                    if let Ok(pic) = master_back {
                        let imr = pic.dummy[2];
                        let irq_base = pic.dummy[5];
                        let irq2 = (imr >> 2) & 1;
                        tracing::info!(
                            "PIC_MASTER: IMR=0x{imr:02x} (IRQ2={irq2}) irq_base=0x{irq_base:02x}"
                        );
                        tracing::info!("PIC_MASTER: full state: {:02x?}", &pic.dummy[..16]);
                    }
                }
                {
                    let slave_back = unsafe { vm.get_irqchip(crate::kvm::KVM_IRQCHIP_PIC_SLAVE) };
                    if let Ok(mut pic) = slave_back {
                        // kvm_pic_state layout: offset 0 = last_irr, 1 = irr,
                        // 2 = imr (Interrupt Mask Register), 3 = isr
                        let imr_offset = 2usize;
                        let imr = pic.dummy[imr_offset];
                        let irq_base = pic.dummy[5];
                        let irq11 = (imr >> 3) & 1;
                        tracing::info!("PIC_SLAVE: IMR=0x{imr:02x} (IRQ11={irq11}) irq_base=0x{irq_base:02x}");
                        tracing::info!("PIC_SLAVE: full state: {:02x?}", &pic.dummy[..16]);
                        // Unmask IRQ 11 = slave pin 3 (clear bit 3) — use PIC ExtINT path
                        if (imr >> 3) & 1 == 1 {
                            pic.dummy[imr_offset] = imr & !(1u8 << 3);
                            unsafe {
                                let raw = crate::kvm::KvmIrqChipRaw {
                                    chip_id: crate::kvm::KVM_IRQCHIP_PIC_SLAVE,
                                    dummy: pic.dummy,
                                    ..Default::default()
                                };
                                let _ = vm.set_irqchip(&raw);
                            }
                            tracing::info!("PIC_SLAVE: unmasked IRQ 11 (slave pin 3)");
                        }
                    }
                }

                // After restoring the IOAPIC, patch the entry for IRQ 11 (virtio-net).
                // The snapshot's IOAPIC has ALL entries masked (mask=1, vector=0)
                // The snapshot's IOAPIC has ALL entries masked because the guest
                // kernel booted with acpi=off and never configured the IOAPIC.
                // Set IOAPIC entry 11 to vector 0x3B = slave PIC base 0x38 + pin 3.
                // Use LEVEL-triggered (bit 15 = 0x8000) so kvm_ioapic_send_eoi()
                // propagates the PIC EOI to the LAPIC and clears its ISR bit.
                // KVM_IRQ_LINE asserts both PIC and IOAPIC; the IOAPIC delivers
                // via LAPIC IRR while the PIC delivers via ExtINT LINT0.
                // Destination BSP (0).
                if let Some(ioapic_data) = &chips.ioapic {
                    let mut ioapic = [0u8; 512];
                    ioapic.copy_from_slice(ioapic_data.as_ref());
                    // kvm_ioapic_state layout: 8 base + 4 ioregsel + 4 id + 4 irr + 4 pad
                    // then 24 redirection entries of 8 bytes each at offset 24
                    let ioredirtbl_base = 24usize;
                    let entry_off = ioredirtbl_base + 11 * 8;
                    let low: u32 = 0x803B; // vector 0x3B, unmasked, level-triggered, Fixed
                    let high: u32 = 0;     // dest=0 (BSP)
                    ioapic[entry_off..entry_off + 4].copy_from_slice(&low.to_le_bytes());
                    ioapic[entry_off + 4..entry_off + 8].copy_from_slice(&high.to_le_bytes());
                    let raw = crate::kvm::KvmIrqChipRaw {
                        chip_id: crate::kvm::KVM_IRQCHIP_IOAPIC,
                        dummy: ioapic,
                        ..Default::default()
                    };
                    unsafe {
                        if let Err(e) = vm.set_irqchip(&raw) {
                            tracing::warn!("Failed to set IOAPIC IRQ 11 entry: {e}");
                        } else {
                            tracing::info!("IOAPIC: IRQ 11 entry set to vector=0x3B, level-triggered, unmasked");
                            // Verify by reading back
                            if let Ok(back) = vm.get_irqchip(crate::kvm::KVM_IRQCHIP_IOAPIC) {
                                let back_lo = u32::from_le_bytes(
                                    back.dummy[entry_off..entry_off+4].try_into().unwrap()
                                );
                                let back_vec = back_lo & 0xff;
                                let back_mask = (back_lo >> 16) & 1;
                                let back_trig = (back_lo >> 15) & 1;
                                tracing::info!(
                                    "IOAPIC: readback entry 11: vector={}, mask={}, level={}",
                                    back_vec, back_mask, back_trig
                                );
                            }
                        }
                    }
                }
            }
        }

        // 5. Create VCPU (Vcpu wraps OwnedFd — drops automatically on error)
        let vcpu = vm.create_vcpu(0)?;

        // 6. mmap kvm_run
        // SAFETY: vcpu is a valid VCPU, its fd is still open.
        // vcpu_mmap_size is from KVM_GET_VCPU_MMAP_SIZE (verified on Kvm::new()).
        // The mmap is MAP_SHARED on the VCPU fd, which is the standard protocol
        // for KVM's kvm_run structure.
        let kvm_run_ptr = unsafe { vcpu.kvm_run_ptr(self.vcpu_mmap_size)? };

        let after_mmap_run = read_timer();

        // 7. Restore CPU state
        // 7a. Set up CPUID from cache (avoids KVM_GET_SUPPORTED_CPUID ioctl per fork)
        vcpu.set_cpuid2(&self.cpuid_cache)?;

        // 7b. Restore special registers (segments, CRx, EFER, etc.)
        // SAFETY: sregs_raw is constructed from valid snapshot CPU state.
        let sregs_raw: kvm::KvmSregsRaw = self.snapshot.cpu.sregs.clone().into();
        vcpu.set_sregs(&sregs_raw)?;

        // 7c. Restore general-purpose registers
        // SAFETY: regs_raw is constructed from valid snapshot CPU state.
        let regs_raw: kvm::KvmRegsRaw = self.snapshot.cpu.regs.clone().into();
        vcpu.set_regs(&regs_raw)?;

        // 7d. Restore critical MSRs (syscall entries, segment bases, etc.)
        // The new VCPU has default MSRs (e.g., MSR_LSTAR=0), which would
        // break syscalls in the guest. We restore the snapshot's saved MSRs
        // to ensure correct kernel operation.
        if !self.snapshot.cpu.msrs.is_empty() {
            // SAFETY: restore_msrs writes MSR values from the snapshot,
            // which are known-good values saved from the running kernel.
            match unsafe { vcpu.restore_msrs(&self.snapshot.cpu.msrs) } {
                Ok(n) => {
                    if n as usize != self.snapshot.cpu.msrs.len() {
                        tracing::warn!("MSR restore: wrote {}/{} MSRs", n, self.snapshot.cpu.msrs.len());
                    }
                }
                Err(e) => {
                    tracing::warn!("MSR restore failed: {e} (continuing anyway)");
                }
            }
        } else {
            tracing::debug!("No MSRs in snapshot (legacy snapshot or test)");
        }

        // 7e. Restore XCR registers (XCR0, etc.) — critical for FPU/SSE/AVX
        // Without this, the kernel would see XCR0=0 and might fault on XSAVE/XRSTOR.
        let xcrs = &self.snapshot.cpu.xcrs;
        if xcrs.is_empty() {
            tracing::warn!("XCRS is empty in snapshot — AVX instructions will SIGILL");
        } else {
            // SAFETY: xcrs values come from the snapshot, which captured valid guest XCR state.
            if let Err(e) = unsafe { vcpu.set_xcrs(xcrs) } {
                tracing::warn!("XCRS restore failed: {e} (continuing anyway)");
            }
        }

        // 7f. Set a clean XSAVE buffer matching XCR0 (delegated to arch module).
        // See `crate::arch::vcpu::build_clean_xsave()` for details.
        let xcr0_value = xcrs.first().map(|(_, v)| *v).unwrap_or(XCR0_X87_SSE_AVX);
        let clean_xsave = crate::arch::vcpu::build_clean_xsave(xcr0_value);
        // SAFETY: xsave buffer is a valid XSAVE region per CPU ABI.
        // set_xsave is unsafe because it passes the buffer to KVM ioctl.
        match unsafe { vcpu.set_xsave(&clean_xsave) } {
            Ok(()) => tracing::debug!("XSAVE restore: clean state (xstate_bv=0x{:x})", xcr0_value & XCR0_X87_SSE_AVX),
            Err(e) => tracing::warn!("XSAVE restore failed: {e} (continuing anyway)"),
        }

        let after_restore = read_timer();

        // Save register restore timing info
        let _reg_setup_ticks = after_restore.saturating_sub(after_mmap_run);

        // 8. Enable the LAPIC if irqchip is present. KVM_CREATE_IRQCHIP leaves
        //    the LAPIC software-disabled (SVR bit 8 = 0), which blocks all
        //    interrupt delivery including IOAPIC-routed MSIs. We also configure
        //    LVT LINT0 for ExtINTA mode so PIC-originated timer interrupts work.
        if self.enable_irqchip {
            if let Err(e) = vcpu.enable_apic() {
                tracing::warn!("enable_apic failed: {e} (interrupts may not work)");
            }
        }

        let cow_str = if self.snapshot.mem_fd.is_some() { "CoW" } else { "memcpy" };
        trace!(
            "fork: {cow_str} mmap={}μs restore={}μs total={}μs",
            (after_mmap.saturating_sub(start_ticks)) * 1000 / tsc_khz(),
            (after_restore.saturating_sub(after_mmap_run)) * 1000 / tsc_khz(),
            (after_restore.saturating_sub(start_ticks)) * 1000 / tsc_khz(),
        );

        // Log the restored RIP for diagnostics
        if let Ok(r) = vcpu.get_regs() {
            tracing::debug!("fork restored: rip=0x{:x} rsp=0x{:x} rflags=0x{:x} (if={})", r.rip, r.rsp, r.rflags, (r.rflags >> 9) & 1);
        }

        // Everything succeeded — disarm the mmap guard and construct ForkedVm
        let (memory_ptr, memory_size_usize) = mem_guard.disarm();
        let memory_size = memory_size_usize as u64;

        let tap_fd = self.tap_fd;
        let virtio_net = self.snapshot.virtio_net_state.as_ref().map(|state| {
            RefCell::new(VirtioNetPci::from_state(state, memory_ptr, tap_fd))
        });

        Ok(ForkedVm {
            vm,
            vcpu,
            kvm_run_ptr,
            kvm_run_size: self.vcpu_mmap_size,
            serial: SerialPort::new(4096),
            memory_ptr,
            memory_size,
            post_boot: self.enable_irqchip,
            enable_irqchip: self.enable_irqchip,
            entropy_divergence: true,  // default: inject CSPRNG per fork
            virtio_net,
        })
    }

    /// Fork multiple VMs in a batch (for warm pool filling).
    ///
    /// Uses serial forking. Each `fork()` takes ~150μs; forking N VMs takes
    /// N × 150μs. This is optimal — concurrent forking is counterproductive
    /// because every thread shares the process VMA lock (for the 128MB mmap),
    /// the kernel KVM fd table, and `/dev/kvm` ioctl dispatch. These shared
    /// resources serialize concurrent forks under a tighter contention regime
    /// than simple serial issuance.
    ///
    /// **The correct strategy for batch throughput is pre-warming the pool**
    /// to the expected burst size, not parallelising the fork itself. With a
    /// warm pool, batch acquire is O(pop) ≈ 0.5μs/VM, or 0.5ms for 1000 VMs.
    pub fn fork_batch(&self, count: usize) -> Result<Vec<ForkedVm>> {
        let mut vms = Vec::with_capacity(count);
        for _ in 0..count {
            vms.push(self.fork()?);
        }
        Ok(vms)
    }

}

// SAFETY:
// - `ForkEngine` fields: KVM fds (kvm_fd, vm_fd, vcpu_fd) are owned file
//   descriptors — thread-safe via kernel atomic refcount.
// - Snapshot data (Snapshot) contains only plain data (Vec<u8>, scalar fields)
//   and is never mutated after construction.
// - `shared_regions: Vec<(SharedMemoryRegion, u64)>` contains `SharedMemoryRegion`
//   which is NOT `Sync`, but `&self` access to these regions is only used during
//   fork setup (reading size/guest_phys for logging). The `shared_regions()` method
//   returns `&[(SharedMemoryRegion, u64)]`; callers must ensure no concurrent
//   access to the returned references across threads (all callers use single-threaded
//   context or external synchronization like Mutex).
// - `ForkEngine` is not `Clone` — each instance is uniquely owned.
// - The `Send` impl is sound: transferring ownership of ForkEngine between threads
//   is safe because all owned resources (fds, Vecs) are Send themselves.
unsafe impl Send for ForkEngine {}
unsafe impl Sync for ForkEngine {}

// ─── SandboxBackend Integration ──────────────────────────────────────

use tinymachine_api::{SandboxBackend, Variant as ApiVariant};
use crate::template_registry::TemplateRegistry;
use tinymachine_api::ExecutionTier;

/// A `SandboxBackend` implementation wrapping `ForkEngine`.
///
/// This enables the `tinyos-core` agent loop to use the KVM fork backend
/// through the unified `SandboxBackend` trait.
///
/// # Lifecycle
/// 1. `init` — Opens KVM and the template registry, loads/creates the template
///    snapshot for the requested variant, creates a `ForkEngine`.
/// 2. `exec` — Forks a new VM from the snapshot, injects code into the command
///    buffer, runs the VM (kernel boots + init executes code), reads output.
/// 3. `reset` — No-op: each exec creates a fresh fork (no state to reset).
/// 4. `destroy` — Releases the ForkEngine (and its KVM fd) by taking `self`.
#[derive(Debug, Default)]
pub struct KvmForkBackend {
    engine: Option<ForkEngine>,
}

impl KvmForkBackend {
    /// Create a new empty KVM fork backend (must call `init` before `exec`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a TAP file descriptor on the fork engine for real network access.
    /// Must be called after `init` and before `exec`.
    pub fn set_tap_fd(&mut self, fd: i32) {
        if let Some(ref mut engine) = self.engine {
            engine.set_tap_fd(fd);
        }
    }

    /// Get the execution tier for this backend.
    pub const fn tier() -> ExecutionTier {
        ExecutionTier::KvmFork
    }
}

impl SandboxBackend for KvmForkBackend {
    fn init(&mut self, variant: &ApiVariant) -> tinymachine_api::Result<()> {
        // Map the API variant to the fork's detailed variant
        let fork_variant = crate::variant::Variant::from_api(variant)
            .ok_or_else(|| tinymachine_api::ApiError::Unsupported(
                format!("variant {}:{} not supported", variant.lang, variant.variant)
            ))?;

        let kvm = crate::kvm::Kvm::new()
            .map_err(|e| tinymachine_api::ApiError::sandbox(format!("KVM init failed: {e}")))?;
        let vcpu_mmap_size = kvm.vcpu_mmap_size()
            .map_err(|e| tinymachine_api::ApiError::sandbox(format!("vcpu_mmap_size failed: {e}")))?;

        // Open template registry and load or build the snapshot
        let registry = TemplateRegistry::open(None)
            .map_err(|e| tinymachine_api::ApiError::sandbox(format!("registry open failed: {e}")))?;

        let snapshot = if registry.has_snapshot(&fork_variant) {
            registry.load_snapshot(&fork_variant)
                .map_err(|e| tinymachine_api::ApiError::sandbox(format!("load snapshot failed: {e}")))?
        } else {
            // For Phase 1 wasm-only testing, return a minimal test snapshot
            return Err(tinymachine_api::ApiError::Unsupported(
                format!("template for {}:{} not built yet. Run `tinyos template build` first.",
                    variant.lang, variant.variant)
            ));
        };

        let mut engine = ForkEngine::new(kvm, snapshot, vcpu_mmap_size);
        // Enable in-kernel irqchip when the snapshot has virtio state, since
        // the guest kernel's interrupt subsystem was initialized with an IOAPIC
        // and expects it for IRQ routing. Without the irqchip, KVM_INTERRUPT
        // cannot deliver device interrupts to the kernel's virtio handler.
        if engine.snapshot.virtio_net_state.is_some() {
            engine.enable_irqchip = true;
            tracing::info!("ENABLE_IRQCHIP: snapshot has virtio_net_state, irqchip enabled");
        } else {
            tracing::info!("ENABLE_IRQCHIP: snapshot NO virtio_net_state, irqchip disabled");
        }
        self.engine = Some(engine);
        Ok(())
    }

    fn exec(&mut self, code: &str) -> tinymachine_api::Result<String> {
        unsafe { libc::write(2, b"KVM_EXEC_ENTER\n" as *const u8 as *const libc::c_void, 16); }
        let engine = self.engine.as_ref().ok_or_else(|| {
            tinymachine_api::ApiError::sandbox("KVM fork backend not initialised")
        })?;

        // Install seccomp-BPF filter at the start of each fork.
        // This locks down the host process syscall surface so that
        // even if the KVM guest escapes via MMIO or a kernel bug,
        // the host process can't open sockets, create files, or
        // spawn new processes.
        seccomp_install(SeccompBackend::KvmFork).map_err(|e| {
            tinymachine_api::ApiError::sandbox(format!(
                "seccomp filter installation for KVM fork failed: {e}"
            ))
        })?;

        // Fork a fresh VM from the snapshot
        let mut forked = engine.fork()
            .map_err(|e| tinymachine_api::ApiError::sandbox(format!("fork failed: {e}")))?;

        // Delegate to ForkedVm::run_code() — the single source of truth for
        // the code-inject / run / read-output cycle. run_code() handles
        // bounds checks, unsafe pointer operations, and output parsing.
        // SAFETY: forked is a properly configured post-fork VCPU.
        let output = unsafe {
            forked.run_code(code)
                .map_err(|e| tinymachine_api::ApiError::sandbox(format!("VM exec failed: {e}")))?
        };

        Ok(output)
    }

    fn reset(&mut self) -> tinymachine_api::Result<()> {
        // Each exec creates a new fork, so no state to reset.
        // If the engine was dropped, re-init would be needed.
        Ok(())
    }

    fn destroy(&mut self) -> tinymachine_api::Result<()> {
        self.engine = None;
        Ok(())
    }
}

/// Create a boxed `KvmForkBackend` (used by `create_backend`).
pub fn create_kvm_fork_backend() -> Box<dyn SandboxBackend> {
    Box::new(KvmForkBackend::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvm::Kvm;
    use crate::test_helpers;
    use crate::test_helpers::test_snapshot;

    // ─── ForkEngine tests ─────────────────────────────────

    #[test]
    fn test_fork_engine_creation() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Skipping test: KVM not available");
                return;
            }
        };

        let snap = test_snapshot();
        let mmap_size = kvm.vcpu_mmap_size().unwrap();
        let engine = ForkEngine::new(kvm, snap, mmap_size);
        assert!(engine.vcpu_mmap_size > 0);
    }

    #[test]
    fn test_fork_basic() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Skipping test: KVM not available");
                return;
            }
        };

        let snap = test_snapshot();
        let mmap_size = kvm.vcpu_mmap_size().unwrap();
        let engine = ForkEngine::new(kvm, snap, mmap_size);

        // Fork a VM
        let forked = engine.fork().expect("Should fork successfully");
        assert!(forked.memory_size > 0);
        assert!(!forked.kvm_run_ptr.is_null());
    }

    #[test]
    fn test_fork_batch() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Skipping test: KVM not available");
                return;
            }
        };

        let snap = test_snapshot();
        let mmap_size = kvm.vcpu_mmap_size().unwrap();
        let engine = ForkEngine::new(kvm, snap, mmap_size);

        let vms = engine.fork_batch(3).expect("Should fork 3 VMs");
        assert_eq!(vms.len(), 3);
    }

    #[test]
    fn test_fork_with_shared_memory() {
        let kvm = match Kvm::new() {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Skipping test: KVM not available");
                return;
            }
        };

        let snap = test_snapshot();
        let mmap_size = kvm.vcpu_mmap_size().unwrap();
        let mut engine = ForkEngine::new(kvm, snap, mmap_size);

        // Create a small shared memory region
        let mut region = crate::shared_mem::SharedMemoryRegion::new_anon(4096)
            .expect("should create anon shared region");

        // Write some data into it
        region.write(0, b"SHARED_DATA").expect("write to shared region");

        // Register it at guest physical address 0x100000
        engine.add_shared_region(region, 0x100000);

        assert_eq!(engine.shared_regions().len(), 1, "should have 1 shared region");

        // Fork should succeed with the shared region injected
        let forked = engine.fork().expect("fork with shared memory should succeed");
        assert!(forked.memory_size > 0);
        assert_eq!(engine.shared_regions()[0].1, 0x100000, "guest_phys should match");
    }

    // ─── SandboxBackend trait tests (Tier 2 lifecycle) ──────────────
    //
    // These test the KvmForkBackend through the SandboxBackend trait,

    #[test]
    fn test_kvm_fork_backend_create() {
        // Verify we can create a boxed backend through the factory function
        let mut backend = create_kvm_fork_backend();
        let _variant = ApiVariant::new("python", "minimal", "base");

        // Exec before init should fail
        let result = backend.exec("print(1)");
        assert!(result.is_err(), "exec without init should fail");
        assert!(
            result.unwrap_err().to_string().contains("not initialised"),
            "error should mention not initialised"
        );
    }

    #[test]
    fn test_kvm_fork_backend_destroy_without_init() {
        // destroy() on a fresh backend should not panic
        let mut backend = KvmForkBackend::new();
        let result = backend.destroy();
        assert!(result.is_ok(), "destroy without init should succeed");
    }

    #[test]
    fn test_kvm_fork_backend_reset_without_init() {
        // reset() on a fresh backend should not panic
        let mut backend = KvmForkBackend::new();
        let result = backend.reset();
        assert!(result.is_ok(), "reset without init should succeed");
    }

    #[test]
    fn test_kvm_fork_backend_init_no_kvm() {
        // If KVM is not available, init should return a sandbox error
        // that includes "KVM init failed"
        let mut backend = KvmForkBackend::new();
        let variant = ApiVariant::new("python", "minimal", "base");
        let result = backend.init(&variant);
        match result {
            Ok(()) => {
                // KVM is available — skip the no-KVM check
                eprintln!("KVM available — init succeeded");
                // Clean up
                let _ = backend.destroy();
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("KVM init failed") || msg.contains("not supported"),
                    "init error should mention KVM or unsupported: got {msg}"
                );
            }
        }
    }

    #[test]
    fn test_kvm_fork_backend_registration() {
        // Verify that register_all_backends includes KvmFork
        // We can't easily check the internal registry, but we can verify
        // the factory function exists and produces a valid boxed backend.
        let backend = create_kvm_fork_backend();
        // The returned value should implement SandboxBackend
        let _: Box<dyn SandboxBackend> = backend;
    }

    #[test]
    fn test_kvm_fork_backend_tier_constant() {
        assert_eq!(
            KvmForkBackend::tier(),
            ExecutionTier::KvmFork,
            "tier() should return KvmFork"
        );
    }

    #[test]
    fn test_kvm_fork_backend_debug() {
        let backend = KvmForkBackend::new();
        let debug_str = format!("{:?}", backend);
        assert!(!debug_str.is_empty(), "Debug should not be empty");
    }

    #[test]
    fn test_kvm_fork_backend_send() {
        // Verify KvmForkBackend implements Send and Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<KvmForkBackend>();
        assert_sync::<KvmForkBackend>();
    }

    #[test]
    fn test_kvm_fork_engine_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ForkEngine>();
        assert_sync::<ForkEngine>();
    }
}
