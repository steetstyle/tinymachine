//! x86_64-specific KVM Vm (VM) ioctl operations.
//!
//! These free functions wrap architecture-specific KVM ioctls that operate
//! on a VM fd. They are extracted from `crate::kvm::Vm` so that
//! architecture-agnostic code can dispatch to the correct implementation.
//!
//! Each function takes `vm_fd: RawFd` as the first parameter (except static
//! helpers that don't need a fd), allowing the `Vm` struct in `kvm.rs` to
//! delegate to these without exposing its internal fd.
//!
//! # Safety
//! All ioctl functions use raw `libc::ioctl` to interact with KVM.
//! Unsafe blocks are documented with `// SAFETY:`.

use std::os::fd::RawFd;

use crate::kvm::{errno_after_ioctl, KvmError, Result};
use crate::arch::kvm_types::*;

// ─── In-kernel irqchip (PIC + IOAPIC + LAPIC) ─────────────────────

/// Create in-kernel interrupt chipset (PIC, IOAPIC, LAPIC, PIT)
///
/// Required for timer interrupts and legacy IRQ delivery. Without this,
/// the guest kernel's `calibrate_delay()` and serial driver hang because
/// no PIT timer interrupts are generated.
///
/// # Errors
/// Returns `KvmError::Ioctl` if creation fails.
pub fn create_irqchip(vm_fd: RawFd) -> Result<()> {
    // SAFETY: vm_fd is a valid VM fd. KVM_CREATE_IRQCHIP takes no argument.
    let ret = unsafe {
        libc::ioctl(
            vm_fd,
            KVM_CREATE_IRQCHIP as libc::c_ulong,
            0,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_CREATE_IRQCHIP".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

/// Create in-kernel PIT (8254) emulation.
///
/// Must be called after `create_irqchip()` to provide PIT timer
/// interrupts to the guest. Without this, PIT IO accesses (0x40-0x43)
/// exit to userspace, and KVM never injects timer interrupts.
///
/// Uses KVM_CREATE_PIT2 with flags=0 (standard timer operation).
///
/// # Errors
/// Returns `KvmError::Ioctl` if creation fails.
pub fn create_pit(vm_fd: RawFd) -> Result<()> {
    // SAFETY: vm_fd is a valid VM fd. KVM_CREATE_PIT2 takes a struct
    // kvm_pit_config: { __u32 flags; __u32 pad[15]; } = 64 bytes.
    // flags=0 is the standard configuration (timer interrupts only).
    let pit_config: [u32; 16] = [0; 16]; // struct kvm_pit_config
    let ret = unsafe {
        libc::ioctl(
            vm_fd,
            KVM_CREATE_PIT2 as libc::c_ulong,
            &pit_config as *const u32 as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_CREATE_PIT2".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

/// Configure the in-kernel PIT channel 0 for periodic timer interrupts.
///
/// Called after `create_pit()` to start the PIT timer when the guest
/// does not program PIT ports (which are intercepted and ignored by the
/// fork I/O handler). Without this, the PIT never fires and the guest
/// gets no timer interrupts, causing HLT to block forever.
///
/// channel 0: counter=11932 (~100 Hz), mode 3 (square wave), gate=enabled.
/// The PIT clock is 1,193,182 Hz; counter = 1193182 / 100 = 11931.82 ≈ 11932.
///
/// # Errors
/// Returns `KvmError::Ioctl` if KVM_SET_PIT2 fails.
pub fn set_pit2(vm_fd: RawFd) -> Result<()> {
    let ch0 = KvmPitChannelState {
        count: 11932,
        latched_count: 0,
        count_latched: 0,
        status_latched: 0,
        status: 0,
        read_state: 0,
        write_state: 3,     // LSB then MSB
        write_latch: 0,
        rw_mode: 3,         // low then high byte
        mode: 3,            // square wave
        bcd: 0,
        gate: 1,
        count_load_time: 0,
    };
    let ch1 = KvmPitChannelState { count: 0, ..ch0 };
    let ch2 = KvmPitChannelState { count: 0, ..ch0 };
    let state = KvmPitState2 {
        channels: [ch0, ch1, ch2],
        flags: 0,
        reserved: [0u32; 9],
    };
    let ret = unsafe {
        libc::ioctl(
            vm_fd,
            KVM_SET_PIT2 as libc::c_ulong,
            &state as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: "KVM_SET_PIT2".into(),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

// ─── Irqchip state save/restore ───────────────────────────────────

/// Save the state of one in-kernel irqchip (PIC master, PIC slave, or IOAPIC)
///
/// `chip_id`: 0=PIC master, 1=PIC slave, 2=IOAPIC
///
/// # Safety
///
/// `chip_id` must be a valid KVM irqchip ID (0-2). The returned buffer
/// contains 520 bytes of C-struct data.
pub unsafe fn get_irqchip(vm_fd: RawFd, chip_id: u32) -> Result<KvmIrqChipRaw> {
    let chip = KvmIrqChipRaw { chip_id, ..Default::default() };
    // SAFETY: vm_fd is a valid VM fd. chip contains the chip_id to query.
    // KVM fills the 512-byte dummy field with the irqchip state.
    let ret = unsafe {
        libc::ioctl(
            vm_fd,
            KVM_GET_IRQCHIP as libc::c_ulong,
            &chip as *const _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: format!("KVM_GET_IRQCHIP(chip_id={})", chip_id),
            errno: errno_after_ioctl(),
        });
    }
    Ok(chip)
}

/// Restore the state of one in-kernel irqchip (PIC master, PIC slave, or IOAPIC)
///
/// `chip_id`: 0=PIC master, 1=PIC slave, 2=IOAPIC
///
/// # Safety
///
/// `chip` must contain valid irqchip state for the given `chip_id`,
/// obtained from a prior `get_irqchip` call on a VM with matching configuration.
pub unsafe fn set_irqchip(vm_fd: RawFd, chip: &KvmIrqChipRaw) -> Result<()> {
    // SAFETY: vm_fd is a valid VM fd. chip contains valid irqchip state.
    let ret = unsafe {
        libc::ioctl(
            vm_fd,
            KVM_SET_IRQCHIP as libc::c_ulong,
            chip as *const _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: format!("KVM_SET_IRQCHIP(chip_id={})", chip.chip_id),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

// ─── GSI routing (IOAPIC + MSI) ───────────────────────────────────

/// Set the interrupt routing table via `KVM_SET_GSI_ROUTING`.
///
/// Replaces the ENTIRE routing table with the provided entries. If you
/// are adding MSI routes without disturbing existing IOAPIC routes, you
/// MUST include all default IOAPIC entries (GSIs 0-23 → IOAPIC pins 0-23).
///
/// # Arguments
/// * `entries` — Slice of `KvmIrqRoutingEntryRaw` specifying the new table.
///
/// # Errors
/// Returns `KvmError::Ioctl` if the kernel rejects the routing table
/// (e.g., invalid GSI, invalid type, or capacity exceeded).
///
/// # Safety
/// `vm_fd` must be a valid KVM VM fd. Entries must be valid
/// (e.g., MSI entries must refer to valid vectors).
#[allow(clippy::manual_slice_size_calculation)] // explicit formula preferred for clarity
pub unsafe fn set_gsi_routing(vm_fd: RawFd, entries: &[KvmIrqRoutingEntryRaw]) -> Result<()> {
    // Header: struct kvm_irq_routing { __u32 nr; __u32 flags; } = 8 bytes
    let header_size = 8usize;
    let entry_size = std::mem::size_of::<KvmIrqRoutingEntryRaw>();
    let total_size = header_size + entries.len() * entry_size;

    let mut buf: Vec<u8> = vec![0u8; total_size];

    // Write header: nr = entries.len(), flags = 0
    // SAFETY: buf has at least header_size bytes, aligned for u32
    unsafe {
        let hdr = buf.as_mut_ptr() as *mut u32;
        *hdr = entries.len() as u32;  // nr
        // flags at offset 4 stays 0 (already zero-initialized)
    }

    // Write entries after the header
    for (i, entry) in entries.iter().enumerate() {
        let offset = header_size + i * entry_size;
        // SAFETY: buf has total_size bytes, offset + entry_size <= total_size
        unsafe {
            let dst = buf.as_mut_ptr().add(offset) as *mut KvmIrqRoutingEntryRaw;
            std::ptr::write(dst, *entry);
        }
    }

    // SAFETY: buf contains a valid kvm_irq_routing header followed by entries.
    // vm_fd is a valid KVM VM fd.
    let ret = unsafe {
        libc::ioctl(
            vm_fd,
            KVM_SET_GSI_ROUTING as libc::c_ulong,
            buf.as_ptr() as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(KvmError::Ioctl {
            context: format!("KVM_SET_GSI_ROUTING(nr={})", entries.len()),
            errno: errno_after_ioctl(),
        });
    }
    Ok(())
}

/// Build a complete GSI routing table with IOAPIC + MSI entries.
///
/// Creates routing entries for:
/// - IOAPIC pins 0-23 (GSIs 0-23) — standard x86 routing after `KVM_CREATE_IRQCHIP`
/// - MSI vectors (starting at `msi_gsi_base`, up to `count` vectors)
///
/// This combines both types into one table because `KVM_SET_GSI_ROUTING`
/// replaces the ENTIRE routing table — partial updates are not supported.
///
/// # Arguments
/// * `msi_gsi_base` — First GSI to use for MSI entries (typically 24,
///   since GSIs 0-23 are reserved for IOAPIC).
/// * `msi_count` — Number of MSI vectors to route (typically 4-8 for GPUs).
/// * `msi_address_lo` — Lower 32 bits of the MSI address.
/// * `msi_address_hi` — Upper 32 bits of the MSI address (0 for x86).
/// * `msi_data_base` — Base MSI data value (vector number) for the first
///   MSI vector. Subsequent vectors get `msi_data_base + i`.
///
/// # Returns
/// A `Vec` of `KvmIrqRoutingEntryRaw` ready to pass to `set_gsi_routing()`.
pub fn build_gsi_routing_table(
    msi_gsi_base: u32,
    msi_count: u32,
    msi_address_lo: u32,
    msi_address_hi: u32,
    msi_data_base: u32,
) -> Vec<KvmIrqRoutingEntryRaw> {
    let mut entries = Vec::with_capacity(24 + msi_count as usize);

    // IOAPIC entries: GSIs 0-23 → IOAPIC pin 0-23
    for gsi in 0..24 {
        entries.push(KvmIrqRoutingEntryRaw {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            flags: 0,
            pad: 0,
            address_lo: KVM_IRQCHIP_IOAPIC, // irqchip_id = IOAPIC
            address_hi: gsi,                  // pin = GSI
            data: 0,
            ..Default::default()              // zero-fills union padding
        });
    }

    // MSI entries
    for i in 0..msi_count {
        let gsi = msi_gsi_base + i;
        entries.push(KvmIrqRoutingEntryRaw {
            gsi,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            pad: 0,
            address_lo: msi_address_lo,
            address_hi: msi_address_hi,
            data: msi_data_base + i,
            ..Default::default()              // zero-fills union padding
        });
    }

    entries
}
