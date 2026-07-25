//! x86_64 KVM Exit Handling — port I/O emulation helpers.
//!
//! x86_64 guests use port I/O (`KVM_EXIT_IO`) for serial, PIT, PIC, and
//! PCI config access. These functions provide the emulation for those ports
//! without depending on the UART emulation state machine (which lives in
//! `crate::arch::Uart16550`).
//!
//! On aarch64, there is no port I/O — MMIO (`KVM_EXIT_MMIO`) replaces it.

use crate::arch::port::*;

/// Read I/O port operation info from the `kvm_run` structure.
///
/// Returns `(direction, size, port, count, data_offset)` where:
/// - `direction`: 0 = IN (guest reads), 1 = OUT (guest writes)
/// - `size`: byte count (1, 2, or 4)
/// - `port`: I/O port number
/// - `count`: repetition count (for `rep ins`/`rep outs`)
/// - `data_offset`: byte offset from `kvm_run` base to the data buffer
///
/// # Safety
/// `kvm_run_ptr` must point to a valid, properly sized `kvm_run` mmap region
/// (obtained from `KVM_GET_VCPU_MMAP_SIZE`). Offsets 32-40 are the standard
/// `struct kvm_run` I/O fields per the KVM ABI.
#[inline(always)]
pub unsafe fn read_io_info(kvm_run_ptr: *mut u8) -> (u8, usize, u16, u32, usize) {
    let dir = *((kvm_run_ptr.add(32)) as *const u8);
    let sz = *((kvm_run_ptr.add(33)) as *const u8);
    let prt = *((kvm_run_ptr.add(34)) as *const u16);
    let cnt = *((kvm_run_ptr.add(36)) as *const u32);
    let doff = *((kvm_run_ptr.add(40)) as *const u64);
    (dir, sz as usize, prt, cnt, doff as usize)
}

/// Return the value for a port I/O **IN** (guest reads from port) when no
/// specific emulation is needed beyond default/sentinel responses.
///
/// This handles ports that have simple fixed responses (PCI config = 0xFF
/// for "no device", PIT = 0x00, PIC = 0xFF for "all masked"). For UART
/// ports, delegate to `Uart16550::read` instead.
///
/// Returns `None` if the port is a UART port or otherwise needs stateful
/// handling from the caller's UART emulation.
pub fn default_port_read(port: u16) -> Option<u8> {
    match port {
        // PCI config data ports (0xCFC-0xCFF): no device → return 0xFF
        PCI_CONFIG_PORT_START..=PCI_CONFIG_PORT_END => Some(0xFF),
        // PIT counter ports (0x40-0x42): no in-kernel PIT → return 0x00
        PIT_DATA0..=PIT_DATA2 => Some(0x00),
        // PIC master/slave (0x20-0x21, 0xA0-0xA1): all masked → return 0xFF
        PIC_MASTER_CMD..=PIC_MASTER_DATA | PIC_SLAVE_CMD..=PIC_SLAVE_DATA => Some(0xFF),
        // PIT command port (0x43) and PPI port B (0x61): return 0x00
        PIT_COMMAND | PPI_PORT_B => Some(0x00),
        // UART ports: need stateful emulation, handled by caller
        UART_PORT_START..=UART_PORT_END => None,
        // All other ports: return 0x00
        _ => Some(0x00),
    }
}

/// Check if a port write (OUT) targets the UART THR (Transmitter Holding
/// Register), indicating a data byte was transmitted for serial capture.
///
/// This is a pure port-range check — it does NOT inspect the UART register
/// state (DLAB, etc.). The caller is responsible for proper UART emulation
/// via `Uart16550::write`.
pub fn is_uart_port(port: u16) -> bool {
    matches!(port, UART_PORT_START..=UART_PORT_END)
}
