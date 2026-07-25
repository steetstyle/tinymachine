//! aarch64 Port I/O — PL011 UART stub.
//!
//! On aarch64, serial is typically a PL011 UART accessed via MMIO
//! (not x86 port I/O). The UART16550 emulation used for x86 KVM_EXIT_IO
//! handling is not needed.
//!
//! # Stub
//! This module provides a minimal `Uart16550` type that compiles but
//! does nothing. When implementing actual aarch64 support, replace
//! this with a PL011 MMIO emulation.

/// STUB: aarch64 uses PL011 MMIO, not 16550 port I/O.
/// This stub exists only to satisfy type imports in architecture-neutral code.
#[derive(Debug)]
pub struct Uart16550;

impl Uart16550 {
    /// Create a new UART stub.
    pub fn new() -> Self {
        Self
    }

    /// STUB: read from a 16550 register offset — always returns 0.
    pub fn read_reg(&mut self, _offset: u16) -> u8 {
        0
    }

    /// STUB: write to a 16550 register offset — no-op, returns false.
    pub fn write_reg(&mut self, _offset: u16, _value: u8) -> bool {
        false
    }

    /// STUB: captured serial output — always empty.
    pub fn output(&self) -> &[u8] {
        &[]
    }
}

impl Default for Uart16550 {
    fn default() -> Self {
        Self
    }
}
