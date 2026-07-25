//! 16550 UART emulation — guest serial I/O
//!
//! Provides communication with the guest via a classic 16550 UART
//! mapped at the standard port 0x3F8 (COM1).
//!
//! In Phase 0, this is minimal: we provide a ring buffer that the
//! guest writes to and the host reads from.

use std::collections::VecDeque;

use thiserror::Error;

/// Errors from serial operations
#[derive(Error, Debug)]
pub enum SerialError {
    #[error("Serial buffer full")]
    BufferFull,
    #[error("No data available")]
    NoData,
}

pub type Result<T> = std::result::Result<T, SerialError>;

/// A minimal 16550 UART emulation
///
/// In a real VM, this would be IO-port trapped by KVM.
/// In Phase 0, we use a simple ring buffer model that the
/// orchestrator can read after KVM_RUN completes.
#[derive(Debug)]
pub struct SerialPort {
    /// Received data from guest (guest → host)
    rx_buffer: VecDeque<u8>,
    /// Data to send to guest (host → guest)
    tx_buffer: VecDeque<u8>,
    /// Max buffer size
    max_size: usize,
    /// Line status register bits
    line_status: u8,
}

impl SerialPort {
    const LSR_DATA_READY: u8 = 0x01;
    const LSR_TX_EMPTY: u8 = 0x20;

    /// Create a new serial port
    pub fn new(max_size: usize) -> Self {
        Self {
            rx_buffer: VecDeque::with_capacity(max_size),
            tx_buffer: VecDeque::with_capacity(max_size),
            max_size,
            line_status: Self::LSR_TX_EMPTY,
        }
    }

    /// Guest writes a byte to the serial port (outb 0x3F8)
    ///
    /// On buffer overflow, drops the oldest byte (circular buffer)
    /// instead of returning BufferFull, which would cause KVM_EXIT_IO errors
    /// and potentially crash the guest.
    pub fn guest_write(&mut self, byte: u8) -> Result<()> {
        if self.rx_buffer.len() >= self.max_size {
            // Circular buffer: drop oldest byte to make room
            let _dropped = self.rx_buffer.pop_front();
        }
        self.rx_buffer.push_back(byte);
        self.line_status |= Self::LSR_DATA_READY;
        Ok(())
    }

    /// Guest reads line status register (inb 0x3FD)
    pub fn guest_read_lsr(&self) -> u8 {
        self.line_status
    }

    /// Guest reads a byte from serial (inb 0x3F8)
    ///
    /// When `tx_buffer` becomes empty after a read, LSR_TX_EMPTY must be
    /// SET (=1 = empty) to signal the guest it can write again.
    pub fn guest_read(&mut self) -> Result<u8> {
        let byte = self.tx_buffer.pop_front().ok_or(SerialError::NoData)?;
        if self.tx_buffer.is_empty() {
            self.line_status |= Self::LSR_TX_EMPTY; // TX buffer empty → set THRE bit
        }
        Ok(byte)
    }

    /// Host reads all received data from guest
    pub fn host_read_all(&mut self) -> Vec<u8> {
        let data: Vec<u8> = self.rx_buffer.drain(..).collect();
        if self.rx_buffer.is_empty() {
            self.line_status &= !Self::LSR_DATA_READY;
        }
        data
    }

    /// Host sends data to guest
    ///
    /// On TX overflow, drops oldest byte (circular buffer) instead
    /// of returning BufferFull. When data is added to tx_buffer,
    /// LSR_TX_EMPTY is cleared (=0 = not empty).
    pub fn host_write(&mut self, data: &[u8]) -> Result<()> {
        for &byte in data {
            if self.tx_buffer.len() >= self.max_size {
                // Circular buffer: drop oldest byte to make room
                let _dropped = self.tx_buffer.pop_front();
            }
            self.tx_buffer.push_back(byte);
        }
        self.line_status &= !Self::LSR_TX_EMPTY; // data available → clear THRE
        Ok(())
    }

    /// Reset the serial port
    pub fn reset(&mut self) {
        self.rx_buffer.clear();
        self.tx_buffer.clear();
        self.line_status = Self::LSR_TX_EMPTY;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_loopback() {
        let mut port = SerialPort::new(1024);

        // Guest writes "hello"
        for b in b"hello\n" {
            port.guest_write(*b).unwrap();
        }

        // Host reads
        let data = port.host_read_all();
        assert_eq!(data, b"hello\n");

        // Host writes response
        port.host_write(b"world\n").unwrap();

        // Guest reads
        let mut out = Vec::new();
        while let Ok(b) = port.guest_read() {
            out.push(b);
        }
        assert_eq!(out, b"world\n");
    }

    #[test]
    fn test_serial_lsr() {
        let mut port = SerialPort::new(1024);
        // Initially TX empty flag should be set
        assert!(port.guest_read_lsr() & SerialPort::LSR_TX_EMPTY != 0);
        // RX not ready
        assert!(port.guest_read_lsr() & SerialPort::LSR_DATA_READY == 0);

        port.guest_write(b'x').unwrap();
        // Now RX data ready
        assert!(port.guest_read_lsr() & SerialPort::LSR_DATA_READY != 0);

        port.host_read_all();
        // RX ready cleared
        assert!(port.guest_read_lsr() & SerialPort::LSR_DATA_READY == 0);
    }
}
