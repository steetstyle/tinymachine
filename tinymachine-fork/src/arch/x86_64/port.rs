//! x86_64 Port I/O addresses — UART 16550 (COM1), PIC, PIT, PCI config, RTC.
//!
//! These constants define the standard x86 I/O port addresses used in TinyMachine
//! KVM guest emulation. They are x86_64-specific and would need different
//! values (or a different mechanism) for aarch64/riscv64.

// ─── UART 16550 (COM1, ports 0x3F8-0x3FF) ────────────────────────

/// Base port for COM1 (standard x86 serial port)
pub const COM1_BASE: u16 = 0x3F8;

/// COM1 register offsets from base
pub const UART_DATA: u16 = 0x0;       // RBR/THR/DLL (DLAB dependent)
pub const UART_IER: u16 = 0x1;       // Interrupt Enable Register
pub const UART_IIR_FCR: u16 = 0x2;   // Interrupt ID / FIFO Control
pub const UART_LCR: u16 = 0x3;       // Line Control Register
pub const UART_MCR: u16 = 0x4;       // Modem Control Register
pub const UART_LSR: u16 = 0x5;       // Line Status Register
pub const UART_MSR: u16 = 0x6;       // Modem Status Register
pub const UART_SCR: u16 = 0x7;       // Scratch Register

/// Port ranges for KVM I/O exit handling
pub const UART_PORT_START: u16 = COM1_BASE;        // 0x3F8
pub const UART_PORT_END: u16 = COM1_BASE + 8;      // 0x3FF (inclusive)

/// PCI configuration address port (32-bit at 0xCF8)
pub const PCI_CONFIG_ADDR_PORT: u16 = 0xCF8;
/// PCI configuration data port range (32-bit at 0xCFC-0xCFF)
pub const PCI_CONFIG_PORT_START: u16 = 0xCFC;
pub const PCI_CONFIG_PORT_END: u16 = 0xCFF;

// ─── UART register bit constants ─────────────────────────────────

/// Divisor Latch Access Bit (bit 7 of LCR)
pub const UART_DLAB: u8 = 0x80;

/// Line Status Register bits
pub const LSR_THRE: u8 = 0x20;   // Transmitter Holding Register Empty
pub const LSR_TEMT: u8 = 0x40;   // Transmitter Empty
pub const LSR_DR: u8 = 0x01;     // Data Ready

/// Modem Status Register bits
pub const MSR_DCD: u8 = 0x80;
pub const MSR_RI: u8 = 0x40;
pub const MSR_DSR: u8 = 0x20;
pub const MSR_CTS: u8 = 0x10;
pub const MSR_ALL_SET: u8 = MSR_DCD | MSR_RI | MSR_DSR | MSR_CTS;

/// FIFO Control Register bits
pub const FCR_ENABLE: u8 = 0x01;

/// Interrupt Identification Register bits (no interrupt pending)
pub const IIR_NO_INT_PENDING: u8 = 0x01;
pub const IIR_FIFO_ENABLED: u8 = 0xC0;

// ─── PIT (8254, ports 0x40-0x43) ─────────────────────────────────

pub const PIT_DATA0: u16 = 0x40;
pub const PIT_DATA1: u16 = 0x41;
pub const PIT_DATA2: u16 = 0x42;
pub const PIT_COMMAND: u16 = 0x43;

// ─── PIC (8259, ports 0x20-0x21, 0xA0-0xA1) ──────────────────────

pub const PIC_MASTER_CMD: u16 = 0x20;
pub const PIC_MASTER_DATA: u16 = 0x21;
pub const PIC_SLAVE_CMD: u16 = 0xA0;
pub const PIC_SLAVE_DATA: u16 = 0xA1;

// ─── 8237 DMA Controller (master 0x00-0x0F, slave 0xC0-0xDF) ─────

/// Master DMA status register — returns channel terminal count bits
pub const DMA_MASTER_STATUS: u16 = 0x08;
/// Master DMA command register (write)
pub const DMA_MASTER_CMD: u16 = 0x08;
/// Slave DMA (cascade) status register
pub const DMA_SLAVE_STATUS: u16 = 0xD0;

/// Value returned for DMA status reads claiming all channels complete.
/// Lower nibble = terminal count per channel (0-3 for master, 4-7 for slave).
pub const DMA_ALL_TC: u8 = 0x0F;

// ─── PPI (8255, port 0x61) — Programmable Peripheral Interface ────

/// PPI port B — speaker control, memory refresh, NMI status
pub const PPI_PORT_B: u16 = 0x61;
/// PPI refresh bit — VBIOS checks this to confirm memory refresh is running
pub const PPI_REFRESH_BIT: u8 = 0x10;

// ─── 16550 UART Emulation ─────────────────────────────────────────
//
// The Linux 8250 driver probes for a UART by writing to the scratch
// register (COM1_BASE + 7) and reading it back. Without proper emulation,
// the probe fails and ttyS0 is never registered for user-space.
//
// This UART only handles output (THR writes). Input reads (RBR) always
// return 0x00 since there is no host-to-guest serial communication.
// LSR reports THRE=1 and TEMT=1 but DR=0, indicating no incoming data.

/// 16550 UART emulation for KVM port I/O.
///
/// Used by `ForkedVm::run_until_ready()` to handle guest serial port
/// accesses via `KVM_EXIT_IO`. On x86_64, the serial port is at `COM1_BASE`
/// (0x3F8) and registers are accessed at byte offsets 0-7.
///
/// On aarch64, serial is typically PL011 via MMIO (not port I/O),
/// so this emulation is x86_64-specific.
#[derive(Debug)]
pub struct Uart16550 {
    /// Line Control Register — DLAB is bit 7
    lcr: u8,
    /// Scratch Register — used by 8250 driver for probe detection
    scr: u8,
    /// Interrupt Enable Register (valid when DLAB=0)
    ier: u8,
    /// FIFO Control Register (write only)
    fcr: u8,
    /// Modem Control Register
    mcr: u8,
    /// Divisor Latch Low (valid when DLAB=1)
    dll: u8,
    /// Divisor Latch High (valid when DLAB=1)
    dlm: u8,
    /// Buffer for captured serial output
    output_buf: Vec<u8>,
    /// Max chars to capture
    max_capture: usize,
}

impl Uart16550 {
    pub fn new() -> Self {
        Self {
            lcr: 0x03,    // 8N1 default (no parity, 1 stop bit, 8 bits)
            scr: 0x00,
            ier: 0x00,
            fcr: 0x00,
            mcr: 0x00,
            dll: 0x01,    // default divisor = 1
            dlm: 0x00,
            output_buf: Vec::new(),
            max_capture: 2000,
        }
    }

    /// Divisor Latch Access Bit — when set, offset 0/1 access DLL/DLM
    fn dlab(&self) -> bool {
        (self.lcr & UART_DLAB) != 0
    }

    /// Read a byte from a 16550 register at `offset` (0-7 from COM1_BASE).
    ///
    /// Called when the guest executes IN from a serial port.
    /// `offset` is `port - COM1_BASE`.
    pub fn read_reg(&mut self, offset: u16) -> u8 {
        match offset {
            0 => {
                if self.dlab() {
                    self.dll
                } else {
                    // RBR (Receive Buffer Register) — always returns 0x00
                    // since there is no host-to-guest serial data.
                    0x00
                }
            }
            1 => {
                if self.dlab() {
                    self.dlm
                } else {
                    self.ier
                }
            }
            2 => {
                // IIR (Interrupt Identification Register)
                // Bits 7-6: FIFO enabled (0xC0 when FCR[0]=1, else 0x00)
                // Bits 3-1: interrupt ID (000 = no interrupt pending)
                // Bit 0: interrupt pending (1 = no)
                let fifo_bits = if (self.fcr & FCR_ENABLE) != 0 { IIR_FIFO_ENABLED } else { 0x00 };
                // No interrupt pending: IIR = 0x01 (bit 0 = 1 = no interrupt)
                IIR_NO_INT_PENDING | fifo_bits
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => {
                // LSR (Line Status Register)
                // Bit 7: error in RCVR FIFO = 0
                // Bit 6: TEMT (transmitter empty) = 1
                // Bit 5: THRE (transmitter holding register empty) = 1
                // Bit 4: break interrupt = 0
                // Bit 3: framing error = 0
                // Bit 2: parity error = 0
                // Bit 1: overrun error = 0
                // Bit 0: data ready = 0 (no incoming data)
                LSR_THRE | LSR_TEMT  // THRE=1, TEMT=1, DR=0
            }
            6 => {
                // MSR (Modem Status Register)
                MSR_ALL_SET  // DCD|RI|DSR|CTS = all set
            }
            7 => self.scr,
            _ => 0x00,
        }
    }

    /// Write a byte to a 16550 register at `offset` (0-7 from COM1_BASE).
    ///
    /// Called when the guest executes OUT to a serial port.
    /// Returns true if the write was to THR (offset 0, DLAB=0),
    /// indicating a data byte was transmitted.
    /// `offset` is `port - COM1_BASE`.
    pub fn write_reg(&mut self, offset: u16, value: u8) -> bool {
        match offset {
            0 => {
                if self.dlab() {
                    self.dll = value;
                    false
                } else {
                    // THR write — data being transmitted
                    self.output_char(value);
                    true
                }
            }
            1 => {
                if self.dlab() {
                    self.dlm = value;
                } else {
                    self.ier = value;
                }
                false
            }
            2 => {
                self.fcr = value;
                false
            }
            3 => {
                self.lcr = value;
                false
            }
            4 => {
                self.mcr = value;
                false
            }
            7 => {
                self.scr = value;
                false
            }
            _ => false,
        }
    }

    /// Get the captured serial output buffer.
    pub fn output(&self) -> &[u8] {
        &self.output_buf
    }

    fn output_char(&mut self, c: u8) {
        if self.output_buf.len() < self.max_capture {
            self.output_buf.push(c);
        }
    }
}

impl Default for Uart16550 {
    fn default() -> Self {
        Self::new()
    }
}
