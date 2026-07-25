//! Synthetic PCIe Root Port for VFIO GPU passthrough.
//!
//! NVIDIA's `nvidia.ko` driver requires the GPU to be behind a PCIe Root Port
//! on the guest PCI bus. Without it, `pci_find_pcie_root_port()` returns NULL
//! and the driver skips all RM (Resource Manager) PCIe initialization, causing
//! CUDA to fail with "Unknown PCIe speed."
//!
//! This module provides a software-emulated PCIe Root Port at BDF `00:01.0`
//! with a Type 1 (bridge) header, Power Management capability, and PCI Express
//! capability (with Root Port type). The VFIO GPU is placed on the secondary
//! bus (bus 1) at BDF `01:00.0`.
//!
//! # Topology
//!
//! ```text
//! Bus 0:
//!   [00:00.0] Host Bridge         — Type 0, class=0x060000
//!   [00:01.0] PCIe Root Port      — Type 1 BRIDGE, class=0x060400
//!     Primary bus = 0, Secondary bus = 1, Subordinate bus = 1
//!
//! Bus 1 (behind root port):
//!   [01:00.0] VFIO GPU            — Type 0 endpoint (forwarded to VFIO)
//! ```
//!
//! # PCIe Capabilities Exposed
//!
//! | Capability | Offset | Purpose |
//! |------------|--------|---------|
//! | Power Management | 0x40 | Required for all PCIe devices |
//! | PCI Express | 0x48 | Root Port type, Link Status (Gen3 x16), LTR |
//!
//! Extended capabilities (AER at 0x100, ACS at 0x160) are NOT implemented
//! because the 0xCF8/0xCFC config mechanism only accesses the first 256 bytes.
//! `nvidia.ko` degrades gracefully without AER/ACS on the root port.

/// Full PCI config space size (256 bytes, standard PCI config)
const CONFIG_SPACE_SIZE: usize = 256;

/// Synthetic PCIe Root Port at BDF 00:01.0
///
/// Emulates a Type 1 PCI-to-PCI bridge with:
/// - Power Management capability (cap ID 0x01)
/// - PCI Express capability, Root Port type (cap ID 0x10)
///
/// The config space is stored as a 256-byte array. Reads return pre-defined
/// values; writes to RW fields (Command, Bridge Control, bus numbers) update
/// the array; writes to RO fields (capabilities, device ID) are silently ignored.
#[derive(Debug, Clone)]
pub struct PcieRootPort {
    /// Primary bus number (bus upstream of this bridge)
    pub primary_bus: u8,
    /// Secondary bus number (bus directly downstream)
    pub secondary_bus: u8,
    /// Subordinate bus number (farthest bus downstream)
    pub subordinate_bus: u8,
    /// Raw PCI config space (256 bytes for Type 1 header + capabilities)
    config: [u8; CONFIG_SPACE_SIZE],
}

impl PcieRootPort {
    /// Create a new PCIe Root Port with default configuration.
    ///
    /// The config space is initialized with the standard Type 1 bridge header
    /// and capabilities. Bus numbers default to primary=0, secondary=1,
    /// subordinate=1.
    pub fn new() -> Self {
        let mut rp = Self {
            primary_bus: 0,
            secondary_bus: 1,
            subordinate_bus: 1,
            config: [0u8; CONFIG_SPACE_SIZE],
        };
        rp.init_config();
        rp
    }

    /// Initialize the 256-byte config space with the Type 1 bridge template.
    fn init_config(&mut self) {
        let c = &mut self.config;

        // ── Type 1 Header (offsets 0x00–0x3F) ──

        // 0x00-0x01: Vendor ID (Red Hat 0x1b36)
        c[0x00] = 0x36;
        c[0x01] = 0x1b;
        // 0x02-0x03: Device ID (QEMU PCIe Root Port 0x000c)
        c[0x02] = 0x0c;
        c[0x03] = 0x00;
        // 0x04-0x05: Command (I/O + Memory + Bus Master = 0x0007)
        c[0x04] = 0x07;
        c[0x05] = 0x00;
        // 0x06-0x07: Status (Capabilities list present = 0x0010)
        c[0x06] = 0x10;
        c[0x07] = 0x00;
        // 0x08: Revision ID
        c[0x08] = 0x00;
        // 0x09-0x0B: Class Code (0x060400 = PCI-to-PCI bridge)
        c[0x09] = 0x04;
        c[0x0a] = 0x06;
        c[0x0b] = 0x00;
        // 0x0C: Cache Line Size (64 bytes)
        c[0x0c] = 0x10;
        // 0x0D: Latency Timer
        c[0x0d] = 0x00;
        // 0x0E: Header Type = 0x01 (Type 1 bridge — CRITICAL)
        c[0x0e] = 0x01;
        // 0x0F: BIST
        c[0x0f] = 0x00;

        // 0x10-0x17: BAR0, BAR1 (no bridge MMIO)
        // Already zero

        // 0x18: Primary Bus Number = 0
        c[0x18] = self.primary_bus;
        // 0x19: Secondary Bus Number = 1
        c[0x19] = self.secondary_bus;
        // 0x1A: Subordinate Bus Number = 1
        c[0x1a] = self.subordinate_bus;
        // 0x1B: Secondary Latency Timer
        c[0x1b] = 0x00;

        // 0x1C: I/O Base (0xF0 = disabled)
        c[0x1c] = 0xf0;
        // 0x1D: I/O Limit (0x00 = disabled)
        c[0x1d] = 0x00;
        // 0x1E-0x1F: Secondary Status
        c[0x1e] = 0x00;
        c[0x1f] = 0x00;

        // 0x20-0x21: Memory Base (forward all non-prefetchable: base=0x0000)
        c[0x20] = 0x00;
        c[0x21] = 0x00;
        // 0x22-0x23: Memory Limit (forward all: limit=0xFFFF)
        c[0x22] = 0xff;
        c[0x23] = 0xff;

        // 0x24-0x25: Prefetchable Memory Base 32-bit (disabled = 0x0001)
        c[0x24] = 0x01;
        c[0x25] = 0x00;
        // 0x26-0x27: Prefetchable Memory Limit 32-bit (disabled = 0x0000)
        c[0x26] = 0x00;
        c[0x27] = 0x00;

        // 0x28-0x2B: Prefetchable Base Upper 32 (0)
        // Already zero
        // 0x2C-0x2F: Prefetchable Limit Upper 32 (at 4GB = 0x00000001)
        c[0x2c] = 0x01;
        c[0x2d] = 0x00;
        c[0x2e] = 0x00;
        c[0x2f] = 0x00;

        // 0x30-0x31: I/O Base Upper 16 (0)
        // Already zero
        // 0x32-0x33: I/O Limit Upper 16 (0)
        // Already zero

        // 0x34: Capabilities Pointer → points to PM cap at offset 0x40
        c[0x34] = 0x40;
        // 0x35-0x37: Reserved
        // Already zero

        // 0x38-0x3B: Expansion ROM Base Address (disabled)
        // Already zero

        // 0x3C: Interrupt Line
        c[0x3c] = 0x00;
        // 0x3D: Interrupt Pin (root port doesn't use INTx)
        c[0x3d] = 0x00;
        // 0x3E-0x3F: Bridge Control
        c[0x3e] = 0x00;
        c[0x3f] = 0x00;

        // ── Capabilities ──

        // ── Power Management Capability (cap ID 0x01) at offset 0x40 ──
        // Total size: 8 bytes (0x40-0x47)

        // 0x40: Capability ID = 0x01 (PM)
        c[0x40] = 0x01;
        // 0x41: Next Capability Pointer → 0x48 (PCIe cap)
        c[0x41] = 0x48;
        // 0x42-0x43: PMC (Power Management Capabilities)
        //   Version = 1 (bits 2:0), No PME (bit 15), No D1/D2 (bits 3,4)
        c[0x42] = 0x02;
        c[0x43] = 0x00;
        // 0x44-0x45: PMCSR (Power Management Control/Status)
        //   PowerState = D0 (bits 1:0 = 0b00)
        c[0x44] = 0x00;
        c[0x45] = 0x00;
        // 0x46: Bridge Extensions
        c[0x46] = 0x00;
        // 0x47: Data
        c[0x47] = 0x00;

        // ── PCI Express Capability (cap ID 0x10) at offset 0x48 ──
        // Total size: 52 bytes (0x48-0x7B)

        // 0x48: Capability ID = 0x10 (PCI Express)
        c[0x48] = 0x10;
        // 0x49: Next Capability Pointer → 0x00 (end of list)
        c[0x49] = 0x00;
        // 0x4A-0x4B: PCI Express Capabilities Register
        //   Cap version = 2 (bits 19:16 = 0x2)
        //   Device/Port Type = Root Port (bits 23:20 = 0x4)
        //   Slot Implemented = 0 (bit 24)
        c[0x4a] = 0x42;
        c[0x4b] = 0x00;
        // 0x4C-0x4F: Device Capabilities
        //   128-byte max payload (bits 4:0 = 0), extended tags (bit 5)
        //   L0s/L1 supported (bits 12:10)
        c[0x4c] = 0x00;
        c[0x4d] = 0x80;
        c[0x4e] = 0x00;
        c[0x4f] = 0x00;
        // 0x50-0x51: Device Control
        c[0x50] = 0x00;
        c[0x51] = 0x00;
        // 0x52-0x53: Device Status
        //   Transactions Pending (bit 4 = 1)
        c[0x52] = 0x10;
        c[0x53] = 0x00;
        // 0x54-0x57: Link Capabilities
        //   Max Link Speed = Gen3 (bits 3:0 = 0x3)
        //   Max Link Width = x16 (bits 9:4 = 0x10)
        //   ASPM support = L0s+L1 (bits 11:10 = 0x3)
        //   L1 exit latency = 8μs (bits 17:15 = 0x3)
        //   Port number = 1 (bits 31:24 = 0x01)
        c[0x54] = 0xc3;
        c[0x55] = 0xee;
        c[0x56] = 0x04;
        c[0x57] = 0x00;
        // 0x58-0x59: Link Control (ASPM disabled)
        c[0x58] = 0x00;
        c[0x59] = 0x00;
        // 0x5A-0x5B: Link Status (CRITICAL — nvidia.ko reads this)
        //   Current Link Speed = Gen3 (bits 3:0 = 0x3)
        //   Negotiated Link Width = x16 (bits 9:4 = 0x10)
        //   Link Training = 0 (bit 11 = 0)
        //   Slot Clock Configuration = 1 (bit 12 = 1)
        //   Data Link Layer Link Active = 1 (bit 13 = 1)
        //   Value: 0x3103 = b0011_0001_0000_0011
        //   Bits 3:0 = 3 (Gen3), Bits 9:4 = 010000 (x16), Bit 12 = 1 (Slot Clock), Bit 13 = 1 (Link Active)
        c[0x5a] = 0x03;
        c[0x5b] = 0x31;
        // 0x5C-0x5F: Slot Capabilities
        //   Hot-Plug capable (bit 6)
        c[0x5c] = 0x40;
        c[0x5d] = 0x00;
        c[0x5e] = 0x00;
        c[0x5f] = 0x00;
        // 0x60-0x61: Slot Control
        c[0x60] = 0x00;
        c[0x61] = 0x00;
        // 0x62-0x63: Slot Status
        c[0x62] = 0x00;
        c[0x63] = 0x00;
        // 0x64-0x65: Root Control
        c[0x64] = 0x00;
        c[0x65] = 0x00;
        // 0x66-0x67: Root Capabilities
        c[0x66] = 0x00;
        c[0x67] = 0x00;
        // 0x68-0x6B: Root Status
        c[0x68] = 0x00;
        c[0x69] = 0x00;
        c[0x6a] = 0x00;
        c[0x6b] = 0x00;
        // 0x6C-0x6F: Device Capabilities 2
        //   LTR Mechanism Supported (bit 5 = 1)
        //   TPH Completer Supported (bit 20 = 1)
        //   OBFF Supported (bit 21 = 1)
        c[0x6c] = 0x20;
        c[0x6d] = 0x00;
        c[0x6e] = 0x1c;
        c[0x6f] = 0x00;
        // 0x70-0x71: Device Control 2
        c[0x70] = 0x00;
        c[0x71] = 0x00;
        // 0x72-0x73: Device Status 2
        c[0x72] = 0x00;
        c[0x73] = 0x00;
        // 0x74-0x77: Link Capabilities 2
        //   Supported Link Speeds Vector = Gen1-5 (bits 7:0 = 0x1F)
        //   Max Link Width = x16 (bits 14:8 = 0x10)
        //   Crosslink disabled (bit 15 = 0)
        //   Supported Egress Clock = 0
            c[0x74] = 0xc3;
            c[0x75] = 0xcf;
            c[0x76] = 0x07;
            c[0x77] = 0x00;
            // 0x78-0x79: Link Control 2
            //   Target Link Speed = Gen3 (bits 3:0 = 0x3)
            c[0x78] = 0x03;
            c[0x79] = 0x00;
            // 0x7A-0x7B: Link Status 2
            //   Current De-emphasis Level (bit 0)
            //   Equalization Complete (bit 1)
            //   Current Link Speed = Gen3 (bits 5:4 = 0x3)
            c[0x7a] = 0x03;
            c[0x7b] = 0x00;
        // 0x7C-0xFF: Reserved (already zero)
    }

    /// Read `size` bytes from config space at `reg_offset`.
    ///
    /// `reg_offset` is the register offset (0-255). `size` is 1, 2, or 4.
    /// Returns the value in the least significant bytes.
    ///
    /// For register offsets that are supposed to be RW (Command, Bridge Control,
    /// bus numbers), we return the current value which may have been modified
    /// by a prior write. For RO registers (capabilities, vendor/device ID),
    /// we return the init-time value.
    pub fn config_read(&self, reg_offset: u16, size: usize) -> u32 {
        if (reg_offset as usize) >= CONFIG_SPACE_SIZE {
            return 0xFFFFFFFF;
        }
        let offset = reg_offset as usize;
        let size = size.min(4);
        let end = (offset + size).min(CONFIG_SPACE_SIZE);

        let mut val: u32 = 0;
        for i in offset..end {
            val |= (self.config[i] as u32) << ((i - offset) * 8);
        }
        val
    }

    /// Write `val` (low `size` bytes) to config space at `reg_offset`.
    ///
    /// Writes to RO registers (capabilities, device ID, class code, etc.) are
    /// silently ignored. Writes to RW registers (Command, Bridge Control,
    /// bus numbers) update the internal state.
    ///
    /// Returns true if the write was accepted (RW register), false if ignored.
    pub fn config_write(&mut self, reg_offset: u16, size: usize, val: u32) -> bool {
        if (reg_offset as usize) >= CONFIG_SPACE_SIZE || size == 0 {
            return false;
        }

        // Masks of writable register offsets (RW fields in Type 1 header).
        // All other offsets are RO or reserved.
        let is_rw = match reg_offset {
            // Command register (0x04-0x05) — RW
            0x04 | 0x05 => true,
            // Cache Line Size (0x0C)
            0x0C => true,
            // Primary Bus Number (0x18)
            0x18 => {
                self.primary_bus = val as u8;
                self.config[0x18] = self.primary_bus;
                return true;
            }
            // Secondary Bus Number (0x19)
            0x19 => {
                self.secondary_bus = val as u8;
                self.config[0x19] = self.secondary_bus;
                return true;
            }
            // Subordinate Bus Number (0x1A)
            0x1A => {
                self.subordinate_bus = val as u8;
                self.config[0x1A] = self.subordinate_bus;
                return true;
            }
            // Secondary Latency Timer (0x1B)
            0x1B => true,
            // I/O Base, I/O Limit (0x1C-0x1D)
            0x1C | 0x1D => true,
            // Secondary Status (0x1E-0x1F) — some bits RW
            0x1E | 0x1F => true,
            // Memory Base (0x20-0x21)
            0x20 | 0x21 => true,
            // Memory Limit (0x22-0x23)
            0x22 | 0x23 => true,
            // Prefetchable Base (0x24-0x25)
            0x24 | 0x25 => true,
            // Prefetchable Limit (0x26-0x27)
            0x26 | 0x27 => true,
            // Prefetchable Base Upper (0x28-0x2B)
            0x28 | 0x29 | 0x2A | 0x2B => true,
            // Prefetchable Limit Upper (0x2C-0x2F)
            0x2C | 0x2D | 0x2E | 0x2F => true,
            // I/O Base/Limit Upper (0x30-0x33)
            0x30 | 0x31 | 0x32 | 0x33 => true,
            // Expansion ROM (0x38-0x3B)
            0x38 | 0x39 | 0x3A | 0x3B => true,
            // Interrupt Line (0x3C)
            0x3C => true,
            // Bridge Control (0x3E-0x3F)
            0x3E | 0x3F => true,
            // PMCSR (0x44-0x45) — power state is RW
            0x44 | 0x45 => true,
            // Device Control (0x50-0x51) — RW
            0x50 | 0x51 => true,
            // Link Control (0x58-0x59) — RW (ASPM control)
            0x58 | 0x59 => true,
            // Slot Control (0x60-0x61) — RW
            0x60 | 0x61 => true,
            // Root Control (0x64-0x65) — RW
            0x64 | 0x65 => true,
            // Device Control 2 (0x70-0x71) — RW
            0x70 | 0x71 => true,
            // Link Control 2 (0x78-0x79) — RW
            0x78 | 0x79 => true,
            _ => false,
        };

        if is_rw {
            let offset = reg_offset as usize;
            let size = size.min(4);
            let end = (offset + size).min(CONFIG_SPACE_SIZE);
            for i in offset..end {
                self.config[i] = ((val >> ((i - offset) * 8)) & 0xFF) as u8;
            }
            true
        } else {
            false
        }
    }

    /// Helper to get the cached bus number values (in case guest modified them).
    pub fn bus_numbers(&self) -> (u8, u8, u8) {
        (self.primary_bus, self.secondary_bus, self.subordinate_bus)
    }
}

impl Default for PcieRootPort {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_port_vendor_device_id() {
        let rp = PcieRootPort::new();
        // Vendor ID at offset 0 (2 bytes)
        assert_eq!(rp.config_read(0, 2), 0x1b36);
        // Device ID at offset 2 (2 bytes)
        assert_eq!(rp.config_read(2, 2), 0x000c);
        // Combined read at offset 0 (4 bytes)
        assert_eq!(rp.config_read(0, 4), 0x000c1b36);
    }

    #[test]
    fn test_root_port_class_code() {
        let rp = PcieRootPort::new();
        // Class code at offset 0x08 (3 bytes)
        assert_eq!(rp.config_read(0x08, 3), 0x060400);
    }

    #[test]
    fn test_root_port_header_type() {
        let rp = PcieRootPort::new();
        // Header type at offset 0x0E (1 byte) — must be 0x01 for Type 1 bridge
        assert_eq!(rp.config_read(0x0E, 1), 0x01);
    }

    #[test]
    fn test_root_port_bus_numbers() {
        let rp = PcieRootPort::new();
        // Primary bus at 0x18
        assert_eq!(rp.config_read(0x18, 1), 0x00);
        // Secondary bus at 0x19
        assert_eq!(rp.config_read(0x19, 1), 0x01);
        // Subordinate bus at 0x1A
        assert_eq!(rp.config_read(0x1A, 1), 0x01);
    }

    #[test]
    fn test_root_port_pcie_cap_id() {
        let rp = PcieRootPort::new();
        // PCIe capability ID at 0x48 (1 byte) — must be 0x10
        assert_eq!(rp.config_read(0x48, 1), 0x10);
        // Next cap pointer at 0x49 — should be 0x00 (end of list)
        assert_eq!(rp.config_read(0x49, 1), 0x00);
    }

    #[test]
    fn test_root_port_pcie_type() {
        let rp = PcieRootPort::new();
        // PCIe Capabilities Register at 0x4A (2 bytes)
        // Bits 23:20 = Device/Port Type = 0x4 (Root Port)
        let cap_reg = rp.config_read(0x4A, 2);
        let port_type = (cap_reg >> 4) & 0xF;
        assert_eq!(port_type, 0x4, "PCIe port type must be Root Port (0x4)");
    }

    #[test]
    fn test_root_port_link_status() {
        let rp = PcieRootPort::new();
        // Link Status at 0x5A (2 bytes)
        let link_sta = rp.config_read(0x5A, 2);
        let speed = link_sta & 0xF;
        let width = (link_sta >> 4) & 0x3F;
        assert_eq!(speed, 0x3, "Link speed must report Gen3");
        assert_eq!(width, 0x10, "Link width must report x16");
    }

    #[test]
    fn test_root_port_ltr_support() {
        let rp = PcieRootPort::new();
        // Device Capabilities 2 at 0x6C (4 bytes)
        let dev_cap2 = rp.config_read(0x6C, 4);
        assert!(dev_cap2 & (1 << 5) != 0, "LTR Mechanism Supported bit must be set");
    }

    #[test]
    fn test_root_port_write_bus_numbers() {
        let mut rp = PcieRootPort::new();
        // Guest writes secondary bus = 2
        assert!(rp.config_write(0x19, 1, 2));
        assert_eq!(rp.config_read(0x19, 1), 2);
        assert_eq!(rp.secondary_bus, 2);

        // Guest writes subordinate bus = 5
        assert!(rp.config_write(0x1A, 1, 5));
        assert_eq!(rp.config_read(0x1A, 1), 5);
        assert_eq!(rp.subordinate_bus, 5);

        // Guest writes primary bus = 0
        assert!(rp.config_write(0x18, 1, 0));
        assert_eq!(rp.config_read(0x18, 1), 0);
    }

    #[test]
    fn test_root_port_ro_registers_ignored() {
        let mut rp = PcieRootPort::new();
        // Vendor ID is RO — write should be ignored
        assert!(!rp.config_write(0x00, 2, 0xffff));
        assert_eq!(rp.config_read(0x00, 2), 0x1b36);

        // Class code is RO — write should be ignored
        assert!(!rp.config_write(0x08, 3, 0x000000));
        assert_eq!(rp.config_read(0x08, 3), 0x060400);

        // Header Type is RO
        assert!(!rp.config_write(0x0E, 1, 0x00));
        assert_eq!(rp.config_read(0x0E, 1), 0x01);
    }

    #[test]
    fn test_root_port_write_command() {
        let mut rp = PcieRootPort::new();
        // Command register is RW
        assert!(rp.config_write(0x04, 2, 0x0005)); // I/O + Memory, no Bus Master
        assert_eq!(rp.config_read(0x04, 2), 0x0005);
    }

    #[test]
    fn test_root_port_write_bridge_control() {
        let mut rp = PcieRootPort::new();
        // Bridge Control at 0x3E is RW
        assert!(rp.config_write(0x3E, 2, 0x0001)); // Parity Error Response Enable
        assert_eq!(rp.config_read(0x3E, 2), 0x0001);
    }

    #[test]
    fn test_root_port_pm_cap() {
        let rp = PcieRootPort::new();
        // PM capability at 0x40
        assert_eq!(rp.config_read(0x40, 1), 0x01, "PM cap ID");
        // Next cap at 0x41 should point to PCIe cap at 0x48
        assert_eq!(rp.config_read(0x41, 1), 0x48, "PM next cap pointer");
        // PMCSR at 0x44 — D0 state (0)
        assert_eq!(rp.config_read(0x44, 2), 0x0000);
    }

    #[test]
    fn test_root_port_default_constructor() {
        let rp: PcieRootPort = Default::default();
        assert_eq!(rp.config_read(0x00, 2), 0x1b36);
        assert_eq!(rp.config_read(0x0E, 1), 0x01);
    }
}
