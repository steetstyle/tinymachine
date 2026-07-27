//! x86_64 KVM register types and ioctl constants.
//!
//! These types mirror the C structs from `<asm/kvm.h>` for x86_64.
//! On aarch64, KVM uses `KVM_SET_ONE_REG` with different register IDs
//! (`KVM_REG_ARM64_*`) instead of per-register-type ioctls.

// ─── Ioctl numbers (x86-specific) ─────────────────────────────────

/// KVM_CREATE_IRQCHIP — creates in-kernel PIC, IOAPIC, LAPIC.
/// NOTE: On Linux 6.x, this does NOT create the PIT (requires KVM_CREATE_PIT2).
pub const KVM_CREATE_IRQCHIP: u64 = 0x0000ae60u64;

/// KVM_CREATE_PIT2 — creates in-kernel PIT with config.
pub const KVM_CREATE_PIT2: u64 = 0x4040ae77u64;

/// KVM_GET_REGS — get x86 general-purpose registers (struct kvm_regs, 144 bytes)
pub const KVM_GET_REGS: u64 = 0x8090ae81u64;

/// KVM_SET_REGS — set x86 general-purpose registers
pub const KVM_SET_REGS: u64 = 0x4090ae82u64;

/// KVM_GET_SREGS — get x86 special registers (segments, CRx, EFER)
pub const KVM_GET_SREGS: u64 = 0x8138ae83u64;

/// KVM_SET_SREGS — set x86 special registers
pub const KVM_SET_SREGS: u64 = 0x4138ae84u64;

/// KVM_SET_CPUID2 — set x86 CPUID leaves
pub const KVM_SET_CPUID2: u64 = 0x4008ae90u64;

/// KVM_GET_SUPPORTED_CPUID — get host-supported x86 CPUID leaves
pub const KVM_GET_SUPPORTED_CPUID: u64 = 0xc008ae05u64;

/// KVM_INTERRUPT — inject a virtual interrupt into an x86 VCPU
pub const KVM_INTERRUPT: u64 = 0x4004ae86u64;

/// KVM_GET_MP_STATE — get x86 VCPU MP state
pub const KVM_GET_MP_STATE: u64 = 0x8004ae98u64;

/// KVM_SET_MP_STATE — set x86 VCPU MP state
pub const KVM_SET_MP_STATE: u64 = 0x4004ae99u64;

/// KVM_GET_XSAVE — get x86 XSAVE state (4096 bytes)
pub const KVM_GET_XSAVE: u64 = 0x9010aea4u64;

/// KVM_SET_XSAVE — set x86 XSAVE state (4096 bytes)
pub const KVM_SET_XSAVE: u64 = 0x5010aea5u64;

/// KVM_GET_XCRS — get x86 XCR registers
pub const KVM_GET_XCRS: u64 = 0x8188aea6u64;

/// KVM_SET_XCRS — set x86 XCR registers
pub const KVM_SET_XCRS: u64 = 0x4188aea7u64;

/// KVM_GET_IRQCHIP — get in-kernel irqchip state (PIC/IOAPIC)
pub const KVM_GET_IRQCHIP: u64 = 0xc208ae62u64;

/// KVM_SET_IRQCHIP — set in-kernel irqchip state
pub const KVM_SET_IRQCHIP: u64 = 0x8208ae63u64;

/// KVM_GET_MSRS — get MSRs from VCPU
pub const KVM_GET_MSRS: u64 = 0xc008ae88u64;
/// KVM_SET_MSRS — set MSRs on VCPU
pub const KVM_SET_MSRS: u64 = 0x4008ae89u64;

/// KVM_SET_TSS_ADDR — set TSS address for VMX
pub const KVM_SET_TSS_ADDR: u64 = 0x0000ae47;

/// KVM_IRQFD — connect eventfd to GSI for interrupt routing
pub const KVM_IRQFD: u64 = 0x4020ae76u64;

/// KVM_SET_GSI_ROUTING — set interrupt routing table
pub const KVM_SET_GSI_ROUTING: u64 = 0x4008AE6A;

/// KVM_CREATE_DEVICE — create a KVM device (e.g., VFIO)
pub const KVM_CREATE_DEVICE: u64 = 0xc00caee0u64;

/// KVM_SET_DEVICE_ATTR — set a device attribute
pub const KVM_SET_DEVICE_ATTR: u64 = 0x4018aee1u64;

/// KVM_DEV_TYPE_VFIO
pub const KVM_DEV_TYPE_VFIO: u32 = 0x04;

/// KVM_DEV_VFIO_GROUP attribute
pub const KVM_DEV_VFIO_GROUP: u32 = 1;
pub const KVM_DEV_VFIO_GROUP_ADD: u64 = 1;
pub const KVM_DEV_VFIO_GROUP_DEL: u64 = 2;

/// KVM_GET_PIT2 — get in-kernel PIT state (struct kvm_pit_state2, 112 bytes)
pub const KVM_GET_PIT2: u64 = 0x8070ae9fu64;

/// KVM_SET_PIT2 — set in-kernel PIT state (struct kvm_pit_state2, 112 bytes)
pub const KVM_SET_PIT2: u64 = 0x4070aea0u64;

/// KVM_IRQ_LINE — assert/deassert an IRQ line (GSI)
/// struct kvm_irq_level { union { __u32 irq; __s32 status; }; __u32 level; } = 8 bytes
pub const KVM_IRQ_LINE: u64 = 0x4008ae61u64;

/// KVM_SIGNAL_MSI — inject an MSI interrupt (bypasses IOAPIC, goes directly to LAPIC)
/// struct kvm_msi { __u32 address_lo, address_hi, data, flags; __u8 devid; __u8 pad[11]; } = 32 bytes
pub const KVM_SIGNAL_MSI: u64 = 0x4020aea5u64;

/// KVM_IRQFD flags
pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
pub const KVM_IRQFD_FLAG_RESAMPLE: u32 = 1 << 1;

/// KVM irqchip IDs
pub const KVM_IRQCHIP_PIC_MASTER: u32 = 0;
pub const KVM_IRQCHIP_PIC_SLAVE: u32 = 1;
pub const KVM_IRQCHIP_IOAPIC: u32 = 2;
pub const KVM_NR_IRQCHIPS: u32 = 3;

/// KVM IRQ routing types
pub const KVM_IRQ_ROUTING_IRQCHIP: u32 = 1;
pub const KVM_IRQ_ROUTING_MSI: u32 = 2;

/// KVM capability numbers
pub const KVM_CAP_IRQ_ROUTING: u32 = 25;
pub const KVM_CAP_READONLY_MEM: u32 = 81;

// ─── KVM exit reasons (arch-specific) ──────────────────────────────
// KVM_EXIT_IO (2) is x86-specific (port I/O). aarch64 uses
// KVM_EXIT_MMIO (6) and KVM_EXIT_HYPERCALL (18) instead.

pub const KVM_EXIT_UNKNOWN: u32 = 0;
pub const KVM_EXIT_EXCEPTION: u32 = 1;
pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
/// KVM_EXIT_MMIO — guest accessed an unmapped MMIO region (value 6).
/// Note: not defined in all KVM uapi headers; 6 is the standard value.
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;

// ─── x86 MP state (from <linux/kvm.h>) ────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpState {
    Runnable = 0,
    Uninitialized = 1,
    InitReceived = 2,
    Halted = 3,
    SipiReceived = 4,
    Startup = 5,
}

impl MpState {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => MpState::Runnable,
            1 => MpState::Uninitialized,
            2 => MpState::InitReceived,
            3 => MpState::Halted,
            4 => MpState::SipiReceived,
            5 => MpState::Startup,
            _ => MpState::Uninitialized,
        }
    }

    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

// ─── C-compatible structs for KVM ioctls (x86_64) ──────────────────

/// C-compatible `struct kvm_pit_channel_state` (24 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KvmPitChannelState {
    pub count: u32,
    pub latched_count: u16,
    pub count_latched: u8,
    pub status_latched: u8,
    pub status: u8,
    pub read_state: u8,
    pub write_state: u8,
    pub write_latch: u8,
    pub rw_mode: u8,
    pub mode: u8,
    pub bcd: u8,
    pub gate: u8,
    pub count_load_time: i64,
}

/// C-compatible `struct kvm_pit_state2` (112 bytes)
#[derive(Debug, Clone)]
#[repr(C)]
pub struct KvmPitState2 {
    pub channels: [KvmPitChannelState; 3],
    pub flags: u32,
    pub reserved: [u32; 9],
}

/// C-compatible `struct kvm_irq_level` (8 bytes)
/// Used by KVM_IRQ_LINE ioctl.
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct KvmIrqLevel {
    pub irq: u32,
    pub level: u32,
}

/// C-compatible `struct kvm_msi` (32 bytes)
/// Used by KVM_SIGNAL_MSI ioctl.
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct KvmMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub flags: u32,
    pub devid: u8,
    pub pad: [u8; 11],
}

/// C-compatible `struct kvm_regs` (144 bytes on x86_64)
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct KvmRegsRaw {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

// SAFETY: KvmRegsRaw is all u64 fields with #[repr(C)], safe to transmute
unsafe impl Pod for KvmRegsRaw {}

/// C-compatible `struct kvm_segment` (24 bytes)
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct KvmSegmentRaw {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

/// C-compatible `struct kvm_dtable` (16 bytes)
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct KvmDtableRaw {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

/// C-compatible `struct kvm_sregs` (312 bytes)
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct KvmSregsRaw {
    pub cs: KvmSegmentRaw,
    pub ds: KvmSegmentRaw,
    pub es: KvmSegmentRaw,
    pub fs: KvmSegmentRaw,
    pub gs: KvmSegmentRaw,
    pub ss: KvmSegmentRaw,
    pub tr: KvmSegmentRaw,
    pub ldt: KvmSegmentRaw,
    pub gdt: KvmDtableRaw,
    pub idt: KvmDtableRaw,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

// SAFETY: KvmSregsRaw is composed of integer types with #[repr(C)], safe to zero-initialize.
unsafe impl Pod for KvmSregsRaw {}

/// C-compatible `struct kvm_irqchip` (520 bytes)
#[derive(Debug, Clone)]
#[repr(C)]
pub struct KvmIrqChipRaw {
    pub chip_id: u32,
    pub pad: u32,
    pub dummy: [u8; 512],
}

impl Default for KvmIrqChipRaw {
    fn default() -> Self {
        Self { chip_id: 0, pad: 0, dummy: [0u8; 512] }
    }
}

/// C-compatible `struct kvm_cpuid_entry2` (40 bytes)
#[derive(Debug, Clone)]
#[repr(C)]
pub struct KvmCpuidEntry2Raw {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

/// C-compatible `struct kvm_cpuid2` header (8 bytes + variable entries)
#[derive(Debug, Clone)]
#[repr(C)]
pub struct KvmCpuid2Raw {
    pub nent: u32,
    pub padding: u32,
}

// ─── IRQ routing structs ───────────────────────────────────────────

/// C-compatible `struct kvm_irq_routing_entry` (48 bytes on x86_64)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KvmIrqRoutingEntryRaw {
    pub gsi: u32,
    pub type_: u32,
    pub flags: u32,
    pub pad: u32,
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub _reserved: [u32; 5],
}

unsafe impl Pod for KvmIrqRoutingEntryRaw {}

/// C-compatible `struct kvm_irqfd` (32 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KvmIrqfd {
    pub fd: u32,
    pub gsi: u32,
    pub flags: u32,
    pub resamplefd: u32,
    pub pad: [u8; 16],
}

/// C-compatible `struct kvm_create_device` (12 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KvmCreateDevice {
    pub type_: u32,
    pub fd: i32,
    pub flags: u32,
}

/// C-compatible `struct kvm_device_attr` (24 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KvmDeviceAttr {
    pub flags: u32,
    pub group: u32,
    pub attr: u64,
    pub addr: u64,
}

/// Marker trait for types that can be safely zero-initialized.
/// # Safety
/// Implementors must be `#[repr(C)]` and contain only integer/float types.
pub unsafe trait Pod: Default + Sized {}

// ─── Compile-time size assertions ──────────────────────────────────

#[cfg(target_os = "linux")]
const _: () = {
    [(); 1][(std::mem::size_of::<KvmRegsRaw>() != 144 && std::mem::size_of::<KvmRegsRaw>() != 184) as usize];
    [(); 1][(std::mem::size_of::<KvmSegmentRaw>() != 24) as usize];
    [(); 1][(std::mem::size_of::<KvmDtableRaw>() != 16) as usize];
    [(); 1][(std::mem::size_of::<KvmSregsRaw>() != 312) as usize];
    [(); 1][(std::mem::size_of::<KvmIrqRoutingEntryRaw>() != 48) as usize];
};
