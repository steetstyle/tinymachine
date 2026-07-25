//! x86_64 CPU constants — MSR indices, CR flags, X86_64 paging, XSAVE.
//!
//! These are x86_64-specific constants for CPU feature control, used
//! during KVM CPU state save/restore and CPUID filtering.

// ─── MSR indices (from <asm/msr-index.h>) ─────────────────────────

/// MSR_IA32_SYSENTER_CS
pub const MSR_IA32_SYSENTER_CS: u32 = 0x174;
/// MSR_IA32_SYSENTER_ESP
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
/// MSR_IA32_SYSENTER_EIP
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
/// MSR_STAR (IA32_STAR) — syscall CS/SS targets
pub const MSR_STAR: u32 = 0xC0000081;
/// MSR_LSTAR (IA32_LSTAR) — syscall entry RIP
pub const MSR_LSTAR: u32 = 0xC0000082;
/// MSR_CSTAR (IA32_CSTAR) — syscall entry RIP (compat)
pub const MSR_CSTAR: u32 = 0xC0000083;
/// MSR_SYSCALL_MASK (IA32_FMASK) — syscall RFLAGS mask
pub const MSR_SYSCALL_MASK: u32 = 0xC0000084;
/// MSR_GS_BASE — GS segment base
pub const MSR_GS_BASE: u32 = 0xC0000101;
/// MSR_KERNEL_GS_BASE — kernel GS base (swapgs target)
pub const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;
/// MSR_IA32_TSC — timestamp counter
pub const MSR_IA32_TSC: u32 = 0x10;
/// MSR_IA32_MISC_ENABLE — misc feature enable
pub const MSR_IA32_MISC_ENABLE: u32 = 0x1A0;
/// MSR_IA32_CR_PAT — page attribute table
pub const MSR_IA32_CR_PAT: u32 = 0x277;

/// The MSRs critical for x86_64 Linux syscall and execution state.
pub const CRITICAL_MSRS: &[u32] = &[
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_STAR,
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_SYSCALL_MASK,
    MSR_GS_BASE,
    MSR_KERNEL_GS_BASE,
    MSR_IA32_TSC,
    MSR_IA32_MISC_ENABLE,
    MSR_IA32_CR_PAT,
];

// ─── CR flags ──────────────────────────────────────────────────────

/// CR0: Protection Enable
pub const CR0_PE: u64 = 1 << 0;
/// CR0: Monitor Coprocessor
pub const CR0_MP: u64 = 1 << 1;
/// CR0: Emulation
pub const CR0_EM: u64 = 1 << 2;
/// CR0: Task Switched
pub const CR0_TS: u64 = 1 << 3;
/// CR0: Extension Type
pub const CR0_ET: u64 = 1 << 4;
/// CR0: Numeric Error
pub const CR0_NE: u64 = 1 << 5;
/// CR0: Write Protect
pub const CR0_WP: u64 = 1 << 16;
/// CR0: Alignment Mask
pub const CR0_AM: u64 = 1 << 18;
/// CR0: Not Write-through
pub const CR0_NW: u64 = 1 << 29;
/// CR0: Cache Disable
pub const CR0_CD: u64 = 1 << 30;
/// CR0: Paging
pub const CR0_PG: u64 = 1 << 31;

/// Combined CR0 for long mode (CD|NW|PG|WP|NE|ET|MP|PE)
pub const CR0_LONG_MODE: u64 = CR0_CD | CR0_NW | CR0_PG | CR0_WP | CR0_NE | CR0_ET | CR0_MP | CR0_PE;

/// CR4: Page Address Extensions (PAE)
pub const CR4_PAE: u64 = 1 << 5;

/// EFER: Long Mode Enable
pub const EFER_LME: u64 = 0x00000100;
/// EFER: Long Mode Active
pub const EFER_LMA: u64 = 0x00000400;
/// EFER combined: LME | LMA
pub const EFER_LONG_MODE: u64 = EFER_LME | EFER_LMA;

// ─── GDT descriptors ──────────────────────────────────────────────

/// Null segment descriptor (8 bytes of zeros)
pub const GDT_NULL: u64 = 0x0000000000000000;

/// 64-bit code segment descriptor (long mode)
/// Type=0xB (code, execute/read, accessed), S=1, DPL=0, P=1,
/// L=1, D=0, G=1. Limit=0xFFFFF (full 4GB, ignored in long mode).
pub const GDT_CODE: u64 = 0x00AF9B000000FFFF;

/// 64-bit data segment descriptor (long mode compatible)
/// Type=3 (data, read/write, accessed), S=1, DPL=0, P=1,
/// L=0, D=0, G=1. Limit=0xFFFFF (full 4GB).
pub const GDT_DATA: u64 = 0x008F93000000FFFF;

/// GDT descriptor indices
pub const GDT_NULL_IDX: u8 = 0;
pub const GDT_CODE_IDX: u8 = 1;
pub const GDT_DATA_IDX: u8 = 2;

/// GDT selectors (index × 8)
pub const GDT_CODE_SEL: u16 = 0x08;  // index 1
pub const GDT_DATA_SEL: u16 = 0x10;  // index 2

/// GDT limit (3 descriptors × 8 bytes - 1)
pub const GDT_LIMIT: u16 = 23;

// ─── XSAVE constants ──────────────────────────────────────────────

/// XSAVE area size in bytes (as used by KVM_GET_XSAVE / KVM_SET_XSAVE)
pub const XSAVE_SIZE: usize = 4096;

/// XCR0 value for x87 | SSE | AVX (fpu | sse | avx)
pub const XCR0_X87_SSE_AVX: u64 = 0x207;

/// XSAVE legacy region size (512 bytes for x87 + SSE)
pub const XSAVE_LEGACY_SIZE: usize = 512;

/// CPUID feature bits to filter for snapshot compatibility
pub const CPUID_FILTER_BITS: &[(u32, u32, u32, u32)] = &[
    // (function, index, register_bit_offset, bit)
    // CET_SS: EAX=7, ECX=0, ECX[11]
    (7, 0, 0x0b, 0x08),  // ECX[11] = 1 << 11
    // WAITPKG: EAX=7, ECX=0, ECX[5]
    (7, 0, 0x05, 0x20),  // ECX[5] = 1 << 5
];

// ─── Page table constants ──────────────────────────────────────────

/// Page table entry: present
pub const PT_PRESENT: u64 = 1 << 0;
/// Page table entry: read/write
pub const PT_RW: u64 = 1 << 1;
/// Page table entry: page size (PS=1 for 2MB/1GB pages)
pub const PT_PS: u64 = 1 << 7;
/// Page table entry: global page
pub const PT_GLOBAL: u64 = 1 << 8;
/// Page table entry: no execute
pub const PT_NX: u64 = 1 << 63;

/// Page table address mask (bits 12-51)
pub const PT_ADDR_MASK: u64 = 0x0000FFFFFFFFF000;

// ─── Audit architecture (for seccomp-bpf) ───────────────────────────

/// seccomp audit architecture value for x86_64 (aarch64 = 0xc00000b7)
pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
