//! Shared test fixtures for TinyMachine fork engine tests.
//!
//! Consolidates the four copies of `test_snapshot()` / inline `Snapshot`
//! creation that were previously duplicated across `fork.rs`, `pool.rs`,
//! `snapshot.rs`, and `template_registry.rs`.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::test_helpers::test_snapshot;
//! let snap = test_snapshot();
//! ```

use crate::snapshot::{CpuState, DescTable, KvmRegs, KvmSregs, Segment, Snapshot};

/// Create a minimal valid `Snapshot` for use in unit tests.
///
/// The snapshot has a 4KiB memory page (NOP sled), realistic x86-64 CPU
/// register state, and metadata fields set to typical values.
///
/// Callers can mutate specific fields after creation if the test needs
/// different data (e.g., `snap.cpu.sregs.gdt = DescTable { .. }`).
pub fn test_snapshot() -> Snapshot {
    Snapshot {
        memory: vec![0x90u8; 4096], // NOP sled
        memory_size: 4096,
        cpu: CpuState {
            regs: KvmRegs {
                rax: 0, rbx: 0, rcx: 0, rdx: 0,
                rsi: 0, rdi: 0, rsp: 0x7c00, rbp: 0,
                r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0,
                rip: 0x7c00, rflags: 2,
            },
            sregs: KvmSregs {
                cs: Segment { base: 0, limit: 0xfffff, selector: 0x10, r#type: 11, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                ds: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                es: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                fs: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                gs: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                ss: Segment { base: 0, limit: 0xfffff, selector: 0x18, r#type: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0 },
                tr: Segment { base: 0, limit: 0xfffff, selector: 0x20, r#type: 11, present: 1, dpl: 0, db: 0, s: 0, l: 0, g: 1, avl: 0, unusable: 0 },
                ldt: Segment { base: 0, limit: 0, selector: 0, r#type: 0, present: 0, dpl: 0, db: 0, s: 0, l: 0, g: 0, avl: 0, unusable: 1 },
                gdt: DescTable { base: 0x7c00, limit: 47 },
                idt: DescTable { base: 0, limit: 0 },
                cr0: 0x60000010, cr2: 0, cr3: 0, cr4: 0, cr8: 0,
                efer: 0, apic_base: 0xfee00000,
            },
            msrs: vec![],
            xcrs: vec![],
        },
        load_addr: 0,
        xsave: None,
        irqchips: None,
        mem_fd: None,
        kernel_version: String::new(),
        kernel_hash: String::new(),
        virtio_net_state: None,
    }
}
