use tinymachine_fork::seccomp;
use tinymachine_api::sandbox::BackendType;

/// Test that `seccomp::install(BackendType::KvmFork)` works correctly.
/// If write is blocked after install, this test will panic (eprintln! panics
/// on write failure).
#[test]
fn test_seccomp_kvmfork_install() {
    eprintln!("Before install, about to call seccomp::install(KvmFork)");
    match seccomp::install(BackendType::KvmFork) {
        Ok(()) => {
            eprintln!("install returned Ok, about to test write");
            unsafe {
                libc::write(2, b"WRITE_CALL_OK\n" as *const u8 as *const libc::c_void, 13);
            }
            eprintln!("WRITE via stdio also works");
        }
        Err(e) => {
            eprintln!("install returned Err: {e}");
        }
    }
}

/// Manual test with ALLOW before DENY (same structure as the working C program).
#[test]
fn test_seccomp_manual_allow_before_deny() {
    use std::os::raw::c_long;

    #[repr(C)]
    struct sock_filter {
        code: u16, jt: u8, jf: u8, k: u32,
    }
    #[repr(C)]
    struct sock_fprog {
        len: u16,
        filter: *const sock_filter,
    }

    let filter = [
        sock_filter { code: 0x0020, jt: 0, jf: 0, k: 4 },
        sock_filter { code: 0x0015, jt: 1, jf: 0, k: 0xc000003e },
        sock_filter { code: 0x0006, jt: 0, jf: 0, k: 0x80000000 },
        sock_filter { code: 0x0020, jt: 0, jf: 0, k: 0 },
        // ALLOW at [4], DENY at [5]
        sock_filter { code: 0x0015, jt: 0, jf: 1, k: 1 },
        sock_filter { code: 0x0006, jt: 0, jf: 0, k: 0x7fff0000 },
        sock_filter { code: 0x0006, jt: 0, jf: 0, k: 0x0005000d },
    ];

    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    eprintln!("Before seccomp");
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        let ret = libc::syscall(
            libc::SYS_seccomp as c_long,
            1 as c_long,
            0 as c_long,
            &prog as *const sock_fprog,
        );
        eprintln!("seccomp returned: {}", ret);
    }
    eprintln!("After seccomp (should work)");
    unsafe { libc::write(2, b"WRITE_OK\n" as *const u8 as *const libc::c_void, 9); }
    eprintln!("DONE");
}
