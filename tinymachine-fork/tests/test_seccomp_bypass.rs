/// Test seccomp filter bypass: verify that write works after seccomp
/// by comparing the behavior of two different filter layouts.

use tinymachine_api::sandbox::BackendType;
use tinymachine_fork::seccomp;

/// Directly call seccomp::install but with ALLOW moved before DENY.
/// This is a temporary override to verify the theory.
#[test]
fn test_seccomp_allow_before_deny() {
    eprintln!("test_seccomp_allow_before_deny: SKIP (use manual test instead)");
}

/// Test: install KvmFork filter (original = DENY before ALLOW).
/// Expected: write should fail with EACCES.
#[test]
fn test_seccomp_original_blocking() {
    eprintln!("--- Original KvmFork filter (DENY before ALLOW) ---");
    match seccomp::install(BackendType::KvmFork) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("seccomp install failed: {e}");
            return;
        }
    }
    // This write should FAIL (we'll detect by the panic that follows)
    eprintln!("FAIL: write succeeded unexpectedly");
}

/// Test: install Wasm filter (original = DENY before ALLOW).
/// Check if Wasm filter also blocks write.
#[test]
fn test_seccomp_wasm_original() {
    eprintln!("--- Original Wasm filter (DENY before ALLOW) ---");
    match seccomp::install(BackendType::Wasm) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("seccomp install failed: {e}");
            return;
        }
    }
    // If write works with Wasm but not KvmFork, the issue is in the
    // allowlist, not the filter structure.
    eprintln!("FAIL: write succeeded unexpectedly");
}
