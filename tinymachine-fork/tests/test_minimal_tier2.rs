use std::path::PathBuf;
use tinymachine_fork::register_all_backends;
use tinymachine_api::sandbox::SandboxBackend;
use tinymachine_fork::fork::KvmForkBackend;
use tinymachine_api::Variant;

#[test]
fn test_minimal_tier2() {
    register_all_backends();
    let variant = Variant::new("python", "minimal", "base");
    eprintln!("Testing Tier 2: {}/{}", variant.lang, variant.variant);
    let mut backend = KvmForkBackend::new();
    SandboxBackend::init(&mut backend, &variant).expect("init failed");
    let output = SandboxBackend::exec(&mut backend, "print('hello from Tier 2')").expect("exec failed");
    eprintln!("Output: {}", output.trim());
    assert!(output.contains("hello from Tier 2"), "Unexpected output: {}", output);
    SandboxBackend::destroy(&mut backend).expect("destroy failed");
    eprintln!("Tier 2 test PASSED!");
}
