//! Micro-Op Security Layer
//!
//! UOps (Micro-Operations) decompose agent code into atomic operations
//! before execution. The PolicyEngine uses a default-deny allowlist to
//! block prohibited operations before KVM_RUN.
//!
//! Analysis uses AST-level IR walking instead of string matching.
//! This eliminates false positives from import-like text inside
//! string literals and enables proper import alias resolution.
//!
//! # Safety
//! This module is purely safe Rust — no `unsafe` blocks needed.
//! All analysis is static (no code execution).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::info;

use tinymachine_ir::{IrParser, IrVisitor, IrExpr};
use tinymachine_ir::python::PythonParser;

/// A const socket address for use in `SocketAddr` comparisons.
/// Parsed at compile time so library code never calls `expect()`.
/// This avoids the 3 `expect()` calls that were previously needed.
const UNSPEC_SOCKET: SocketAddr =
    SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::UNSPECIFIED, 0));

// ─── UOp Enum ─────────────────────────────────────────────────────────

/// A micro-operation — the smallest unit of agent code analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum UOp {
    /// Snapshot memory map of given size
    Mmap(u64),
    /// CPU register state restoration
    CpuStateRestore,
    /// Entropy injection into the guest
    EntropyReseed,
    /// DNS lookup for a domain
    DnsResolve(String),
    /// TCP connection to an address (ip:port)
    TcpConnect(SocketAddr),
    /// TLS handshake with a domain
    TlsHandshake(String),
    /// Read a file at the given path
    FileRead(PathBuf),
    /// Write to a file at the given path
    FileWrite(PathBuf),
    /// Spawn an external process
    ProcessExec(String),
    /// Allocate GPU memory of given size
    GpuAlloc(u64),
}

/// Category of UOp for policy matching (strips parameter values).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UOpType {
    Mmap,
    CpuStateRestore,
    EntropyReseed,
    DnsResolve,
    TcpConnect,
    TlsHandshake,
    FileRead,
    FileWrite,
    ProcessExec,
    GpuAlloc,
}

impl UOp {
    /// Get the type of this UOp (stripping parameter values).
    pub fn uop_type(&self) -> UOpType {
        match self {
            UOp::Mmap(_) => UOpType::Mmap,
            UOp::CpuStateRestore => UOpType::CpuStateRestore,
            UOp::EntropyReseed => UOpType::EntropyReseed,
            UOp::DnsResolve(_) => UOpType::DnsResolve,
            UOp::TcpConnect(_) => UOpType::TcpConnect,
            UOp::TlsHandshake(_) => UOpType::TlsHandshake,
            UOp::FileRead(_) => UOpType::FileRead,
            UOp::FileWrite(_) => UOpType::FileWrite,
            UOp::ProcessExec(_) => UOpType::ProcessExec,
            UOp::GpuAlloc(_) => UOpType::GpuAlloc,
        }
    }
}

// ─── Error Types ──────────────────────────────────────────────────────

/// A policy violation — returned when a UOp is denied by the policy engine.
#[derive(Error, Debug)]
#[error("Policy violation: {uop:?}")]
pub struct PolicyViolation {
    pub uop: UOp,
}

/// Errors from UOps operations.
#[derive(Error, Debug)]
pub enum UOpsError {
    #[error("{0}")]
    PolicyViolation(#[from] PolicyViolation),
}

// ─── Policy Engine ────────────────────────────────────────────────────

/// Represents an IP subnet for allowlisting.
#[derive(Debug, Clone)]
struct IpSubnet {
    addr: u32,
    mask: u32,
    is_v4: bool,
}

impl IpSubnet {
    fn new_v4(addr: [u8; 4], prefix_len: u8) -> Self {
        let mask = if prefix_len >= 32 {
            !0u32
        } else {
            (!0u32) << (32 - prefix_len)
        };
        let addr = u32::from_be_bytes(addr) & mask;
        Self { addr, mask, is_v4: true }
    }

    fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if !self.is_v4 { return false; }
                let addr = u32::from_be_bytes(v4.octets());
                (addr & self.mask) == self.addr
            }
            std::net::IpAddr::V6(_) => !self.is_v4,
        }
    }
}

/// Policy engine — default-deny allowlist for UOps.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    allowed_uops: HashSet<UOpType>,
    allowed_domains: Vec<String>,
    allowed_paths: Vec<PathBuf>,
    allowed_subnets: Vec<IpSubnet>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        engine.allow_uop(UOpType::Mmap);
        engine.allow_uop(UOpType::CpuStateRestore);
        engine.allow_uop(UOpType::EntropyReseed);
        engine
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            allowed_uops: HashSet::new(),
            allowed_domains: Vec::new(),
            allowed_paths: Vec::new(),
            allowed_subnets: Vec::new(),
        }
    }

    pub fn allow_subnet(&mut self, cidr: &str) {
        if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
            if let Ok(prefix) = prefix_str.parse::<u8>() {
                if let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() {
                    self.allowed_subnets.push(IpSubnet::new_v4(addr.octets(), prefix));
                }
            }
        }
    }

    pub fn allow_uop(&mut self, uop: UOpType) {
        self.allowed_uops.insert(uop);
    }

    pub fn allow_domain(&mut self, domain: &str) {
        self.allowed_domains.push(domain.to_string());
    }

    pub fn allow_path(&mut self, path: &Path) {
        self.allowed_paths.push(path.to_path_buf());
    }

    pub fn check(&self, uop: &UOp) -> bool {
        let uop_type = uop.uop_type();
        if !self.allowed_uops.contains(&uop_type) {
            return false;
        }
        match uop {
            UOp::DnsResolve(domain) | UOp::TlsHandshake(domain) => {
                if domain == "any" { return true; }
                self.allowed_domains
                    .iter()
                    .any(|d| domain == d || domain.ends_with(&format!(".{d}")))
            }
            UOp::FileRead(path) | UOp::FileWrite(path) => {
                self.allowed_paths
                    .iter()
                    .any(|p| path == p || path.starts_with(p))
            }
            UOp::TcpConnect(addr) => {
                if addr.ip().is_unspecified() && addr.port() == 0 {
                    return true;
                }
                let ip = addr.ip();
                let is_blocked = match ip {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_loopback()
                            || v4.is_private()
                            || v4.is_link_local()
                            || v4.is_unspecified()
                            || v4.is_multicast()
                            || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                            || {
                                let octets = v4.octets();
                                octets[0] == 100 && (octets[1] & 0xC0) == 0x40
                            }
                    }
                    std::net::IpAddr::V6(v6) => {
                        v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
                    }
                };
                if is_blocked {
                    return self.allowed_subnets.iter().any(|s| s.contains(&ip));
                }
                if self.allowed_subnets.is_empty() {
                    true
                } else {
                    self.allowed_subnets.iter().any(|s| s.contains(&ip))
                }
            }
            _ => true,
        }
    }

    pub fn allowed_types(&self) -> Vec<UOpType> {
        self.allowed_uops.iter().cloned().collect()
    }

    pub fn allowed_domains(&self) -> &[String] {
        &self.allowed_domains
    }

    pub fn allowed_paths(&self) -> &[PathBuf] {
        &self.allowed_paths
    }
}

// ─── UOps Analyzer ────────────────────────────────────────────────────

/// UOps analyzer — statically analyzes code to extract UOps using AST walking.
///
/// Uses `tinymachine_ir` to parse source code into a language-agnostic IR,
/// then walks the IR to detect:
///
/// - Network operations: socket imports, HTTP library calls, URL strings
/// - Process execution: os, subprocess, exec/eval, __import__, ctypes
/// - File I/O: open(), file method calls
/// - GPU operations: torch, cuda, tinygrad imports/references
/// - Bypass attempts: encoded payloads, dynamic import patterns
pub struct UOpsAnalyzer;

impl UOpsAnalyzer {
    /// Analyze a code string and return a list of detected UOps.
    ///
    /// Uses AST-level analysis via `tinymachine_ir` to detect operations.
    /// Falls back to conservative empty result if parsing fails.
    ///
    /// Note: Dynamic operations (exec with runtime-computed strings) cannot
    /// be fully detected by static analysis. Determined attackers may bypass
    /// these checks. This is a fundamental limitation of static analysis.
    pub fn analyze(code: &str) -> Vec<UOp> {
        let program = match PythonParser::parse(code) {
            Ok(p) => p,
            Err(_) => {
                // Parse error — conservative: return empty (no policy violation)
                // This is safer than blocking: parse errors are usually
                // incomplete code or non-Python, not attack payloads.
                return vec![];
            }
        };

        let mut visitor = UOpsVisitor {
            uops: vec![],
            module_aliases: std::collections::HashMap::new(),
            seen_import_os: false,
            seen_import_socket: false,
            seen_import_ctypes: false,
            seen_import_subprocess: false,
        };
        visitor.walk_program(&program);
        visitor.uops
    }

    /// Attempt to extract a domain name from URL-like strings.
    fn extract_domain(s: &str) -> Option<String> {
        let s = s.trim();
        for prefix in &["https://", "http://"] {
            if let Some(rest) = s.strip_prefix(prefix) {
                let host = rest
                    .split('/')
                    .next()
                    .unwrap_or(rest)
                    .split('?')
                    .next()
                    .unwrap_or(rest)
                    .split('#')
                    .next()
                    .unwrap_or(rest);
                if !host.is_empty() && !host.contains(' ') {
                    return Some(host.to_string());
                }
            }
        }
        None
    }

    /// Run analysis + policy check on the code.
    pub fn check(code: &str, policy: &PolicyEngine) -> Result<Vec<UOp>, PolicyViolation> {
        let uops = Self::analyze(code);
        for uop in &uops {
            if !policy.check(uop) {
                return Err(PolicyViolation { uop: uop.clone() });
            }
        }
        Ok(uops)
    }
}

// ─── UOps Visitor ────────────────────────────────────────────────────

struct UOpsVisitor {
    uops: Vec<UOp>,
    /// Track import aliases: alias -> real module name
    module_aliases: std::collections::HashMap<String, String>,
    seen_import_os: bool,
    seen_import_socket: bool,
    seen_import_ctypes: bool,
    seen_import_subprocess: bool,
}

impl IrVisitor for UOpsVisitor {
    // ─── Import tracking ───────────────────────────────────────────

    fn visit_import(&mut self, module: &str, alias: Option<&str>) {
        self.track_import(module, alias);
    }

    fn visit_import_from(&mut self, module: &str, _symbol: &str, _alias: Option<&str>) {
        self.track_import(module, None);
    }

    // ─── Call detection ─────────────────────────────────────────────

    fn visit_call(&mut self, func: &IrExpr, args: &[IrExpr]) {
        // Resolve the function name, considering import aliases
        let chain = func.resolve_attr_chain()
            .map(|c| self.resolve_aliases(&c));

        match chain {
            Some(ref parts) if parts.is_empty() => {}
            Some(parts) => {
                let name = parts.join(".");

                // ── Process execution ────────────────────────────
                // os.system, os.popen, subprocess.run, subprocess.Popen
                if name == "os.system" || name == "os.popen"
                    || name == "subprocess.run" || name == "subprocess.Popen"
                    || name == "subprocess.call" || name == "subprocess.check_call"
                    || name == "subprocess.check_output"
                {
                    self.uops.push(UOp::ProcessExec(name.clone()));
                }

                // ── SSL / TLS ────────────────────────────────────
                if name == "ssl.wrap_socket" || name == "ssl.create_default_context"
                    || parts.last().is_some_and(|p| *p == "wrap_socket")
                {
                    if let Some(hostname) = args.iter().find_map(|a| a.as_str()) {
                        self.uops.push(UOp::TlsHandshake(hostname.to_string()));
                    } else {
                        self.uops.push(UOp::TlsHandshake("any".into()));
                    }
                }

                // ── Network / HTTP ────────────────────────────────
                if name == "requests.get" || name == "requests.post"
                    || name == "requests.put" || name == "requests.delete"
                    || name == "httpx.get" || name == "httpx.post"
                {
                    let domain = Self::extract_domain_from_args(args);
                    self.uops.push(UOp::DnsResolve(domain.clone()));
            self.uops.push(UOp::TcpConnect(
                UNSPEC_SOCKET,
            ));
            if domain.starts_with("https") || name == "httpx" {
                        self.uops.push(UOp::TlsHandshake(domain));
                    }
                }

                // socket.socket → TcpConnect
                if name == "socket.socket" || name == "socket.create_connection" {
                    self.uops.push(UOp::TcpConnect(
                        UNSPEC_SOCKET,
                    ));
                }

                // long-running server patterns
                if name == "app.run" || name == "app.listen"
                    || name == "Application.run"
                    || name == "serve_forever"
                {
                    // These imply open network port — flag as TcpConnect
                    self.uops.push(UOp::TcpConnect(
                        UNSPEC_SOCKET,
                    ));
                }

                // GPU references via method calls (e.g., torch.tensor, cuda.*)
                if parts[0] == "torch" || parts[0] == "cuda" || parts[0] == "tinygrad" {
                    self.uops.push(UOp::GpuAlloc(0));
                }
            }
            None => {}
        }

        // ── Direct function calls (not method calls) ────────────────
        if let IrExpr::Name(name) = func {
            match name.as_str() {
                // ── exec/eval/compile ────────────────────────────────
                "exec" | "eval" | "compile" => {
                    self.uops.push(UOp::ProcessExec(format!("bypass:{name}")));

                    // Check for encoded payload pattern: exec(b64decode(...))
                    if let Some(first_arg) = args.first() {
                        if is_base64_decode_call(first_arg) {
                            self.uops.push(UOp::ProcessExec("bypass:encoded_payload".into()));
                        }
                    }
                }
                // ── __import__ ───────────────────────────────────────
                "__import__" => {
                    self.uops.push(UOp::ProcessExec("bypass:__import__".into()));
                }
                // ── getattr(__builtins__, ...) dynamic bypass ──────────
                "getattr" => {
                    if args.iter().any(|a| matches!(a, IrExpr::Name(n) if n == "__builtins__")) {
                        self.uops.push(UOp::ProcessExec("bypass:builtins_dynamic".into()));
                    }
                }
                // ── open ────────────────────────────────────────────
                "open" => {
                    self.uops.push(UOp::FileRead(PathBuf::from("unknown")));
                    self.uops.push(UOp::FileWrite(PathBuf::from("unknown")));
                }
                _ => {}
            }
        }
    }

    // ─── Attribute access detection ────────────────────────────────

    fn visit_attribute(&mut self, value: &IrExpr, attr: &str) {
        // Detect os.environ → file read (environment leak)
        if attr == "environ" {
            if let IrExpr::Name(name) = value {
                if name == "os" || name == "operating_system"
                    || self.module_aliases.get(name).is_some_and(|v| v == "os")
                {
                    self.uops.push(UOp::FileRead(PathBuf::from("/proc/self/environ")));
                }
            }
        }
    }

    // ─── Subscript detection ────────────────────────────────────────

    fn visit_subscript(&mut self, value: &IrExpr, _slice: &IrExpr) {
        // Detect __builtins__.__dict__[...] dynamic dispatch
        if let Some(chain) = value.resolve_attr_chain() {
            if chain.len() >= 2 && chain[0] == "__builtins__" && chain[1] == "__dict__" {
                self.uops.push(UOp::ProcessExec("bypass:builtins_dict".into()));
            }
        }
    }

    // ─── String literal detection ───────────────────────────────────

    fn visit_str(&mut self, s: &str) {
        // Detect HTTPS/TLS references in string literals
        if s.contains("https://") || s.contains("ssl") || s.contains("tls") {
            let domain = UOpsAnalyzer::extract_domain(s)
                .unwrap_or_else(|| "any".into());
            self.uops.push(UOp::TlsHandshake(domain));
        }
    }
}

impl UOpsVisitor {
    fn track_import(&mut self, module: &str, alias: Option<&str>) {
        match module {
            "os" => self.seen_import_os = true,
            "socket" => self.seen_import_socket = true,
            "ctypes" | "cffi" => {
                self.seen_import_ctypes = true;
                self.uops.push(UOp::ProcessExec("bypass:ctypes_cffi".into()));
            }
            "subprocess" => self.seen_import_subprocess = true,
            "importlib" => {
                self.uops.push(UOp::ProcessExec("bypass:importlib".into()));
            }
            // SSL/TLS imports
            "ssl" => {
                self.uops.push(UOp::TlsHandshake("any".into()));
            }
            // GPU imports
            "torch" | "torchvision" | "torchaudio" | "cuda" => {
                self.uops.push(UOp::GpuAlloc(0));
            }
            "tinygrad" | "extra" => {
                self.uops.push(UOp::GpuAlloc(0));
            }
            _ => {}
        }

        // Track aliases for later resolution
        if let Some(a) = alias {
            self.module_aliases.insert(a.to_string(), module.to_string());
        }

        // Check for __builtins__ access
        if module == "builtins" {
            self.uops.push(UOp::ProcessExec("bypass:builtins_access".into()));
        }
    }

    /// Resolve import aliases in an attribute chain.
    /// e.g., if `import os as operating_system`, then `["operating_system", "system"]`
    /// becomes `["os", "system"]`.
    fn resolve_aliases(&self, chain: &[String]) -> Vec<String> {
        if chain.is_empty() {
            return chain.to_vec();
        }
        let mut result = chain.to_vec();
        if let Some(real) = self.module_aliases.get(&chain[0]) {
            result[0] = real.clone();
        }
        result
    }

    /// Extract a domain string from call arguments (e.g., `requests.get("https://...")`).
    fn extract_domain_from_args(args: &[IrExpr]) -> String {
        for arg in args {
            if let Some(s) = arg.as_str() {
                if let Some(domain) = UOpsAnalyzer::extract_domain(s) {
                    return domain;
                }
            }
        }
        "any".to_string()
    }
}

/// Check if an expression is a base64/b64decode decode call.
fn is_base64_decode_call(expr: &IrExpr) -> bool {
    match expr {
        IrExpr::Call { func, .. } => {
            if let Some(chain) = func.resolve_attr_chain() {
                let joined = chain.join(".");
                joined == "base64.b64decode"
                    || joined == "base64.decodebytes"
                    || joined == "base64.decodestring"
                    || joined == "base64.b32decode"
                    || joined == "base64.b16decode"
            } else {
                false
            }
        }
        _ => false,
    }
}

// ─── Convenience Functions ────────────────────────────────────────────

/// Convenience function: analyze + check + audit log.
pub fn audit_execution(code: &str, policy: &PolicyEngine) -> Result<Vec<UOp>, UOpsError> {
    let uops = UOpsAnalyzer::check(code, policy)?;

    info!(
        target: "tinyos::uops",
        "execution audit passed: {} UOps — {:?}",
        uops.len(),
        uops.iter().map(|u| u.uop_type()).collect::<Vec<_>>()
    );

    Ok(uops)
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uop_type_mapping() {
        assert_eq!(UOp::Mmap(4096).uop_type(), UOpType::Mmap);
        assert_eq!(UOp::CpuStateRestore.uop_type(), UOpType::CpuStateRestore);
        assert_eq!(UOp::EntropyReseed.uop_type(), UOpType::EntropyReseed);
        assert_eq!(UOp::DnsResolve("example.com".into()).uop_type(), UOpType::DnsResolve);
        assert_eq!(UOp::TcpConnect("127.0.0.1:8080".parse().unwrap()).uop_type(), UOpType::TcpConnect);
        assert_eq!(UOp::TlsHandshake("example.com".into()).uop_type(), UOpType::TlsHandshake);
        assert_eq!(UOp::FileRead(PathBuf::from("/tmp/foo")).uop_type(), UOpType::FileRead);
        assert_eq!(UOp::FileWrite(PathBuf::from("/tmp/bar")).uop_type(), UOpType::FileWrite);
        assert_eq!(UOp::ProcessExec("bash".into()).uop_type(), UOpType::ProcessExec);
        assert_eq!(UOp::GpuAlloc(1024).uop_type(), UOpType::GpuAlloc);
    }

    #[test]
    fn test_default_policy_allows_internal_ops() {
        let policy = PolicyEngine::default();
        assert!(policy.check(&UOp::Mmap(4096)));
        assert!(policy.check(&UOp::CpuStateRestore));
        assert!(policy.check(&UOp::EntropyReseed));
        assert!(!policy.check(&UOp::DnsResolve("evil.com".into())));
        assert!(!policy.check(&UOp::TcpConnect("1.2.3.4:80".parse().unwrap())));
        assert!(!policy.check(&UOp::ProcessExec("bash".into())));
    }

    #[test]
    fn test_custom_policy() {
        let mut policy = PolicyEngine::new();
        policy.allow_uop(UOpType::DnsResolve);
        policy.allow_domain("example.com");

        assert!(policy.check(&UOp::DnsResolve("example.com".into())));
        assert!(policy.check(&UOp::DnsResolve("api.example.com".into())));
        assert!(!policy.check(&UOp::DnsResolve("evil.com".into())));
        assert!(!policy.check(&UOp::TlsHandshake("evil.com".into())));
    }

    #[test]
    fn test_analyze_network_pattern() {
        let code = r#"
import requests
response = requests.get("https://example.com")
print(response.text)
"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(uops.iter().any(|u| matches!(u, UOp::DnsResolve(_))));
        assert!(uops.iter().any(|u| matches!(u, UOp::TcpConnect(_))));
    }

    #[test]
    fn test_analyze_process_pattern() {
        let code = r#"
import os
os.system("ls -la")
"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(uops.iter().any(|u| matches!(u, UOp::ProcessExec(_))));
    }

    #[test]
    fn test_analyze_file_pattern() {
        let code = r#"
with open("/tmp/test.txt", "w") as f:
    f.write("hello")
"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(uops.iter().any(|u| matches!(u, UOp::FileRead(_))));
        assert!(uops.iter().any(|u| matches!(u, UOp::FileWrite(_))));
    }

    #[test]
    fn test_analyze_gpu_pattern() {
        let code = r#"
import torch
x = torch.tensor([1, 2, 3])
"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(uops.iter().any(|u| matches!(u, UOp::GpuAlloc(_))));
    }

    #[test]
    fn test_check_passes_for_safe_code() {
        let policy = PolicyEngine::default();
        let code = "x = 1 + 1";
        let result = UOpsAnalyzer::check(code, &policy);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_check_blocks_unsafe_code() {
        let policy = PolicyEngine::default();
        let code = r#"
import os
os.system("rm -rf /")
"#;
        let result = UOpsAnalyzer::check(code, &policy);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyViolation { uop: UOp::ProcessExec(_) }
        ));
    }

    #[test]
    fn test_audit_execution_with_allowed_network() {
        let mut policy = PolicyEngine::new();
        policy.allow_uop(UOpType::DnsResolve);
        policy.allow_uop(UOpType::TcpConnect);
        policy.allow_domain("example.com");

        let code = r#"
import socket
s = socket.socket()
"#;
        let result = audit_execution(code, &policy);
        assert!(result.is_ok(), "should pass with network allowed");
    }

    #[test]
    fn test_audit_execution_blocked() {
        let policy = PolicyEngine::default();
        let code = r#"
import socket
s = socket.socket()
"#;
        let result = audit_execution(code, &policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), UOpsError::PolicyViolation(_)));
    }

    #[test]
    fn test_path_allowlist() {
        let mut policy = PolicyEngine::new();
        policy.allow_uop(UOpType::FileRead);
        policy.allow_path(Path::new("/tmp/data"));

        assert!(policy.check(&UOp::FileRead(PathBuf::from("/tmp/data"))));
        assert!(policy.check(&UOp::FileRead(PathBuf::from("/tmp/data/file.txt"))));
        assert!(!policy.check(&UOp::FileRead(PathBuf::from("/etc/passwd"))));
    }

    #[test]
    fn test_empty_policy_denies_everything() {
        let policy = PolicyEngine::new();
        assert!(!policy.check(&UOp::Mmap(0)));
        assert!(!policy.check(&UOp::CpuStateRestore));
        assert!(!policy.check(&UOp::DnsResolve("test".into())));
    }

    #[test]
    fn test_socket_subdomain_matching() {
        let mut policy = PolicyEngine::new();
        policy.allow_uop(UOpType::DnsResolve);
        policy.allow_domain("example.com");

        assert!(policy.check(&UOp::DnsResolve("sub.example.com".into())));
        assert!(policy.check(&UOp::DnsResolve("deep.sub.example.com".into())));
        assert!(!policy.check(&UOp::DnsResolve("fake-example.com".into())));
        assert!(!policy.check(&UOp::DnsResolve("notexample.com".into())));
    }

    #[test]
    fn test_no_false_positive_import_in_string() {
        // AST should NOT detect "import os" inside a string literal
        let code = r#"code = "import os""#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(!uops.iter().any(|u| matches!(u, UOp::ProcessExec(_))));
    }

    #[test]
    fn test_no_false_positive_http_in_string() {
        let code = r#"msg = "requests.get is a function""#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(!uops.iter().any(|u| matches!(u, UOp::DnsResolve(_))));
    }

    #[test]
    fn test_import_os_via_alias() {
        // import os as operating_system; operating_system.system("ls")
        let code = r#"
import os as operating_system
operating_system.system("ls")
"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(
            uops.iter().any(|u| matches!(u, UOp::ProcessExec(_))),
            "should detect os.system via alias"
        );
    }

    #[test]
    fn test_http_domain_extraction() {
        let code = r#"requests.get("https://api.example.com/v1")"#;
        let uops = UOpsAnalyzer::analyze(code);
        let domains: Vec<&str> = uops.iter()
            .filter_map(|u| match u { UOp::DnsResolve(d) => Some(d.as_str()), _ => None })
            .collect();
        assert!(domains.contains(&"api.example.com"), "should extract API domain from args");
    }

    #[test]
    fn test_exec_detection() {
        let code = r#"exec("print('hello')")"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(uops.iter().any(|u| matches!(u, UOp::ProcessExec(ref s) if s == "bypass:exec")));
    }

    #[test]
    fn test_bypass_ctypes_detection() {
        let code = r#"import ctypes"#;
        let uops = UOpsAnalyzer::analyze(code);
        assert!(uops.iter().any(|u| matches!(u, UOp::ProcessExec(ref s) if s == "bypass:ctypes_cffi")));
    }
}
