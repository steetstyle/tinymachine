//! Symbolic resource profiler — estimates RAM/CPU/GPU usage from IR analysis.
//!
//! Uses [`tinymachine_ir`] to parse source code into a language-agnostic IR,
//! then walks the IR to detect imports, array allocations, HTTP calls,
//! and file operations. No string matching — all analysis is done on
//! the parsed AST.
//!
//! # Example
//!
//! ```
//! use tinymachine_fork::profiler::SymbolicProfiler;
//!
//! let profile = SymbolicProfiler::profile("import numpy; x = np.ones((1024, 1024))");
//! assert!(profile.ram_bytes > 5 * 1024 * 1024);
//! assert!(!profile.gpu_required);
//! ```
//!
//! # Design
//!
//! A [`ProfilerVisitor`] implements [`IrVisitor`] to walk the IR tree.
//! The visitor detects:
//!
//! - **Imports**: `import numpy`, `from torch import ...`
//! - **Array allocations**: `np.ones((1024, 1024))` — extracts dimensions
//! - **HTTP calls**: `requests.get(...)`, `urllib.request`
//! - **File operations**: `open(...)`, `.read()`, `.write()`
//! - **Framework detection**: `flask`, `express`, `django` → long-running flag

use tinymachine_ir::{IrParser, IrVisitor, IrExpr};
use tinymachine_ir::python::PythonParser;

/// Maximum code length for profiling (1 MB). Codes longer than this skip
/// detailed AST analysis and return a conservative estimate to prevent
/// CPU-exhaustion DoS from large code inputs.
const MAX_CODE_LENGTH: usize = 1024 * 1024;

/// Baseline RAM per sandbox (5 MB)
const BASE_SANDBOX_RAM: u64 = 5 * 1024 * 1024;
/// Baseline CPU time per sandbox (0.5 ms)
const BASE_SANDBOX_CPU: u64 = 500;
/// Additional RAM for numpy import (~20 MB)
const NUMPY_RAM: u64 = 20 * 1024 * 1024;
/// Additional RAM for torch import (~1 GB)
const TORCH_RAM: u64 = 1024 * 1024 * 1024;
/// Additional RAM for tinygrad import (~50 MB)
const TINYGRAD_RAM: u64 = 50 * 1024 * 1024;
/// Additional RAM for Node.js runtime (~30 MB)
const NODE_RAM: u64 = 30 * 1024 * 1024;
/// CPU latency per HTTP call (~50 ms)
const HTTP_LATENCY_US: u64 = 50_000;
/// Buffer RAM per file operation (1 MB)
const FILE_BUF_RAM: u64 = 1024 * 1024;
/// Additional RAM for framework/server imports (~30 MB)
const FRAMEWORK_RAM: u64 = 30 * 1024 * 1024;
/// Constant bytes per array element (f64, 8 bytes)
const ARRAY_ELEMENT_SIZE: u64 = 8;

/// Resource usage estimate for a single code snippet.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceProfile {
    /// Estimated total RAM usage in bytes.
    pub ram_bytes: u64,
    /// Estimated total CPU time in us (microseconds).
    pub cpu_us: u64,
    /// Whether GPU access is required (torch/tinygrad import).
    pub gpu_required: bool,
    /// Number of network calls detected.
    pub network_calls: usize,
    /// Whether the code appears to be a long-running server/event-loop.
    /// If true, the scheduler should use Tier 3 (long-running) instead of Tier 2.
    pub long_running: bool,
}

impl ResourceProfile {
    /// A zeroed-out profile (no resources used).
    pub fn zero() -> Self {
        Self {
            ram_bytes: 0,
            cpu_us: 0,
            gpu_required: false,
            network_calls: 0,
            long_running: false,
        }
    }

    /// Sum two profiles (additive properties).
    pub fn merge(&self, other: &Self) -> Self {
        Self {
            ram_bytes: self.ram_bytes + other.ram_bytes,
            cpu_us: self.cpu_us + other.cpu_us,
            gpu_required: self.gpu_required || other.gpu_required,
            network_calls: self.network_calls + other.network_calls,
            long_running: self.long_running || other.long_running,
        }
    }
}

impl std::ops::Add for ResourceProfile {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        self.merge(&other)
    }
}

impl std::iter::Sum for ResourceProfile {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + b)
    }
}

/// Symbolic profiler — estimates resource usage without running the code.
///
/// The profiler parses source code through `tinymachine_ir` and walks the
/// resulting IR tree to detect patterns. No string matching is used —
/// all analysis happens on the parsed AST, eliminating false positives
/// from strings/containing import-like text.
pub struct SymbolicProfiler;

impl SymbolicProfiler {
    /// Analyze a code snippet and return a resource usage estimate.
    ///
    /// Detection logic uses AST walking:
    /// - **Imports**: `import numpy` (+20 MB), `import torch` (+1 GB, GPU),
    ///   `import tinygrad` (+50 MB, GPU), `import flask/express/django` (+long_running, +30 MB)
    /// - **Array allocs**: Method calls on `np.ones/torch.zeros` etc. with numeric args
    /// - **HTTP calls**: Method calls like `requests.get/post` etc.
    /// - **File ops**: `open()` calls, method calls `.read()/.write()`
    /// - **Long-running**: `.run()`, `.listen()`, `.serve_forever()`, `.start()`
    pub fn profile(code: &str) -> ResourceProfile {
        // Skip detailed analysis for excessively long codes to prevent
        // CPU-exhaustion DoS.
        if code.len() > MAX_CODE_LENGTH {
            return ResourceProfile {
                ram_bytes: BASE_SANDBOX_RAM + 512 * 1024 * 1024, // conservative 512MB
                cpu_us: BASE_SANDBOX_CPU + 50_000, // conservative 50ms
                gpu_required: false,
                network_calls: 0,
                long_running: false,
            };
        }

        let mut profile = ResourceProfile {
            ram_bytes: BASE_SANDBOX_RAM,
            cpu_us: BASE_SANDBOX_CPU,
            gpu_required: false,
            network_calls: 0,
            long_running: false,
        };

        // Parse with Python parser. If parsing fails (syntax error),
        // return the baseline profile (conservative defaults).
        let program = match PythonParser::parse(code) {
            Ok(p) => p,
            Err(_) => return profile,
        };

        let mut visitor = ProfilerVisitor {
            profile: ResourceProfile::zero(),
            array_dims_seen: false,
        };
        visitor.walk_program(&program);

        // Merge visitor results into baseline
        profile = profile.merge(&visitor.profile);
        profile
    }
}

/// Visitor that walks the IR to detect resource usage patterns.
struct ProfilerVisitor {
    profile: ResourceProfile,
    array_dims_seen: bool,
}

impl IrVisitor for ProfilerVisitor {
    // ─── Import detection ───────────────────────────────────────────

    fn visit_import(&mut self, module: &str, _alias: Option<&str>) {
        self.handle_import(module);
    }

    fn visit_import_from(&mut self, module: &str, _symbol: &str, _alias: Option<&str>) {
        self.handle_import(module);
    }

    // ─── Call detection ─────────────────────────────────────────────

    fn visit_call(&mut self, func: &IrExpr, args: &[IrExpr]) {
        // Try to resolve the function as an attribute chain like "np.ones",
        // "requests.get", or a simple name like "open".
        if let Some(chain) = func.resolve_attr_chain() {
            let chain_str = chain.join(".");

            // ── Array allocations ────────────────────────────────────
            let array_alloc_funcs = [
                "np.ones", "np.zeros", "np.empty", "np.full", "np.array",
                "torch.tensor", "torch.zeros", "torch.ones", "torch.rand",
                "torch.empty",
            ];
            if array_alloc_funcs.contains(&chain_str.as_str()) {
                if let Some(bytes) = extract_array_dims(args) {
                    self.profile.ram_bytes += bytes * ARRAY_ELEMENT_SIZE;
                    self.profile.cpu_us += 10;
                    self.array_dims_seen = true;
                }
            }

            // ── HTTP calls ───────────────────────────────────────────
            let http_funcs = [
                "requests.get", "requests.post", "requests.put",
                "requests.delete", "urllib.request",
            ];
            if http_funcs.contains(&chain_str.as_str()) || chain_str.starts_with("urllib.request") {
                self.profile.network_calls += 1;
                self.profile.cpu_us += HTTP_LATENCY_US;
            }

            // ── Framework / long-running detection ────────────────────
            let long_running_methods = [
                "app.run", "app.listen", "app.start",
                "Application.run", "Application.listen",
                "server.serve_forever", "serve_forever",
                "Uvicorn.run", "uvicorn.run",
                "gunicorn.run",
                "loop.run_forever", "loop.run_until_complete",
                "asyncio.run",
            ];
            if long_running_methods.contains(&chain_str.as_str()) {
                self.profile.long_running = true;
            }
        }

        // Also check plain function names (not method calls)
        if let IrExpr::Name(name) = func {
            // `open(...)` → file operation
            if name == "open" {
                self.profile.ram_bytes += FILE_BUF_RAM;
            }
        }

        // File method calls: .read(), .write()
        if let IrExpr::Attribute { attr, .. } = func {
            if attr == "read" || attr == "write" {
                self.profile.ram_bytes += FILE_BUF_RAM;
            }
        }
    }

    // ─── Method call detection for .read() / .write() ───────────────

    fn visit_attribute(&mut self, _value: &IrExpr, attr: &str) {
        // .read() and .write() are detected at the Call level via
        // resolve_attr_chain. But we also check standalone attributes
        // like ".read()" in a call context.
        if attr == "read" || attr == "write" {
            // This will be caught by visit_call as well if it's a method
            // call. We won't double-count because visit_attribute is called
            // during the walk, but we only add RAM for file ops if the
            // method is called — which happens in visit_call.
        }
    }

    // ─── String constants (potential URLs or file paths) ────────────

    fn visit_str(&mut self, s: &str) {
        // If a string looks like a URL, it might be an HTTP call
        if s.starts_with("http://") || s.starts_with("https://") {
            // The call itself is already counted in visit_call.
            // We just flag it for extra CPU time.
            self.profile.cpu_us += 5; // negligible
        }
    }
}

impl ProfilerVisitor {
    fn handle_import(&mut self, module: &str) {
        match module {
            "numpy" | "scipy" | "pandas" | "matplotlib" => {
                self.profile.ram_bytes += NUMPY_RAM;
            }
            "torch" | "torchvision" | "torchaudio" => {
                self.profile.ram_bytes += TORCH_RAM;
                self.profile.gpu_required = true;
            }
            "tinygrad" | "extra" => {
                self.profile.ram_bytes += TINYGRAD_RAM;
                self.profile.gpu_required = true;
            }
            "flask" | "django" | "fastapi" | "bottle" | "tornado" | "aiohttp" => {
                self.profile.ram_bytes += FRAMEWORK_RAM;
                self.profile.long_running = true;
            }
            "node" | "express" => {
                self.profile.ram_bytes += NODE_RAM;
                self.profile.long_running = true;
            }
            _ => {}
        }
    }
}

/// Try to extract array dimensions from call arguments.
///
/// Handles patterns like:
/// - `np.ones((1024, 1024))` — tuple-wrapped dimensions
/// - `torch.zeros([3, 224, 224])` — list-wrapped dimensions
/// - `torch.tensor(3, 224)` — direct dimensions
///
/// Returns total element count (product of dimensions), or `None`.
fn extract_array_dims(args: &[IrExpr]) -> Option<u64> {
    // First arg may be a Tuple or List containing the dimensions,
    // or the args themselves may be the dimensions.
    let dims: Vec<u64> = if args.is_empty() {
        return None;
    } else if let Some(first) = args.first() {
        // Check if first arg is a Tuple (np.ones((3, 4))) or List (torch.zeros([3, 4]))
        match first {
            IrExpr::Tuple(elts) | IrExpr::List(elts) => {
                if elts.is_empty() {
                    return None;
                }
                elts.iter().filter_map(|e| e.as_int().map(|i| i.max(0) as u64)).collect()
            }
            // Direct args: torch.tensor(3, 224)
            _ => {
                args.iter().filter_map(|e| e.as_int().map(|i| i.max(0) as u64)).collect()
            }
        }
    } else {
        return None;
    };

    if dims.is_empty() {
        None
    } else {
        Some(dims.iter().product())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Smoke tests ───────────────────────────────────────────────────

    #[test]
    fn test_empty_code() {
        let p = SymbolicProfiler::profile("");
        assert_eq!(p.ram_bytes, BASE_SANDBOX_RAM);
        assert_eq!(p.cpu_us, BASE_SANDBOX_CPU);
        assert!(!p.gpu_required);
        assert_eq!(p.network_calls, 0);
        assert!(!p.long_running);
    }

    #[test]
    fn test_base_ram() {
        let p = SymbolicProfiler::profile("x = 1 + 1");
        assert_eq!(p.ram_bytes, BASE_SANDBOX_RAM);
        assert_eq!(p.cpu_us, BASE_SANDBOX_CPU);
    }

    // ── Import detection ──────────────────────────────────────────────

    #[test]
    fn test_numpy_detection() {
        let p = SymbolicProfiler::profile("import numpy\nx = np.array([1,2,3])");
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + NUMPY_RAM);
        assert!(!p.gpu_required);
    }

    #[test]
    fn test_torch_detection() {
        let p = SymbolicProfiler::profile("import torch\nx = torch.zeros(3, 224, 224)");
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + TORCH_RAM);
        assert!(p.gpu_required);
    }

    #[test]
    fn test_tinygrad_detection() {
        let p = SymbolicProfiler::profile("from tinygrad import Tensor");
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + TINYGRAD_RAM);
        assert!(p.gpu_required);
    }

    #[test]
    fn test_from_syntax() {
        let p = SymbolicProfiler::profile("from numpy import array");
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + NUMPY_RAM);
    }

    #[test]
    fn test_flask_detection_long_running() {
        let p = SymbolicProfiler::profile("from flask import Flask\napp = Flask(__name__)\napp.run()");
        assert!(p.long_running);
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + FRAMEWORK_RAM);
    }

    #[test]
    fn test_express_detection() {
        // This test verifies that the profiler handles non-Python-like
        // patterns gracefully (just conservative defaults).
        let p = SymbolicProfiler::profile("const express = require('express'); const app = express(); app.listen(3000);");
        // Parsing will fail, so we get baseline only
        assert_eq!(p.ram_bytes, BASE_SANDBOX_RAM);
    }

    // ── HTTP detection ────────────────────────────────────────────────

    #[test]
    fn test_http_detection() {
        let p = SymbolicProfiler::profile(
            "import requests\nr = requests.get('https://example.com')",
        );
        assert_eq!(p.network_calls, 1);
        assert!(p.cpu_us > BASE_SANDBOX_CPU);
    }

    #[test]
    fn test_multiple_http_calls() {
        let code = "\
import requests
a = requests.get('https://a.com')
b = requests.post('https://b.com')
";
        let p = SymbolicProfiler::profile(code);
        assert_eq!(p.network_calls, 2);
    }

    #[test]
    fn test_urllib_detection() {
        let p = SymbolicProfiler::profile("import urllib.request\nurllib.request.urlopen('https://example.com')");
        assert_eq!(p.network_calls, 1);
    }

    // ── Array allocation ──────────────────────────────────────────────

    #[test]
    fn test_array_alloc_np_ones() {
        let p = SymbolicProfiler::profile("x = np.ones((1024, 1024))");
        // 1024 x 1024 x 8 = 8 MB
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + 1024 * 1024 * ARRAY_ELEMENT_SIZE);
    }

    #[test]
    fn test_array_alloc_torch_zeros_brackets() {
        let p = SymbolicProfiler::profile("x = torch.zeros([3, 224, 224])");
        // 3 x 224 x 224 x 8 = ~1.2 MB
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + 3 * 224 * 224 * ARRAY_ELEMENT_SIZE);
    }

    #[test]
    fn test_array_alloc_direct_args() {
        let p = SymbolicProfiler::profile("x = torch.tensor(64, 64)");
        // 64 x 64 x 8 = 32 KB
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + 64 * 64 * ARRAY_ELEMENT_SIZE);
    }

    #[test]
    fn test_array_alloc_empty() {
        let p = SymbolicProfiler::profile("x = np.empty((10,))");
        // 10 x 8 = 80 bytes
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + 10 * ARRAY_ELEMENT_SIZE);
    }

    #[test]
    fn test_no_false_positive_alloc() {
        // String-matching would catch "np.ones" inside this string.
        // AST should NOT.
        let p = SymbolicProfiler::profile("print('np.ones is a function')");
        assert_eq!(p.ram_bytes, BASE_SANDBOX_RAM);
    }

    // ── File operations ───────────────────────────────────────────────

    #[test]
    fn test_file_open() {
        let p = SymbolicProfiler::profile("f = open('/tmp/x', 'r')");
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + FILE_BUF_RAM);
    }

    #[test]
    fn test_file_read_write() {
        let p = SymbolicProfiler::profile("data = f.read()\nf.write('hello')");
        // open() call is detected, plus .read and .write
        assert!(p.ram_bytes >= BASE_SANDBOX_RAM + FILE_BUF_RAM);
    }

    // ── Profile composition ──────────────────────────────────────────

    #[test]
    fn test_profile_merge() {
        let a = ResourceProfile {
            ram_bytes: 10, cpu_us: 20, gpu_required: false,
            network_calls: 1, long_running: false,
        };
        let b = ResourceProfile {
            ram_bytes: 30, cpu_us: 40, gpu_required: true,
            network_calls: 2, long_running: true,
        };
        let c = a.merge(&b);
        assert_eq!(c.ram_bytes, 40);
        assert_eq!(c.cpu_us, 60);
        assert!(c.gpu_required);
        assert_eq!(c.network_calls, 3);
        assert!(c.long_running);
    }

    #[test]
    fn test_profile_add() {
        let a = ResourceProfile {
            ram_bytes: 5, cpu_us: 5, gpu_required: false,
            network_calls: 0, long_running: false,
        };
        let b = ResourceProfile {
            ram_bytes: 7, cpu_us: 3, gpu_required: true,
            network_calls: 2, long_running: true,
        };
        let c = a + b;
        assert_eq!(c.ram_bytes, 12);
        assert_eq!(c.cpu_us, 8);
        assert!(c.gpu_required);
    }

    #[test]
    fn test_profile_sum() {
        let profiles = vec![
            ResourceProfile {
                ram_bytes: 1, cpu_us: 2, gpu_required: false,
                network_calls: 0, long_running: false,
            },
            ResourceProfile {
                ram_bytes: 3, cpu_us: 4, gpu_required: true,
                network_calls: 1, long_running: false,
            },
        ];
        let total: ResourceProfile = profiles.into_iter().sum();
        assert_eq!(total.ram_bytes, 4);
        assert_eq!(total.cpu_us, 6);
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn test_zero_profile() {
        let z = ResourceProfile::zero();
        assert_eq!(z.ram_bytes, 0);
        assert_eq!(z.cpu_us, 0);
        assert!(!z.gpu_required);
        assert_eq!(z.network_calls, 0);
        assert!(!z.long_running);
    }

    #[test]
    fn test_profile_on_noise() {
        let p = SymbolicProfiler::profile("    \n\t  ");
        assert_eq!(p.ram_bytes, BASE_SANDBOX_RAM);
    }

    #[test]
    fn test_no_false_positive_import_in_string() {
        // AST should NOT detect "import numpy" inside a string literal
        let p = SymbolicProfiler::profile("code = \"import numpy\"");
        assert_eq!(p.ram_bytes, BASE_SANDBOX_RAM);
    }

    #[test]
    fn test_no_false_positive_http_in_string() {
        // AST should NOT detect "requests.get" inside a string
        let p = SymbolicProfiler::profile("msg = \"requests.get is a function\"");
        assert_eq!(p.network_calls, 0);
    }
}
