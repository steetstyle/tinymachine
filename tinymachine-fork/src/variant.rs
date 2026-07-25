//! Variant definitions for multi-template execution environments.
//!
//! A "variant" describes a specific execution environment (e.g., `python:minimal`,
//! `python:numpy`, `wasm`). Each variant has a kernel profile, optional initrd,
//! tier, and warm pool configuration.
//!
//! # Design Rules
//!
//! 1. **No fallbacks between variants** — GPU pytorch nvidia, CPU pytorch, and GPU
//!    pytorch amd are different features. There is no fallback between them.
//! 2. **No stacking** — Each variant is standalone. `python:numpy` does not include
//!    tinygrad. `python:pytorch-cpu` does not include numpy.
//! 3. **Source builds** — All variants built from source, no runtime patches.
//! 4. **CPU variants use `base` kernel** — Tier 2 KVM fork, no GPU required.
//! 5. **GPU variants use `gpu-nvidia`/`gpu-vfio` kernel** — Tier 3 FreshBoot.
//!
//! # Variant Auto-Detection
//! When a user runs `tinyos exec --lang python 'import torch; ...'`, the system
//! parses the imports and selects the matching CPU variant. GPU variants require
//! explicit selection (`--variant pytorch-nv` or `--variant tinygrad-nv`).

use serde::{Deserialize, Serialize};

use tinymachine_api::ExecutionTier;

/// Resource constraints for a variant's sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum guest memory in bytes
    pub max_memory: u64,
    /// Maximum CPU time in milliseconds
    pub max_cpu_ms: u64,
    /// Network allowed (default-deny)
    pub network_allowed: bool,
    /// GPU required
    pub gpu_required: bool,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory: 64 * 1024 * 1024, // 64 MB
            max_cpu_ms: 5000,              // 5 seconds
            network_allowed: false,
            gpu_required: false,
        }
    }
}

/// Kernel profile determines which kernel binary to use
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KernelProfile {
    /// Base kernel (no GPU modules)
    Base,
    /// Kernel with Vulkan support
    GpuVk,
    /// Kernel with VFIO PCI passthrough
    GpuVfio,
    /// Kernel with ACPI=y + VFIO=y (for nvidia.ko module loading)
    GpuNvidia,
}

impl KernelProfile {
    /// Get the string identifier for this kernel profile (e.g. "gpu-vk", "base")
    pub fn as_str(&self) -> &'static str {
        match self {
            KernelProfile::Base => "base",
            KernelProfile::GpuVk => "gpu-vk",
            KernelProfile::GpuVfio => "gpu-vfio",
            KernelProfile::GpuNvidia => "gpu-nvidia",
        }
    }

    /// Get the filename for this kernel profile
    pub fn filename(&self) -> &'static str {
        match self {
            KernelProfile::Base => "vmlinux-base",
            KernelProfile::GpuVk => "vmlinux-gpu-vk",
            KernelProfile::GpuVfio => "vmlinux-gpu-vfio",
            KernelProfile::GpuNvidia => "vmlinux-gpu-nvidia",
        }
    }

    /// Parse from a string (reverse of `as_str`).
    ///
    /// Returns `None` for unknown strings (graceful fallback to `Base`).
    /// Named `from_str_opt` instead of `from_str` to avoid collision with
    /// the standard `std::str::FromStr` trait.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "gpu-vk" => Some(KernelProfile::GpuVk),
            "gpu-vfio" => Some(KernelProfile::GpuVfio),
            "gpu-nvidia" => Some(KernelProfile::GpuNvidia),
            "base" => Some(KernelProfile::Base),
            _ => None,
        }
    }
}

/// A variant definition — a specific execution environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variant {
    /// Language (e.g., "python", "node", "wasm")
    pub lang: String,
    /// Variant name — unique per language (e.g., "minimal", "numpy", "pytorch-cpu", "tinygrad-nv")
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Execution tier
    pub tier: ExecutionTier,
    /// Kernel profile for this variant
    pub kernel_profile: KernelProfile,
    /// Whether an initrd is needed
    pub needs_initrd: bool,
    /// Resource limits
    pub limits: ResourceLimits,
    /// Warm pool config
    pub pool_min: usize,
    pub pool_max: usize,
    pub pool_idle_timeout_secs: u64,
    /// Optional kernel version override (None = use registry default)
    #[serde(default)]
    pub kernel_version: Option<String>,
}

impl Variant {
    /// Full identifier like "python:minimal"
    pub fn id(&self) -> String {
        format!("{}:{}", self.lang, self.name)
    }

    /// Check if this variant matches a language and optional variant name
    pub fn matches(&self, lang: &str, name: Option<&str>) -> bool {
        if self.lang != lang {
            return false;
        }
        match name {
            Some(n) => self.name == n,
            None => true, // any variant of this language
        }
    }

    /// Create a Variant from a composition plan.
    ///
    /// This allows the ForkEngine pool to use composition-key based naming
    /// instead of variant ID strings.
    ///
    /// Reads kernel profile, memory, and tier from the plan (which was resolved
    /// from the layer registry metadata) — no hardcoded mappings.
    pub fn from_composition_plan(plan: &crate::layer_registry::CompositionPlan, lang: &str) -> Self {
        let description = format!(
            "Composed: {} layers, profile={}",
            plan.layers.len(),
            plan.kernel_profile
        );

        // Determine kernel profile enum from plan string (no fallback —
        // the plan must contain a valid kernel profile from the registry)
        let kernel_profile = match plan.kernel_profile.as_str() {
            "gpu-vk" => KernelProfile::GpuVk,
            "gpu-vfio" => KernelProfile::GpuVfio,
            "gpu-nvidia" => KernelProfile::GpuNvidia,
            "base" => KernelProfile::Base,
            other => panic!("Invalid kernel profile in composition plan: '{other}'"),
        };

        // Determine tier and pool config from kernel profile
        let (tier, gpu_required, pool_min, pool_max) = match kernel_profile {
            KernelProfile::GpuNvidia | KernelProfile::GpuVfio => {
                (tinymachine_api::ExecutionTier::FreshBoot, true, 0, 2)
            }
            KernelProfile::GpuVk => {
                (tinymachine_api::ExecutionTier::KvmFork, true, 1, 3)
            }
            KernelProfile::Base => {
                (tinymachine_api::ExecutionTier::KvmFork, false, 3, 10)
            }
        };

        // Read memory directly from plan metadata (resolved from registry)
        let max_memory = plan.memory_mb * 1024 * 1024;

        Self {
            lang: lang.to_string(),
            name: format!("compose-{}", &plan.composition_key[..12.min(plan.composition_key.len())]),
            description,
            tier,
            kernel_profile,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory,
                gpu_required,
                ..ResourceLimits::default()
            },
            pool_min,
            pool_max,
            pool_idle_timeout_secs: 60,
            kernel_version: None,
        }
    }

    /// Create the standard `python:minimal` variant
    pub fn python_minimal() -> Self {
        Self {
            lang: "python".into(),
            name: "minimal".into(),
            description: "Python 3 + stdlib, no GPU, Tier 2 KVM fork".into(),
            tier: ExecutionTier::KvmFork,
            kernel_profile: KernelProfile::Base,
            needs_initrd: true,
            limits: ResourceLimits::default(),
            pool_min: 3,
            pool_max: 20,
            pool_idle_timeout_secs: 60,
            kernel_version: None,
        }
    }

    /// Create `python:numpy` variant — CPU-only, no stacking
    ///
    /// Pure numpy. No torch, no tinygrad, no GPU. Tier 2 KVM fork.
    pub fn python_numpy() -> Self {
        Self {
            lang: "python".into(),
            name: "numpy".into(),
            description: "Python 3 + numpy (CPU-only), Tier 2 KVM fork".into(),
            tier: ExecutionTier::KvmFork,
            kernel_profile: KernelProfile::Base,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 128 * 1024 * 1024,
                ..ResourceLimits::default()
            },
            pool_min: 2,
            pool_max: 10,
            pool_idle_timeout_secs: 60,
            kernel_version: None,
        }
    }

    /// Create `python:pytorch-cpu` variant — CPU-only, no stacking
    ///
    /// CPU-only PyTorch. No CUDA, no GPU firmware, no nvidia.ko.
    /// Uses base kernel, Tier 2 KVM fork. Standalone — does not include numpy.
    pub fn python_pytorch_cpu() -> Self {
        Self {
            lang: "python".into(),
            name: "pytorch-cpu".into(),
            description: "Python 3 + torch (CPU-only), Tier 2 KVM fork, no GPU".into(),
            tier: ExecutionTier::KvmFork,
            kernel_profile: KernelProfile::Base,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 2 * 1024 * 1024 * 1024, // 2 GB for torch
                max_cpu_ms: 600_000,                  // 10 minutes (torch import is slow on single VCPU)
                network_allowed: false,
                gpu_required: false,
            },
            pool_min: 1,
            pool_max: 5,
            pool_idle_timeout_secs: 120,
            kernel_version: None,
        }
    }

    /// Create `python:pytorch-nv` variant (Tier 3, NVIDIA GPU via VFIO passthrough)
    ///
    /// GPU PyTorch with CUDA via NVIDIA GPU passthrough. Requires nvidia.ko
    /// kernel module loaded in guest (VBIOS + RMAPI path).
    /// Pool is not pre-warmed (`min=0`); instances are booted on demand.
    pub fn python_pytorch_nv() -> Self {
        Self {
            lang: "python".into(),
            name: "pytorch-nv".into(),
            description: "Python 3 + torch (CUDA NVIDIA), Tier 3 fresh boot, GPU VFIO".into(),
            tier: ExecutionTier::FreshBoot,
            kernel_profile: KernelProfile::GpuNvidia,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 3 * 1024 * 1024 * 1024, // 3 GB
                max_cpu_ms: 300_000,                 // 5 minutes
                network_allowed: true,
                gpu_required: true,
            },
            pool_min: 0,             // not pre-warmed
            pool_max: 2,             // at most 2 idle instances
            pool_idle_timeout_secs: 300, // 5 min
            kernel_version: None,
        }
    }

    /// Create `python:pytorch-amd` variant (Tier 3, AMD GPU via VFIO passthrough)
    ///
    /// GPU PyTorch with ROCm via AMD GPU passthrough.
    /// Pool is not pre-warmed; instances are booted on demand.
    pub fn python_pytorch_amd() -> Self {
        Self {
            lang: "python".into(),
            name: "pytorch-amd".into(),
            description: "Python 3 + torch (ROCm AMD), Tier 3 fresh boot, GPU VFIO".into(),
            tier: ExecutionTier::FreshBoot,
            kernel_profile: KernelProfile::GpuVfio,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 3 * 1024 * 1024 * 1024, // 3 GB
                max_cpu_ms: 300_000,
                network_allowed: true,
                gpu_required: true,
            },
            pool_min: 0,
            pool_max: 2,
            pool_idle_timeout_secs: 300,
            kernel_version: None,
        }
    }

    /// Create `python:tinygrad-cpu` variant (Tier 2, CPU-only)
    ///
    /// Tinygrad on CPU only. Uses base kernel. Tier 2 KVM fork.
    /// No GPU backend, no patches, no stacking.
    pub fn python_tinygrad_cpu() -> Self {
        Self {
            lang: "python".into(),
            name: "tinygrad-cpu".into(),
            description: "Python 3 + tinygrad (CPU-only), Tier 2 KVM fork".into(),
            tier: ExecutionTier::KvmFork,
            kernel_profile: KernelProfile::Base,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 512 * 1024 * 1024, // 512 MB — initrd ~80-100MB uncompressed
                ..ResourceLimits::default()
            },
            pool_min: 1,
            pool_max: 5,
            pool_idle_timeout_secs: 30,
            kernel_version: None,
        }
    }

    /// Create `python:tinygrad-nv` variant (Tier 3, NV backend via KVM VFIO passthrough)
    ///
    /// This variant uses TinyGrad's NVKIface which communicates with the GPU via
    /// nvidia.ko RMAPI or direct PCIIface (sysfs BAR mmap). nvidia.ko is NOT
    /// loaded in the guest; tinygrad accesses GPU via direct BAR MMIO.
    ///
    /// Requires `NV_RENDERER=NAK` env var for GPU kernel compilation (uses the
    /// open-source mesa/tinymesa NAK compiler — no CUDA toolkit needed).
    ///
    /// Requires a VFIO-passthrough NVIDIA GPU bound to vfio-pci.
    /// Pool is not pre-warmed (`min=0`); instances are booted on demand.
    pub fn python_tinygrad_nv() -> Self {
        Self {
            lang: "python".into(),
            name: "tinygrad-nv".into(),
            description: "Python 3 + tinygrad (NV backend), Tier 3 fresh boot, GPU VFIO".into(),
            tier: ExecutionTier::QemuVm,
            kernel_profile: KernelProfile::GpuNvidia,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 3 * 1024 * 1024 * 1024, // 3 GB — initrd ~1.1GB uncompressed
                max_cpu_ms: 300_000,            // 5 minutes
                network_allowed: false,
                gpu_required: true,
            },
            pool_min: 0,             // not pre-warmed
            pool_max: 2,             // at most 2 idle instances
            pool_idle_timeout_secs: 300, // 5 min
            kernel_version: None,
        }
    }

    /// Create `python:tinygrad-amd` variant (Tier 3, AMD backend via KVM VFIO passthrough)
    ///
    /// Tinygrad on AMD GPU. Uses direct ring buffer (no ROCm driver needed).
    /// Pool is not pre-warmed; instances are booted on demand.
    pub fn python_tinygrad_amd() -> Self {
        Self {
            lang: "python".into(),
            name: "tinygrad-amd".into(),
            description: "Python 3 + tinygrad (AMD backend), Tier 3 fresh boot, GPU VFIO".into(),
            tier: ExecutionTier::FreshBoot,
            kernel_profile: KernelProfile::GpuVk,
            needs_initrd: true,
            limits: ResourceLimits {
                max_memory: 512 * 1024 * 1024,
                max_cpu_ms: 300_000,
                network_allowed: false,
                gpu_required: true,
            },
            pool_min: 0,
            pool_max: 2,
            pool_idle_timeout_secs: 300,
            kernel_version: None,
        }
    }

    /// Create the standard `wasm` variant (Tier 1, no kernel)
    pub fn wasm() -> Self {
        Self {
            lang: "wasm".into(),
            name: "minimal".into(),
            description: "WASM sandbox (wasmtime), in-process, 2µs latency".into(),
            tier: ExecutionTier::Wasm,
            kernel_profile: KernelProfile::Base,
            needs_initrd: false,
            limits: ResourceLimits {
                max_memory: 16 * 1024 * 1024,
                ..ResourceLimits::default()
            },
            pool_min: 0,
            pool_max: 0,
            pool_idle_timeout_secs: 0,
            kernel_version: None,
        }
    }

    /// Convert from the API's `Variant` to the fork's detailed `Variant`.
    ///
    /// The kernel profile comes from `api_variant.kernel_profile` — no
    /// registry lookup, no fallback. Returns `None` for unknown kernel
    /// profiles.
    pub fn from_api(api_variant: &tinymachine_api::variant::Variant) -> Option<Self> {
        let lang = &api_variant.lang;
        let variant_name = &api_variant.variant;

        // Use kernel profile directly from the API variant (no fallback)
        let kernel_profile = match api_variant.kernel_profile.as_str() {
            "base" => KernelProfile::Base,
            "gpu-vk" => KernelProfile::GpuVk,
            "gpu-vfio" => KernelProfile::GpuVfio,
            "gpu-nvidia" => KernelProfile::GpuNvidia,
            // Unknown kernel profile → None (no fallback to Base)
            _ => return None,
        };

        let tier = if lang == "wasm" {
            tinymachine_api::ExecutionTier::Wasm
        } else if kernel_profile == KernelProfile::GpuNvidia || kernel_profile == KernelProfile::GpuVfio {
            tinymachine_api::ExecutionTier::QemuVm
        } else if kernel_profile == KernelProfile::GpuVk {
            tinymachine_api::ExecutionTier::KvmFork
        } else {
            tinymachine_api::ExecutionTier::KvmFork
        };

        let gpu_required = matches!(kernel_profile, KernelProfile::GpuNvidia | KernelProfile::GpuVfio);
        Some(Self {
            lang: lang.to_string(),
            name: variant_name.to_string(),
            description: format!("{lang}:{variant_name} (from API)"),
            tier,
            kernel_profile,
            needs_initrd: lang != "wasm",
            limits: ResourceLimits {
                gpu_required,
                ..ResourceLimits::default()
            },
            pool_min: 3,
            pool_max: 10,
            pool_idle_timeout_secs: 60,
            kernel_version: None,
        })
    }
}

/// Return the boot memory size (in bytes) for a given variant name.
///
/// Uses the variant's `limits.max_memory` when the field is set to a
/// non-default value (>64MB).  Otherwise falls back to a name-based map
/// that **must** stay in sync with the variant definitions above.
///
/// This is the **single source of truth** for boot memory sizing, used
/// by both `build_snapshot.rs` (Tier 2 snapshot builder) and
/// `fresh_boot.rs` (Tier 3 fresh boot).  When a new variant is added,
/// update BOTH the `Variant::python_*()` method AND this function.
///
/// # Special cases
///
/// * Pytorch variants return `0xFEC00000` (just below the x86 IOAPIC
///   MMIO hole at 4 GB).  The guest PCI allocator needs space for GPU
///   BARs in the 32-bit gap above RAM; 4 GB leaves no room, so we cap
///   memory at ~4 GB − 20 MB.
/// * `tinygrad-nv` returns 3 GB — its initramfs is ~1.1 GB
///   uncompressed (NVIDIA firmware + modules + Python packages).
///   tmpfs default max_size = 50% of RAM, so need RAM >= 2.2 GB.
pub fn boot_memory_size_bytes(name: &str) -> u64 {
    match name {
        // Pytorch variants — cap below 4 GB IOAPIC hole
        "pytorch" | "pytorch-cpu" | "pytorch-nv" => 0xFEC00000,
        // TinyGrad NV has a ~1.1 GB initramfs
        "tinygrad-nv" => 3 * 1024 * 1024 * 1024,  // 3 GB
        // Big initrd variants (~80-100 MB uncompressed, tmpfs needs room)
        "tinygrad" | "tinygrad-cpu" | "numpy" => 512 * 1024 * 1024,
        // Default for minimal / everything else
        _ => 128 * 1024 * 1024,
    }
}

/// Auto-detect variant from code imports.
///
/// Parses the import statements in the code and selects the matching variant.
/// **No fallback between CPU and GPU variants.** `import torch` selects
/// `pytorch-cpu` (CPU-only). For GPU, the user must explicitly choose
/// `--variant pytorch-nv` or `--variant tinygrad-nv`.
///
/// This is a simplified AST-free version that uses string matching.
pub fn detect_variant(lang: &str, code: &str) -> Variant {
    match lang {
        "wasm" => Variant::wasm(),
        "python" => {
            let lower = code.to_lowercase();
            // torch → pytorch-cpu (CPU-only, no GPU fallback)
            if lower.contains("import torch") || lower.contains("from torch") {
                Variant::python_pytorch_cpu()
            }
            // tinygrad → tinygrad-cpu (CPU-only, no GPU fallback)
            else if lower.contains("import tinygrad") || lower.contains("from tinygrad") {
                Variant::python_tinygrad_cpu()
            }
            // numpy → numpy (CPU-only)
            else if lower.contains("import numpy") || lower.contains("from numpy") {
                Variant::python_numpy()
            } else {
                Variant::python_minimal()
            }
        }
        _ => Variant::python_minimal(),
    }
}

/// Auto-detect variant from code imports using the Layer Registry.
///
/// Unlike `detect_variant()` which uses simple string matching, this function
/// uses the full `LayerRegistry` to resolve imports to layers. This provides:
/// - Multi-import support (e.g., `import numpy, tinygrad`)
/// - Version-aware resolution (from pragmas or latest)
/// - Explicit dependency override via `--dep`
/// - Composition plan generation
///
/// Returns `None` if the registry is not available or the imports can't be resolved.
pub fn detect_variant_with_registry(lang: &str, code: &str, explicit_deps: &[(String, String)]) -> Option<Variant> {
    use crate::layer_registry::{LayerRegistry, parse_pragmas, VersionConstraint};

    let registry = LayerRegistry::load().ok()?;

    // Parse implicit imports from code
    let imports = crate::layer_registry::extract_imports(lang, code);

    // Parse pragmas from code (# tinyos:dep X@Y)
    let pragma_deps = parse_pragmas(code);

    // Merge explicit deps (CLI --dep) with pragmas
    let mut all_deps: Vec<(String, String)> = explicit_deps.to_vec();
    for (name, ver) in &pragma_deps {
        if !all_deps.iter().any(|(n, _)| n == name) {
            all_deps.push((name.clone(), ver.clone()));
        }
    }

    // Collect all layer names needed
    let mut all_layer_names: Vec<String> = Vec::new();

    // Resolve imports to layer names
    for import in &imports {
        let constraint = if let Some((_name, ver)) = all_deps.iter().find(|(n, _)| n == import) {
            VersionConstraint::Exact(ver.clone())
        } else {
            VersionConstraint::Latest
        };

        if let Ok(layer) = registry.resolve_import(lang, import, &constraint) {
            if !all_layer_names.contains(&layer.name) {
                all_layer_names.push(layer.name.clone());
            }
        }
    }

    // Add explicit deps that weren't from imports
    for (name, _ver) in &all_deps {
        if !all_layer_names.contains(name) {
            // Check if the name maps to a pip layer
            if let Some(pip_name) = crate::layer_registry::import_to_pip_layer(name) {
                if !all_layer_names.contains(&pip_name.to_string()) {
                    all_layer_names.push(pip_name.to_string());
                }
            }
        }
    }

    // Build variant from composition plan (reads kernel profile, memory,
    // cmd config from layer registry metadata — no hardcoded mappings)
    let plan = match registry.resolve(lang, code, &all_deps) {
        Ok(p) => p,
        Err(_) => return Some(Variant::python_minimal()),
    };
    Some(Variant::from_composition_plan(&plan, lang))
}

/// Get all built-in variants
pub fn builtin_variants() -> Vec<Variant> {
    vec![
        Variant::python_minimal(),
        Variant::python_numpy(),
        Variant::python_tinygrad_cpu(),
        Variant::python_tinygrad_nv(),
        Variant::python_tinygrad_amd(),
        Variant::python_pytorch_cpu(),
        Variant::python_pytorch_nv(),
        Variant::python_pytorch_amd(),
        Variant::wasm(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_id() {
        let v = Variant::python_minimal();
        assert_eq!(v.id(), "python:minimal");
    }

    #[test]
    fn test_variant_wasm() {
        let v = Variant::wasm();
        assert_eq!(v.tier, ExecutionTier::Wasm);
        assert!(!v.needs_initrd);
    }

    #[test]
    fn test_detect_python_minimal() {
        let v = detect_variant("python", "print('hello')");
        assert_eq!(v.name, "minimal");
    }

    #[test]
    fn test_detect_python_numpy() {
        let v = detect_variant("python", "import numpy as np\nx = np.array([1])");
        assert_eq!(v.name, "numpy");
    }

    #[test]
    fn test_detect_python_torch_pytorch_cpu() {
        let v = detect_variant("python", "import torch\nx = torch.tensor([1])");
        assert_eq!(v.name, "pytorch-cpu");
        // CPU pytorch uses Tier 2, base kernel, NO GPU
        assert_eq!(v.tier, ExecutionTier::KvmFork);
        assert_eq!(v.kernel_profile, KernelProfile::Base);
        assert!(!v.limits.gpu_required);
    }

    #[test]
    fn test_detect_tinygrad_import_cpu() {
        let v = detect_variant("python", "import tinygrad\nx = tinygrad.Tensor([1, 2, 3])");
        assert_eq!(v.name, "tinygrad-cpu");
        assert_eq!(v.tier, ExecutionTier::KvmFork);
        assert_eq!(v.kernel_profile, KernelProfile::Base);
        assert!(!v.limits.gpu_required);
    }

    #[test]
    fn test_detect_from_tinygrad_import_cpu() {
        let v = detect_variant("python", "from tinygrad import Tensor");
        assert_eq!(v.name, "tinygrad-cpu");
        assert!(!v.limits.gpu_required);
    }

    #[test]
    fn test_detect_wasm() {
        let v = detect_variant("wasm", "(module ...)");
        assert_eq!(v.tier, ExecutionTier::Wasm);
    }

    #[test]
    fn test_builtin_variants_count() {
        let variants = builtin_variants();
        assert!(variants.len() >= 9);
    }

    #[test]
    fn test_kernel_profile_filename() {
        assert_eq!(KernelProfile::Base.filename(), "vmlinux-base");
        assert_eq!(KernelProfile::GpuVk.filename(), "vmlinux-gpu-vk");
        assert_eq!(KernelProfile::GpuVfio.filename(), "vmlinux-gpu-vfio");
        assert_eq!(KernelProfile::GpuNvidia.filename(), "vmlinux-gpu-nvidia");
    }

    // ─── Pytorch CPU variant tests ─────────────────────────────────

    #[test]
    fn test_variant_python_pytorch_cpu() {
        let v = Variant::python_pytorch_cpu();
        assert_eq!(v.lang, "python");
        assert_eq!(v.name, "pytorch-cpu");
        assert_eq!(v.id(), "python:pytorch-cpu");
        assert_eq!(v.tier, ExecutionTier::KvmFork);
        assert_eq!(v.kernel_profile, KernelProfile::Base);
        assert!(v.needs_initrd);
        assert!(!v.limits.gpu_required);
        assert!(!v.limits.network_allowed);
        assert_eq!(v.limits.max_memory, 2 * 1024 * 1024 * 1024);
        assert_eq!(v.pool_min, 1);
        assert_eq!(v.pool_max, 5);
    }

    // ─── Pytorch NV variant tests ──────────────────────────────────

    #[test]
    fn test_variant_python_pytorch_nv() {
        let v = Variant::python_pytorch_nv();
        assert_eq!(v.lang, "python");
        assert_eq!(v.name, "pytorch-nv");
        assert_eq!(v.id(), "python:pytorch-nv");
        assert_eq!(v.tier, ExecutionTier::FreshBoot);
        assert_eq!(v.kernel_profile, KernelProfile::GpuNvidia);
        assert!(v.needs_initrd);
        assert!(v.limits.gpu_required);
        assert!(v.limits.network_allowed);
        assert_eq!(v.limits.max_memory, 3 * 1024 * 1024 * 1024);
        assert_eq!(v.pool_min, 0);
        assert_eq!(v.pool_max, 2);
    }

    // ─── Pytorch AMD variant tests ─────────────────────────────────

    #[test]
    fn test_variant_python_pytorch_amd() {
        let v = Variant::python_pytorch_amd();
        assert_eq!(v.lang, "python");
        assert_eq!(v.name, "pytorch-amd");
        assert_eq!(v.id(), "python:pytorch-amd");
        assert_eq!(v.tier, ExecutionTier::FreshBoot);
        assert_eq!(v.kernel_profile, KernelProfile::GpuVfio);
        assert!(v.limits.gpu_required);
    }

    // ─── TinyGrad CPU variant tests ────────────────────────────────

    #[test]
    fn test_variant_python_tinygrad_cpu() {
        let v = Variant::python_tinygrad_cpu();
        assert_eq!(v.lang, "python");
        assert_eq!(v.name, "tinygrad-cpu");
        assert_eq!(v.id(), "python:tinygrad-cpu");
        assert_eq!(v.tier, ExecutionTier::KvmFork);
        assert_eq!(v.kernel_profile, KernelProfile::Base);
        assert!(v.needs_initrd);
        assert!(!v.limits.gpu_required);
        assert!(!v.limits.network_allowed);
        assert_eq!(v.limits.max_memory, 512 * 1024 * 1024);
        assert_eq!(v.pool_min, 1);
        assert_eq!(v.pool_max, 5);
    }

    // ─── TinyGrad NV variant tests ─────────────────────────────────

    #[test]
    fn test_variant_python_tinygrad_nv() {
        let v = Variant::python_tinygrad_nv();
        assert_eq!(v.lang, "python");
        assert_eq!(v.name, "tinygrad-nv");
        assert_eq!(v.id(), "python:tinygrad-nv");
        assert_eq!(v.tier, ExecutionTier::QemuVm);
        assert_eq!(v.kernel_profile, KernelProfile::GpuNvidia);
        assert!(v.needs_initrd);
        assert!(v.limits.gpu_required);
        assert!(!v.limits.network_allowed);
        assert_eq!(v.limits.max_memory, 3 * 1024 * 1024 * 1024);
        assert_eq!(v.pool_min, 0);
        assert_eq!(v.pool_max, 2);
    }

    // ─── TinyGrad AMD variant tests ────────────────────────────────

    #[test]
    fn test_variant_python_tinygrad_amd() {
        let v = Variant::python_tinygrad_amd();
        assert_eq!(v.lang, "python");
        assert_eq!(v.name, "tinygrad-amd");
        assert_eq!(v.id(), "python:tinygrad-amd");
        assert_eq!(v.tier, ExecutionTier::FreshBoot);
        assert_eq!(v.kernel_profile, KernelProfile::GpuVk);
        assert!(v.limits.gpu_required);
    }

    // ─── No-fallback tests ────────────────────────────────────────

    #[test]
    fn test_no_fallback_tinygrad_to_nv() {
        // Importing tinygrad should NOT select GPU NV variant
        let v = detect_variant("python", "import tinygrad");
        assert!(!v.limits.gpu_required, "tinygrad import must not require GPU");
        assert_eq!(v.kernel_profile, KernelProfile::Base,
            "tinygrad import must use base kernel, not gpu-nvidia");
    }

    #[test]
    fn test_no_fallback_torch_to_nv() {
        // Importing torch should NOT select GPU NV variant
        let v = detect_variant("python", "import torch");
        assert!(!v.limits.gpu_required, "torch import must not require GPU");
        assert_eq!(v.kernel_profile, KernelProfile::Base,
            "torch import must use base kernel, not gpu-nvidia");
    }

    #[test]
    fn test_no_fallback_numpy_to_tinygrad() {
        // Importing numpy should NOT select tinygrad
        let v = detect_variant("python", "import numpy");
        assert_eq!(v.name, "numpy", "numpy import must select numpy variant, not tinygrad");
    }
}
