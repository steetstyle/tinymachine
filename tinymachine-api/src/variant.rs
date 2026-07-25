//! Template variant types for sandbox selection.
//!
//! A `Variant` describes which language runtime and which feature-set
//! (``minimal``, ``numpy``, ``tinygrad``, ``pytorch``) the sandbox
//! should provide. Variants map directly to template snapshots on disk.
//!
//! # Examples
//!
//! ```
//! use tinymachine_api::Variant;
//!
//! let v = Variant::new("python", "minimal", "base");
//! assert_eq!(v.lang, "python");
//! assert_eq!(v.variant, "minimal");
//! assert_eq!(v.kernel_profile, "base");
//!
//! // Auto-detect variant from Python imports (returns Option)
//! let code = "\
//! import numpy
//! x = np.array([1])";
//! let v = Variant::detect("python", code).unwrap();
//! assert_eq!(v.variant, "numpy");
//! ```

use serde::{Deserialize, Serialize};
use tinymachine_ir::IrParser;

/// Describes a language runtime variant for sandbox execution.
///
/// Each variant corresponds to a specific template snapshot on disk,
/// with its own initrd, runtime, and optional GPU profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Variant {
    /// Language name, e.g. ``"python"``, ``"node"``, ``"wasm"``.
    pub lang: String,
    /// Variant name, e.g. ``"minimal"``, ``"numpy"``, ``"tinygrad"``, ``"pytorch"``.
    pub variant: String,
    /// Kernel profile, e.g. ``"base"``, ``"gpu-vk"``, ``"gpu-vfio"``.
    pub kernel_profile: String,
}

// ─── Known Python imports → variant name mapping ──────────────────────
// Maps Python import names to variant names (kernel profile is NOT stored here —
// it comes from layer metadata at runtime).
const IMPORT_VARIANTS: &[(&[&str], &str)] = &[
    (&["torch", "torchvision", "torchaudio"], "pytorch"),
    (&["tinygrad", "extra"], "tinygrad"),
    (&["numpy", "scipy", "pandas", "matplotlib"], "numpy"),
];

impl Variant {
    /// Create a new `Variant` with the given language, variant name, and
    /// kernel profile. All three are required — no default kernel profile.
    ///
    /// # Examples
    ///
    /// ```
    /// use tinymachine_api::Variant;
    ///
    /// let v = Variant::new("python", "pytorch", "gpu-vfio");
    /// assert_eq!(v.kernel_profile, "gpu-vfio");
    /// ```
    pub fn new(lang: &str, variant: &str, kernel_profile: &str) -> Self {
        Self {
            lang: lang.to_string(),
            variant: variant.to_string(),
            kernel_profile: kernel_profile.to_string(),
        }
    }

    /// Detect the appropriate variant from Python code using AST-level import analysis.
    ///
    /// Only works for Python code (returns `None` for other languages).
    /// Returns `None` when no known imports are detected.
    /// The kernel profile must be provided separately (from layer registry metadata).
    ///
    /// Uses `tinymachine_ir` to parse the code and extract imports
    /// from the AST. This eliminates false positives from import-like text
    /// inside string literals.
    ///
    /// # Examples
    ///
    /// ```
    /// use tinymachine_api::Variant;
    ///
    /// // torch import → pytorch variant
    /// let code = "\
    /// import torch
    /// x = torch.randn(3)";
    /// let v = Variant::detect("python", code).unwrap();
    /// assert_eq!(v.variant, "pytorch");
    ///
    /// // no special imports → None (no fallback variant)
    /// let v = Variant::detect("python", "print('hello')");
    /// assert!(v.is_none());
    ///
    /// // node code → None (not Python)
    /// let v = Variant::detect("node", "console.log('hi')");
    /// assert!(v.is_none());
    /// ```
    pub fn detect(lang: &str, code: &str) -> Option<Self> {
        let lang = lang.trim().to_lowercase();

        // Only Python code can be analyzed for variant detection
        if lang != "python" {
            return None;
        }

        // Extract imports using AST-level parsing (no string matching)
        let imports: Vec<String> = extract_imports(code);

        // Score each variant by number of matched imports
        let mut best_variant: Option<&str> = None;
        let mut best_score = 0usize;

        for &(pkgs, variant) in IMPORT_VARIANTS.iter() {
            let score = pkgs
                .iter()
                .filter(|pkg| imports.iter().any(|i| i == *pkg))
                .count();
            if score > best_score {
                best_score = score;
                best_variant = Some(variant);
            }
        }

        // Return None when no imports match (no fallback to "minimal")
        best_variant.map(|v| Self::new(&lang, v, "base"))
    }

    /// Returns the template storage path segment ``"{lang}/{variant}"``.
    pub fn path_segment(&self) -> String {
        format!("{}/{}", self.lang, self.variant)
    }

    /// Returns ``true`` if this variant requires GPU hardware.
    pub fn requires_gpu(&self) -> bool {
        self.kernel_profile == "gpu-vk"
            || self.kernel_profile == "gpu-vfio"
            || self.kernel_profile == "gpu-nvidia"
    }

    /// Returns the execution tier implied by this variant.
    ///
    /// Uses kernel profile string only — no hardcoded variant name checks.
    ///
    /// - ``"wasm"`` language → ``Wasm``  
    /// - Any GPU profile (``gpu-vfio``, ``gpu-nvidia``, ``gpu-vk``) → ``FreshBoot`` (direct KVM)  
    /// - Everything else → ``KvmFork``  
    ///
    /// Callers can override the tier if a variant supports a lighter backend.
    pub fn default_tier(&self) -> crate::ExecutionTier {
        if self.lang == "wasm" {
            crate::ExecutionTier::Wasm
        } else if self.requires_gpu() {
            // All GPU variants use FreshBootBackend (direct KVM with VFIO).
            // FreshBootBackend pre-assigns BAR addresses via KVM EPT, avoiding
            // VFIO_MAP_DMA entirely. This works regardless of dma_mask_bits
            // (kernel BZ 217237) because VFIO DMA mapping is not used for BARs
            // in direct KVM mode — only KVM_SET_USER_MEMORY_REGION (EPT).
            //
            // QemuBackend is NOT used for GPU variants because QEMU's VFIO
            // path requires x-no-mmap=on when dma_mask_bits=32 (trapped MMIO,
            // ~10μs/access vs ~10ns native EPT). See qemu_backend.rs for the
            // QEMU fallback path (available via ExecutionTier::QemuVm).
            crate::ExecutionTier::FreshBoot
        } else {
            crate::ExecutionTier::KvmFork
        }
    }
}

/// Extract the set of imported module names from Python code using
/// AST-level parsing via `tinymachine_ir`. Returns the top-level package name
/// for each import (e.g. ``"torch"`` for ``import torch.nn as nn``).
fn extract_imports(code: &str) -> Vec<String> {
    match tinymachine_ir::python::PythonParser::parse(code) {
        Ok(prog) => {
            let mut imports = Vec::new();
            for stmt in &prog.body {
                match stmt {
                    tinymachine_ir::IrStmt::Import { module, alias: _ } => {
                        // module is e.g. "torch.nn" — take top-level
                        let top = module.split('.').next().unwrap_or(module);
                        if !imports.iter().any(|s| s == top) {
                            imports.push(top.to_string());
                        }
                    }
                    tinymachine_ir::IrStmt::ImportFrom { module, symbol: _, alias: _ } => {
                        let top = module.split('.').next().unwrap_or(module);
                        if !imports.iter().any(|s| s == top) {
                            imports.push(top.to_string());
                        }
                    }
                    _ => {}
                }
            }
            imports
        }
        Err(_) => {
            // Parse error — return empty, fall back to minimal
            Vec::new()
        }
    }
}

impl std::fmt::Display for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.lang, self.variant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_variant_minimal() {
        let v = Variant::new("python", "minimal", "base");
        assert_eq!(v.lang, "python");
        assert_eq!(v.variant, "minimal");
        assert_eq!(v.kernel_profile, "base");
    }

    #[test]
    fn test_new_variant_pytorch() {
        let v = Variant::new("python", "pytorch", "gpu-vfio");
        assert_eq!(v.kernel_profile, "gpu-vfio");
        assert!(v.requires_gpu());
    }

    #[test]
    fn test_new_variant_tinygrad() {
        let v = Variant::new("python", "tinygrad", "gpu-vk");
        assert_eq!(v.kernel_profile, "gpu-vk");
        assert!(v.requires_gpu());
    }

    #[test]
    fn test_new_variant_node() {
        let v = Variant::new("node", "minimal", "base");
        assert_eq!(v.kernel_profile, "base");
        assert!(!v.requires_gpu());
    }

    #[test]
    fn test_detect_pytorch() {
        let v = Variant::detect(
            "python",
            "import torch\nimport torch.nn as nn\nx = torch.tensor([1])",
        );
        assert_eq!(v.unwrap().variant, "pytorch");
    }

    #[test]
    fn test_detect_tinygrad() {
        let v = Variant::detect("python", "from tinygrad import Tensor\nx = Tensor([1])");
        assert_eq!(v.unwrap().variant, "tinygrad");
    }

    #[test]
    fn test_detect_numpy() {
        let v = Variant::detect("python", "import numpy as np\nimport pandas\na = np.array([1])");
        assert_eq!(v.unwrap().variant, "numpy");
    }

    #[test]
    fn test_detect_minimal_no_fallback() {
        // No known imports → None (no implicit "minimal" fallback)
        let v = Variant::detect("python", "print('hello world')");
        assert!(v.is_none());
    }

    #[test]
    fn test_detect_node_no_fallback() {
        // Non-Python language → None
        let v = Variant::detect("node", "console.log('hi')");
        assert!(v.is_none());
    }

    #[test]
    fn test_default_tier() {
        assert_eq!(
            Variant::new("wasm", "minimal", "base").default_tier(),
            crate::ExecutionTier::Wasm
        );
        assert_eq!(
            Variant::new("python", "minimal", "base").default_tier(),
            crate::ExecutionTier::KvmFork
        );
        assert_eq!(
            Variant::new("python", "tinygrad", "gpu-vk").default_tier(),
            crate::ExecutionTier::FreshBoot  // all GPU → direct KVM
        );
        assert_eq!(
            Variant::new("python", "tinygrad-nv", "gpu-vfio").default_tier(),
            crate::ExecutionTier::FreshBoot  // all GPU → direct KVM (was QemuVm)
        );
        assert_eq!(
            Variant::new("python", "pytorch", "gpu-vfio").default_tier(),
            crate::ExecutionTier::FreshBoot  // all GPU → direct KVM (was QemuVm)
        );
    }

    #[test]
    fn test_display() {
        let v = Variant::new("python", "minimal", "base");
        assert_eq!(v.to_string(), "python:minimal");
    }

    #[test]
    fn test_path_segment() {
        let v = Variant::new("python", "numpy", "base");
        assert_eq!(v.path_segment(), "python/numpy");
    }

    #[test]
    fn test_detect_from_import_variant() {
        // "from X import Y" syntax
        let v = Variant::detect("python", "from torch import nn");
        assert_eq!(v.unwrap().variant, "pytorch");
    }

    #[test]
    fn test_detect_scipy_as_numpy() {
        let v = Variant::detect("python", "import scipy\nimport numpy");
        // Both scipy and numpy map to "numpy" variant
        assert_eq!(v.unwrap().variant, "numpy");
    }
}
