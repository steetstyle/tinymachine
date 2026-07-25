//! Layer Registry — metadata management for the Layer Composition System
//!
//! Manages the index of pre-built layers (base, runtime, pip, npm, etc.)
//! and resolves code imports (e.g., `import numpy`) to layer references.
//!
//! # Architecture
//!
//! Each installed layer is a `.cpio.zst` archive stored at:
    //! `~/.tinymachine/layers/<type>/<name>/<version>/layer.cpio.zst`
    //!
    //! The registry index is at `~/.tinymachine/layers/registry.toml`.
//!
//! # Safety
//! This module contains no unsafe code. All I/O uses standard library
//! filesystem operations.

use std::collections::HashMap;

#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(test)]
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error Types ──────────────────────────────────────────────────────

/// Errors from layer registry operations
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(String),
    #[error("Layer not found: {type_name}/{name}@{version}")]
    LayerNotFound {
        type_name: String,
        name: String,
        version: String,
    },
    #[error("Version not found for {name}: {constraint}")]
    VersionNotFound {
        name: String,
        constraint: String,
    },
    #[error("Import not mapped: {import_name} (lang={lang})")]
    ImportNotMapped {
        import_name: String,
        lang: String,
    },
    #[error("Composition error: {0}")]
    Composition(String),
    #[error("Conflict: {0}")]
    Conflict(String),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

// ─── Core Data Types ─────────────────────────────────────────────────

/// Layer type identifies the package manager / build method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum LayerType {
    Base,
    Runtime,
    Pip,
    Npm,
    Cargo,
    Apt,
    Source,
}

impl LayerType {
    /// Get the directory name for this layer type
    pub fn dirname(&self) -> &'static str {
        match self {
            LayerType::Base => "base",
            LayerType::Runtime => "runtime",
            LayerType::Pip => "pip",
            LayerType::Npm => "npm",
            LayerType::Cargo => "cargo",
            LayerType::Apt => "apt",
            LayerType::Source => "source",
        }
    }

    /// Parse a directory name to LayerType
    pub fn from_dirname(s: &str) -> Option<Self> {
        match s {
            "base" => Some(LayerType::Base),
            "runtime" => Some(LayerType::Runtime),
            "pip" => Some(LayerType::Pip),
            "npm" => Some(LayerType::Npm),
            "cargo" => Some(LayerType::Cargo),
            "apt" => Some(LayerType::Apt),
            "source" => Some(LayerType::Source),
            _ => None,
        }
    }
}

impl std::fmt::Display for LayerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dirname())
    }
}

/// Metadata for a single layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerMetadata {
    pub layer_type: LayerType,
    pub name: String,
    pub version: String,
    /// Import names this layer provides (e.g., numpy → ["numpy"])
    #[serde(default)]
    pub provides: Vec<String>,
    /// Runtime this layer requires (e.g., "python", "node")
    #[serde(default)]
    pub requires_runtime: Option<String>,
    /// Uncompressed size in bytes
    pub size_bytes: u64,
    /// Compressed size in bytes
    pub compressed_size: u64,
    /// SHA-256 hash of the layer file
    pub hash: String,
    /// Optional kernel profile override (e.g., "gpu-vfio")
    #[serde(default)]
    pub kernel_profile: Option<String>,
    /// Recommended memory in MB
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    /// Interpreter binary path (e.g., "/usr/bin/python3")
    #[serde(default)]
    pub interpreter: Option<String>,
    /// Interpreter CLI arguments (e.g., ["-c"])
    #[serde(default)]
    pub interpreter_args: Vec<String>,
    /// Whether this version is the default ("latest")
    #[serde(default)]
    pub default: bool,
}

fn default_memory_mb() -> u64 { 64 }

/// A resolved reference to a specific layer file on disk
#[derive(Debug, Clone)]
pub struct LayerRef {
    pub layer_type: LayerType,
    pub name: String,
    pub version: String,
    /// Absolute path to the .cpio.zst file
    pub layer_path: PathBuf,
    /// SHA-256 hash of the layer file
    pub hash: String,
}

impl LayerRef {
    /// Display string like "pip/numpy@1.26.4"
    pub fn display(&self) -> String {
        format!("{}/{}@{}", self.layer_type.dirname(), self.name, self.version)
    }
}

/// Command configuration for the VM init process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdConfig {
    /// Interpreter binary (e.g., "/usr/bin/python3")
    pub interpreter: Option<String>,
    /// Interpreter arguments (e.g., ["-c"])
    #[serde(default)]
    pub args: Vec<String>,
    /// Direct binary to exec (e.g., "/app/myapp")
    pub exec: Option<String>,
}

// No Default impl for CmdConfig — every field must be set explicitly.
// Interpreter, args and exec come from layer metadata or explicit config.

/// A complete composition plan describing a composed initrd
#[derive(Debug, Clone)]
pub struct CompositionPlan {
    /// Ordered list of layers (base first)
    pub layers: Vec<LayerRef>,
    /// Kernel profile (e.g., "base", "gpu-vfio")
    pub kernel_profile: String,
    /// Total memory needed in MB
    pub memory_mb: u64,
    /// Command configuration for the init process
    pub cmd_config: CmdConfig,
    /// Deterministic composition key (SHA-256)
    pub composition_key: String,
}

// ─── Version Constraints ──────────────────────────────────────────────

/// A version constraint from pragma, CLI, or implicit latest
#[derive(Debug, Clone)]
pub enum VersionConstraint {
    Exact(String),
    Latest,
}

impl std::fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionConstraint::Exact(v) => write!(f, "{v}"),
            VersionConstraint::Latest => write!(f, "latest"),
        }
    }
}

/// Parse a version constraint string ("name@version" or "name")
pub fn parse_version_constraint(s: &str) -> (String, VersionConstraint) {
    if let Some((name, ver)) = s.split_once('@') {
        (name.to_string(), VersionConstraint::Exact(ver.to_string()))
    } else {
        (s.to_string(), VersionConstraint::Latest)
    }
}

/// Parse `# tinymachine:dep name@version` pragmas from code
pub fn parse_pragmas(code: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    for line in code.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# tinymachine:dep ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            for part in parts {
                let (name, ver) = parse_version_constraint(part);
                let version_str = match &ver {
                    VersionConstraint::Exact(v) => v.clone(),
                    VersionConstraint::Latest => "latest".into(),
                };
                deps.push((name, version_str));
            }
        }
    }
    deps
}

/// Extract import names from code (Python + basic JS)
pub fn extract_imports(lang: &str, code: &str) -> Vec<String> {
    match lang {
        "python" => extract_python_imports(code),
        "node" | "javascript" => extract_js_requires(code),
        _ => Vec::new(),
    }
}

fn extract_python_imports(code: &str) -> Vec<String> {
    let mut imports = Vec::new();
    for line in code.lines() {
        let trimmed = line.trim();
        // Match: import X, import X as Y, import X.Y.Z
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let parts: Vec<&str> = rest.split(',').flat_map(|s| s.split_whitespace()).collect();
            for part in parts {
                if part == "as" || part.starts_with('#') {
                    continue;
                }
                let module = part.split('.').next().unwrap_or(part).trim();
                if !module.is_empty() && module != "as" {
                    imports.push(module.to_string());
                }
            }
        }
        // Match: from X import Y
        if let Some(rest) = trimmed.strip_prefix("from ") {
            if let Some(module) = rest.split_whitespace().next() {
                let module = module.split('.').next().unwrap_or(module);
                if !module.is_empty() {
                    imports.push(module.to_string());
                }
            }
        }
    }
    imports
}

fn extract_js_requires(code: &str) -> Vec<String> {
    let mut imports = Vec::new();
    for line in code.lines() {
        let trimmed = line.trim();
        // Match: require('X')
        if let Some(rest) = trimmed.find("require(") {
            let after = &trimmed[rest..];
            if let Some(start) = after.find('\'') {
                if let Some(end) = after[start+1..].find('\'') {
                    let module = &after[start+1..start+1+end];
                    if !module.starts_with('.') && !module.starts_with('/') {
                        imports.push(module.to_string());
                    }
                }
            }
        }
        // Match: import X from 'Y' (ES module)
        if let Some(rest) = trimmed.strip_prefix("import ") {
            if let Some(from_pos) = rest.find(" from ") {
                let after_from = &rest[from_pos + 6..];
                let module = after_from.trim().trim_matches('\'').trim_matches('"');
                if !module.is_empty() && module != "from" {
                    imports.push(module.to_string());
                }
            }
        }
    }
    imports
}

// ─── Hardcoded Import-to-Layer Mapping (DEPRECATED) ──────────────────
// These functions are no longer used by `resolve()` / `resolve_import()`.
// The new data-driven approach reads from the registry's `provides` field
// instead. These are kept for backward compatibility with external callers.
//
// To add a new import→layer mapping, add a layer to the registry with
// the appropriate `provides` field instead of editing these functions.

/// Built-in import name to layer mapping — DEPRECATED.
/// Use `LayerRegistry::find_layer_by_import()` instead.
#[allow(dead_code)]
pub fn import_to_pip_layer(import_name: &str) -> Option<&'static str> {
    match import_name {
        "numpy" | "scipy" | "pandas" | "matplotlib" => Some("numpy"),
        "tinygrad" | "extra" => Some("tinygrad"),
        "torch" | "torchvision" | "torchaudio" => Some("pytorch"),
        "requests" | "urllib3" => Some("requests"),
        "flask" | "fastapi" => Some("flask"),
        "pillow" | "PIL" => Some("pillow"),
        "transformers" | "sentencepiece" => Some("transformers"),
        "jax" | "flax" => Some("jax"),
        _ => None,
    }
}

// ─── Layer Registry ───────────────────────────────────────────────────

/// Layer Registry — manages layer metadata and resolves imports
#[derive(Debug, Clone)]
pub struct LayerRegistry {
    /// Base path for layers (~/.tinymachine/layers/)
    layers_path: PathBuf,
    /// Index of all installed layers: type/name → version → metadata
    index: HashMap<String, Vec<LayerMetadata>>,
}

impl LayerRegistry {
    /// Load registry from the default path (~/.tinymachine/layers/registry.toml)
    pub fn load() -> Result<Self> {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|e| RegistryError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound, format!("HOME not set: {e}")
            )))?;
        let layers_path = home.join(".tinymachine").join("layers");
        Self::load_from(&layers_path)
    }

    /// Load registry from a specific base path
    pub fn load_from(layers_path: &Path) -> Result<Self> {
        let registry_file = layers_path.join("registry.toml");
        let mut registry = Self {
            layers_path: layers_path.to_path_buf(),
            index: HashMap::new(),
        };

        if registry_file.exists() {
            let content = std::fs::read_to_string(&registry_file)
                .map_err(RegistryError::Io)?;
            registry.parse_registry_toml(&content)?;
        }

        Ok(registry)
    }

    /// Save registry to disk
    pub fn save(&self) -> Result<()> {
        let registry_file = self.layers_path.join("registry.toml");
        std::fs::create_dir_all(&self.layers_path)
            .map_err(RegistryError::Io)?;
        let toml_content = self.serialize_registry_toml();
        std::fs::write(&registry_file, toml_content)
            .map_err(RegistryError::Io)?;
        Ok(())
    }

    /// Scan the layers directory and rebuild the index from on-disk metadata
    pub fn scan_layers(&mut self) -> Result<()> {
        self.index.clear();
        if !self.layers_path.exists() {
            return Ok(());
        }

        let mut reader = std::fs::read_dir(&self.layers_path)
            .map_err(RegistryError::Io)?;
        while let Some(entry) = reader.next().transpose()? {
            let entry_path = entry.path();
            if !entry_path.is_dir() { continue; }
            let type_name = entry.file_name().to_string_lossy().to_string();
            if type_name.starts_with('.') { continue; }

            // Read type directory (pip, npm, runtime, etc.)
            let mut type_reader = std::fs::read_dir(&entry_path)
                .map_err(RegistryError::Io)?;
            while let Some(type_entry) = type_reader.next().transpose()? {
                let name_path = type_entry.path();
                if !name_path.is_dir() { continue; }
                let layer_name = type_entry.file_name().to_string_lossy().to_string();
                if layer_name.starts_with('.') { continue; }

                // Read version directories
                let mut ver_reader = std::fs::read_dir(&name_path)
                    .map_err(RegistryError::Io)?;
                while let Some(ver_entry) = ver_reader.next().transpose()? {
                    let ver_path = ver_entry.path();
                    if !ver_path.is_dir() { continue; }
                    let version = ver_entry.file_name().to_string_lossy().to_string();
                    if version.starts_with('.') { continue; }

                    // Check for metadata
                    let meta_path = ver_path.join("meta.json");
                    let layer_file = ver_path.join("layer.cpio.zst");

                    if !layer_file.exists() { continue; }

                    let meta = if meta_path.exists() {
                        let content = std::fs::read_to_string(&meta_path)
                            .map_err(RegistryError::Io)?;
                        serde_json::from_str::<LayerMetadata>(&content)
                            .map_err(|e| RegistryError::TomlParse(e.to_string()))?
                    } else {
                        // Create minimal metadata from filesystem
                        let file_size = std::fs::metadata(&layer_file)
                            .map_err(RegistryError::Io)?.len();
                        LayerMetadata {
                            layer_type: LayerType::from_dirname(&type_name)
                                .unwrap_or(LayerType::Source),
                            name: layer_name.clone(),
                            version: version.clone(),
                            provides: Vec::new(),
                            requires_runtime: None,
                            size_bytes: file_size * 3, // estimate
                            compressed_size: file_size,
                            hash: String::new(),
                            kernel_profile: None,
                            memory_mb: default_memory_mb(),
                            interpreter: None,
                            interpreter_args: Vec::new(),
                            default: false,
                        }
                    };

                    self.add_layer_raw(meta);
                }
            }
        }
        Ok(())
    }

    fn add_layer_raw(&mut self, meta: LayerMetadata) {
        let key = format!("{}/{}", meta.layer_type.dirname(), meta.name);
        self.index.entry(key).or_default().push(meta);
    }

    /// Parse the legacy registry.toml format
    fn parse_registry_toml(&mut self, content: &str) -> Result<()> {
        // Simple TOML parser for the layers format
        // Format:
        //   ["pip/numpy"]
        //   version = "1.26.4"
        //   hash = "sha256:..."
        //   path = "..."
        let mut current_section = String::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len()-1].to_string();
            } else if line.starts_with("version") && !current_section.is_empty() {
                // Parse: version = "..."
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let val = parts[1].trim().trim_matches('"');
                    // Extract type/name from section
                    if let Some((type_name, name)) = current_section.split_once('/') {
                        if let Some(lt) = LayerType::from_dirname(type_name) {
                            // Try to find and update metadata, or create stub
                            self.add_layer_raw(LayerMetadata {
                                layer_type: lt,
                                name: name.to_string(),
                                version: val.to_string(),
                                provides: Vec::new(),
                                requires_runtime: None,
                                size_bytes: 0,
                                compressed_size: 0,
                                hash: String::new(),
                                kernel_profile: None,
                                memory_mb: default_memory_mb(),
                                interpreter: None,
                                interpreter_args: Vec::new(),
                                default: false,
                            });
                        }
                    } else {
                        // No type prefix — try to infer from name
                        self.add_layer_raw(LayerMetadata {
                            layer_type: LayerType::Runtime,
                            name: current_section.clone(),
                            version: val.to_string(),
                            provides: Vec::new(),
                            requires_runtime: None,
                            size_bytes: 0,
                            compressed_size: 0,
                            hash: String::new(),
                            kernel_profile: None,
                            memory_mb: default_memory_mb(),
                            interpreter: None,
                            interpreter_args: Vec::new(),
                            default: false,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Serialize registry to TOML format
    fn serialize_registry_toml(&self) -> String {
        let mut lines = Vec::new();
        lines.push("# TinyMachine Layer Registry".to_string());
        lines.push("# Auto-generated by layer_registry.rs".to_string());
        lines.push(String::new());

        let mut sections: Vec<(&str, &LayerMetadata)> = Vec::new();
        for (key, metas) in &self.index {
            for meta in metas {
                sections.push((key.as_str(), meta));
            }
        }
        sections.sort_by_key(|(k, m)| (k.to_string(), m.version.clone()));

        for (section_key, meta) in sections {
            lines.push(format!("[\"{}\"]", section_key));
            lines.push(format!("version = \"{}\"", meta.version));
            lines.push(format!("hash = \"{}\"", meta.hash));
            if !meta.provides.is_empty() {
                let provides = meta.provides.iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!("provides = [{}]", provides));
            }
            if let Some(ref rt) = meta.requires_runtime {
                lines.push(format!("requires_runtime = \"{rt}\""));
            }
            if let Some(ref kp) = meta.kernel_profile {
                lines.push(format!("kernel_profile = \"{kp}\""));
            }
            if meta.default {
                lines.push("default = true".to_string());
            }
            lines.push(String::new());
        }

        lines.join("\n")
    }

    /// Get metadata for a specific layer
    pub fn get_layer(&self, layer_type: &LayerType, name: &str, version: &str) -> Result<LayerRef> {
        let key = format!("{}/{}", layer_type.dirname(), name);
        let metas = self.index.get(&key)
            .ok_or_else(|| RegistryError::LayerNotFound {
                type_name: layer_type.dirname().to_string(),
                name: name.to_string(),
                version: version.to_string(),
            })?;

        let meta = metas.iter()
            .find(|m| m.version == version)
            .ok_or_else(|| RegistryError::LayerNotFound {
                type_name: layer_type.dirname().to_string(),
                name: name.to_string(),
                version: version.to_string(),
            })?;

        let layer_path = self.layers_path
            .join(layer_type.dirname())
            .join(name)
            .join(version)
            .join("layer.cpio.zst");

        Ok(LayerRef {
            layer_type: layer_type.clone(),
            name: name.to_string(),
            version: version.to_string(),
            layer_path,
            hash: meta.hash.clone(),
        })
    }

    /// Resolve a version constraint to an actual version
    pub fn resolve_version(&self, name: &str, constraint: &VersionConstraint) -> Result<String> {
        match constraint {
            VersionConstraint::Exact(v) => Ok(v.clone()),
            VersionConstraint::Latest => {
                // Find the default version across all types
                for meta in self.index.values().flatten() {
                    if meta.name == name && meta.default {
                        return Ok(meta.version.clone());
                    }
                }
                // No default found, try to find any version
                for meta in self.index.values().flatten() {
                    if meta.name == name {
                        return Ok(meta.version.clone());
                    }
                }
                Err(RegistryError::VersionNotFound {
                    name: name.to_string(),
                    constraint: "latest".to_string(),
                })
            }
        }
    }

    /// Find a layer by import name using the registry's `provides` field.
    /// Scans all layers to find one whose `provides` list includes `import_name`.
    /// This replaces the hardcoded `import_to_pip_layer()` / `import_to_npm_layer()` functions.
    fn find_layer_by_import(&self, lang: &str, import_name: &str) -> Result<(LayerType, String)> {
        let target_type = match lang {
            "python" => LayerType::Pip,
            "node" | "javascript" => LayerType::Npm,
            _ => return Err(RegistryError::ImportNotMapped {
                import_name: import_name.to_string(),
                lang: lang.to_string(),
            }),
        };

        // Scan all layers for one whose `provides` matches the import name
        for metas in self.index.values() {
            for meta in metas {
                if meta.layer_type == target_type && meta.provides.iter().any(|p| p == import_name) {
                    return Ok((target_type, meta.name.clone()));
                }
            }
        }

        Err(RegistryError::ImportNotMapped {
            import_name: import_name.to_string(),
            lang: lang.to_string(),
        })
    }

    /// Resolve a single import name to a layer reference.
    /// Uses the registry's `provides` field (data-driven, not hardcoded).
    pub fn resolve_import(&self, lang: &str, import_name: &str, version: &VersionConstraint) -> Result<LayerRef> {
        let (layer_type, layer_name) = self.find_layer_by_import(lang, import_name)?;
        let resolved_version = self.resolve_version(&layer_name, version)?;
        self.get_layer(&layer_type, &layer_name, &resolved_version)
    }

    /// Full resolution: lang + code + explicit deps → CompositionPlan
    pub fn resolve(&self, lang: &str, code: &str, explicit_deps: &[(String, String)]) -> Result<CompositionPlan> {
        let mut all_layer_refs: Vec<LayerRef> = Vec::new();

        // 1. Always add base layer
        let base_ref = self.get_layer(&LayerType::Base, "base", "v1")?;
        all_layer_refs.push(base_ref);

        // 2. Determine runtime layer from language.
        //    Fails hard if the runtime is not in the registry — no silent fallback.
        let runtime_name = match lang {
            "python" | "wasm" => "python",
            "node" | "javascript" => "node",
            _ => "python",
        };
        let runtime_ver = self.resolve_version(runtime_name, &VersionConstraint::Latest)?;
        let runtime_ref = self.get_layer(&LayerType::Runtime, runtime_name, &runtime_ver)?;
        all_layer_refs.push(runtime_ref);

        // 3. Parse pragmas from code (# tinymachine:dep name@version)
        let pragma_deps = parse_pragmas(code);
        let mut all_explicit_deps: Vec<(String, String)> = explicit_deps.to_vec();
        for (name, version) in pragma_deps {
            if !all_explicit_deps.iter().any(|(n, _)| n == &name) {
                all_explicit_deps.push((name, version));
            }
        }

        // 4. Parse implicit imports from code
        let implicit_imports = extract_imports(lang, code);
        let mut resolved_import_names: Vec<String> = Vec::new();

        for import_name in &implicit_imports {
            // Check if already resolved via explicit deps or pragmas
            if all_explicit_deps.iter().any(|(name, _)| name == import_name) {
                continue;
            }
            if let Ok(layer_ref) = self.resolve_import(lang, import_name, &VersionConstraint::Latest) {
                let display = layer_ref.display();
                if !all_layer_refs.iter().any(|r| r.display() == display) {
                    resolved_import_names.push(import_name.clone());
                    all_layer_refs.push(layer_ref);
                }
            }
        }

        // 5. Add explicit deps (CLI --dep flags + pragma deps).
        //    These MUST be resolvable — fail hard instead of silently skipping.
        //    If a user explicitly requests --dep pytorch@2.0.0, they get an error
        //    if that layer doesn't exist, not a silent no-op.
        for (name, version) in &all_explicit_deps {
            let layer_ref = self.resolve_import(lang, name, &VersionConstraint::Exact(version.clone()))?;
            let display = layer_ref.display();
            if !all_layer_refs.iter().any(|r| r.display() == display) {
                resolved_import_names.push(name.clone());
                all_layer_refs.push(layer_ref);
            }
        }

        // 6. Determine kernel profile from layer metadata (data-driven, not hardcoded)
        let kernel_profile = self.kernel_profile_from_layers(&all_layer_refs);

        // 7. Calculate memory from layer metadata
        let memory_mb = self.memory_mb_from_layers(&all_layer_refs);

        // 8. Determine cmd_config from runtime layer metadata (no fallback)
        let cmd_config = self.cmd_config_from_runtime(runtime_name)
            .ok_or_else(|| RegistryError::Composition(
                format!("no runtime layer found for '{runtime_name}' — cannot determine cmd_config")
            ))?;

        // 9. Compute composition key
        fn hash_prefix(h: &str) -> &str {
            if h.len() >= 12 { &h[..12] } else { h }
        }
        let key_input = format!("{}:{}",
            kernel_profile,
            all_layer_refs.iter().map(|r| format!("{}@{}:{}", r.name, r.version, hash_prefix(&r.hash))).collect::<Vec<_>>().join(",")
        );
        let composition_key = format!("compose:{}", blake3::hash(key_input.as_bytes()).to_hex());

        Ok(CompositionPlan {
            layers: all_layer_refs,
            kernel_profile,
            memory_mb,
            cmd_config,
            composition_key,
        })
    }

    /// Look up full `LayerMetadata` for a given `LayerRef`.
    /// Returns `None` if the layer is not in the registry (e.g., synthetic layers).
    fn metadata_for_layer(&self, layer_ref: &LayerRef) -> Option<&LayerMetadata> {
        let key = format!("{}/{}", layer_ref.layer_type.dirname(), layer_ref.name);
        self.index.get(&key).and_then(|metas| {
            metas.iter().find(|m| m.version == layer_ref.version)
        })
    }

    /// Determine kernel profile from layer metadata.
    /// Scans all layers in the composition plan and returns the first non-"base"
    /// kernel profile found. If none specified, returns "base".
    /// Data-driven replacement for the hardcoded `kernel_profile_for_layers()`.
    pub fn kernel_profile_from_layers(&self, layers: &[LayerRef]) -> String {
        for layer_ref in layers {
            if let Some(meta) = self.metadata_for_layer(layer_ref) {
                if let Some(ref kp) = meta.kernel_profile {
                    if kp != "base" {
                        return kp.clone();
                    }
                }
            }
        }
        "base".to_string()
    }

    /// Calculate memory from layer metadata.
    /// Takes the maximum `memory_mb` across all layers (minimum 128 MB).
    /// Data-driven replacement for the hardcoded `memory_mb_for_layers()`.
    pub fn memory_mb_from_layers(&self, layers: &[LayerRef]) -> u64 {
        let mut mem = 128u64;
        for layer_ref in layers {
            if let Some(meta) = self.metadata_for_layer(layer_ref) {
                mem = mem.max(meta.memory_mb);
            }
        }
        mem
    }

    /// Determine `CmdConfig` from the runtime layer's metadata.
    /// Uses `interpreter` and `interpreter_args` from the metadata.
    /// Returns `None` when no runtime layer is found (no fallback defaults).
    pub fn cmd_config_from_runtime(&self, runtime_name: &str) -> Option<CmdConfig> {
        let key = format!("{}/{runtime_name}", LayerType::Runtime.dirname());
        let metas = self.index.get(&key);
        let meta = metas.and_then(|ms| {
            ms.iter().find(|m| m.default)
                .or_else(|| ms.first())
        });
        meta.map(|m| CmdConfig {
            interpreter: m.interpreter.clone(),
            args: m.interpreter_args.clone(),
            exec: None,
        })
    }

    /// Add a layer to the registry
    pub fn add_layer(&mut self, meta: LayerMetadata) -> Result<()> {
        let key = format!("{}/{}", meta.layer_type.dirname(), meta.name);
        self.index.entry(key).or_default().push(meta);
        Ok(())
    }

    /// Remove a layer from the registry
    pub fn remove_layer(&mut self, layer_type: &LayerType, name: &str, version: &str) -> Result<()> {
        let key = format!("{}/{}", layer_type.dirname(), name);
        if let Some(metas) = self.index.get_mut(&key) {
            metas.retain(|m| m.version != version);
            if metas.is_empty() {
                self.index.remove(&key);
            }
            return Ok(());
        }
        Err(RegistryError::LayerNotFound {
            type_name: layer_type.dirname().to_string(),
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    /// List all layers, optionally filtered by type
    pub fn list_layers(&self, layer_type: Option<&LayerType>) -> Vec<&LayerMetadata> {
        let mut result = Vec::new();
        for metas in self.index.values() {
            for meta in metas {
                if let Some(lt) = layer_type {
                    if meta.layer_type != *lt {
                        continue;
                    }
                }
                result.push(meta);
            }
        }
        result
    }

    /// Update the "latest" version for a given layer name
    pub fn update_latest(&mut self, name: &str, version: &str) -> Result<()> {
        for metas in self.index.values_mut() {
            for meta in metas.iter_mut() {
                if meta.name == name {
                    meta.default = meta.version == version;
                }
            }
        }
        Ok(())
    }

    /// Update all layers to mark newest version as default
    pub fn update_all_latest(&mut self) -> Result<()> {
        for metas in self.index.values_mut() {
            if let Some(newest) = metas.iter()
                .max_by(|a, b| a.version.cmp(&b.version))
                .map(|m| m.version.clone())
            {
                for meta in metas.iter_mut() {
                    meta.default = meta.version == newest;
                }
            }
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_registry() -> LayerRegistry {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("tinymachine-test-registry-{counter}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create some test layers
        let base_dir = dir.join("base").join("base").join("v1");
        fs::create_dir_all(&base_dir).unwrap();
        fs::write(base_dir.join("layer.cpio.zst"), b"base-content").unwrap();
        fs::write(base_dir.join("meta.json"), r#"{"layer_type":"base","name":"base","version":"v1","size_bytes":100,"compressed_size":50,"hash":"abc","memory_mb":32,"default":true}"#).unwrap();

        let py_dir = dir.join("runtime").join("python").join("3.12.3");
        fs::create_dir_all(&py_dir).unwrap();
        fs::write(py_dir.join("layer.cpio.zst"), b"python-content").unwrap();
        fs::write(py_dir.join("meta.json"), r#"{"layer_type":"runtime","name":"python","version":"3.12.3","size_bytes":500,"compressed_size":200,"hash":"def","interpreter":"/usr/bin/python3","interpreter_args":["-c"],"memory_mb":128,"default":true}"#).unwrap();

        let np_dir = dir.join("pip").join("numpy").join("1.26.4");
        fs::create_dir_all(&np_dir).unwrap();
        fs::write(np_dir.join("layer.cpio.zst"), b"numpy-content").unwrap();
        fs::write(np_dir.join("meta.json"), r#"{"layer_type":"pip","name":"numpy","version":"1.26.4","provides":["numpy","scipy","pandas"],"requires_runtime":"python","size_bytes":1000,"compressed_size":400,"hash":"ghi","memory_mb":256,"default":true}"#).unwrap();

        let mut registry = LayerRegistry::load_from(&dir).unwrap();
        registry.scan_layers().unwrap();
        registry
    }

    #[test]
    fn test_extract_python_imports() {
        let imports = extract_imports("python", "import numpy\nfrom torch import nn\nimport pandas as pd");
        assert!(imports.contains(&"numpy".to_string()));
        assert!(imports.contains(&"torch".to_string()));
        assert!(imports.contains(&"pandas".to_string()));
    }

    #[test]
    fn test_extract_python_no_imports() {
        let imports = extract_imports("python", "print('hello')\nx = 42");
        assert!(imports.is_empty());
    }

    #[test]
    fn test_extract_js_requires() {
        let imports = extract_imports("node", "const express = require('express');\nconst _ = require('lodash');");
        assert!(imports.contains(&"express".to_string()));
        assert!(imports.contains(&"lodash".to_string()));
    }

    #[test]
    fn test_parse_pragmas() {
        let code = "\
# tinymachine:dep numpy@1.26.4
# tinymachine:dep tinygrad@latest
import numpy
";
        let deps = parse_pragmas(code);
        assert!(deps.contains(&("numpy".to_string(), "1.26.4".to_string())));
        assert!(deps.contains(&("tinygrad".to_string(), "latest".to_string())));
    }

    #[test]
    fn test_parse_version_constraint() {
        let (n, v) = parse_version_constraint("numpy@1.26.4");
        assert_eq!(n, "numpy");
        assert!(matches!(v, VersionConstraint::Exact(_)));

        let (n, v) = parse_version_constraint("numpy");
        assert_eq!(n, "numpy");
        assert!(matches!(v, VersionConstraint::Latest));
    }

    #[test]
    fn test_registry_scan_layers() {
        let registry = test_registry();
        let layers = registry.list_layers(None);
        assert!(layers.len() >= 3);
    }

    #[test]
    fn test_get_layer() {
        let registry = test_registry();
        let layer = registry.get_layer(&LayerType::Pip, "numpy", "1.26.4").unwrap();
        assert_eq!(layer.name, "numpy");
        assert_eq!(layer.version, "1.26.4");
        assert!(layer.layer_path.exists());
    }

    #[test]
    fn test_resolve_version_exact() {
        let registry = test_registry();
        let v = registry.resolve_version("numpy", &VersionConstraint::Exact("1.26.4".into())).unwrap();
        assert_eq!(v, "1.26.4");
    }

    #[test]
    fn test_resolve_version_latest() {
        let registry = test_registry();
        let v = registry.resolve_version("python", &VersionConstraint::Latest).unwrap();
        assert_eq!(v, "3.12.3");
    }

    #[test]
    fn test_resolve_import_python() {
        let registry = test_registry();
        let layer = registry.resolve_import("python", "numpy", &VersionConstraint::Latest).unwrap();
        assert_eq!(layer.name, "numpy");
    }

    #[test]
    fn test_full_resolve() {
        let registry = test_registry();
        let plan = registry.resolve("python", "import numpy", &[]).unwrap();
        assert!(!plan.layers.is_empty());
        assert!(!plan.composition_key.is_empty());
        assert_eq!(plan.cmd_config.interpreter.as_deref(), Some("/usr/bin/python3"));
    }

    #[test]
    fn test_resolve_with_explicit_deps() {
        let registry = test_registry();
        let plan = registry.resolve("python", "import tinygrad", &[("numpy".into(), "1.26.4".into())]).unwrap();
        let layer_names: Vec<&str> = plan.layers.iter().map(|l| l.name.as_str()).collect();
        assert!(layer_names.contains(&"numpy"));
    }

    #[test]
    fn test_composition_key_determinism() {
        let registry = test_registry();
        let plan1 = registry.resolve("python", "import numpy", &[]).unwrap();
        let plan2 = registry.resolve("python", "import numpy", &[]).unwrap();
        assert_eq!(plan1.composition_key, plan2.composition_key);
    }

    #[test]
    fn test_add_remove_layer() {
        let mut registry = test_registry();
        let meta = LayerMetadata {
            layer_type: LayerType::Pip,
            name: "test-pkg".into(),
            version: "1.0.0".into(),
            provides: vec!["test-pkg".into()],
            requires_runtime: Some("python".into()),
            size_bytes: 100,
            compressed_size: 50,
            hash: "test-hash".into(),
            kernel_profile: None,
            memory_mb: 64,
            interpreter: None,
            interpreter_args: vec![],
            default: false,
        };
        registry.add_layer(meta).unwrap();
        assert!(registry.get_layer(&LayerType::Pip, "test-pkg", "1.0.0").is_ok());

        registry.remove_layer(&LayerType::Pip, "test-pkg", "1.0.0").unwrap();
        assert!(registry.get_layer(&LayerType::Pip, "test-pkg", "1.0.0").is_err());
    }

    #[test]
    fn test_find_layer_by_import() {
        let registry = test_registry();
        // Provides-based lookup (not hardcoded)
        assert!(registry.find_layer_by_import("python", "numpy").is_ok());
        assert!(registry.find_layer_by_import("python", "nonexistent").is_err());

        // Test with node (npm type): create a new registry with express
        let node_registry = {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir2 = std::env::temp_dir().join(format!("tinymachine-test-registry-node-{counter}"));
            let _ = fs::remove_dir_all(&dir2);
            fs::create_dir_all(&dir2).unwrap();
            let node_dir = dir2.join("npm").join("express").join("4.19.0");
            fs::create_dir_all(&node_dir).unwrap();
            fs::write(node_dir.join("layer.cpio.zst"), b"express-content").unwrap();
            fs::write(node_dir.join("meta.json"), r#"{"layer_type":"npm","name":"express","version":"4.19.0","provides":["express"],"requires_runtime":"node","size_bytes":500,"compressed_size":200,"hash":"expresshash","interpreter":"/usr/bin/node","interpreter_args":["-e"],"memory_mb":64,"default":true}"#).unwrap();
            let mut r = LayerRegistry::load_from(&dir2).unwrap();
            r.scan_layers().unwrap();
            r
        };
        assert!(node_registry.find_layer_by_import("node", "express").is_ok());
        assert!(node_registry.find_layer_by_import("node", "nonexistent").is_err());
    }

    #[test]
    fn test_kernel_profile_from_registry() {
        let registry = test_registry();
        // Get a LayerRef for numpy and verify kernel_profile is None → "base"
        let numpy = registry.get_layer(&LayerType::Pip, "numpy", "1.26.4").unwrap();
        assert_eq!(registry.kernel_profile_from_layers(&[numpy]), "base");

        // Create a separate registry with tinygrad (has explicit gpu-vk kernel profile)
        let tg_registry = {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir2 = std::env::temp_dir().join(format!("tinymachine-test-registry-tg-{counter}"));
            let _ = fs::remove_dir_all(&dir2);
            fs::create_dir_all(&dir2).unwrap();
            // Need base + python runtime too
            let base_dir = dir2.join("base").join("base").join("v1");
            fs::create_dir_all(&base_dir).unwrap();
            fs::write(base_dir.join("layer.cpio.zst"), b"base").unwrap();
            fs::write(base_dir.join("meta.json"), r#"{"layer_type":"base","name":"base","version":"v1","size_bytes":100,"compressed_size":50,"hash":"abc","memory_mb":32,"default":true}"#).unwrap();
            let py_dir = dir2.join("runtime").join("python").join("3.12.3");
            fs::create_dir_all(&py_dir).unwrap();
            fs::write(py_dir.join("layer.cpio.zst"), b"python").unwrap();
            fs::write(py_dir.join("meta.json"), r#"{"layer_type":"runtime","name":"python","version":"3.12.3","size_bytes":500,"compressed_size":200,"hash":"def","interpreter":"/usr/bin/python3","interpreter_args":["-c"],"memory_mb":128,"default":true}"#).unwrap();
            let tg_dir = dir2.join("pip").join("tinygrad").join("0.9.0");
            fs::create_dir_all(&tg_dir).unwrap();
            fs::write(tg_dir.join("layer.cpio.zst"), b"tg-content").unwrap();
            fs::write(tg_dir.join("meta.json"), r#"{"layer_type":"pip","name":"tinygrad","version":"0.9.0","provides":["tinygrad","extra"],"requires_runtime":"python","size_bytes":5000,"compressed_size":2000,"hash":"tghash","kernel_profile":"gpu-vk","memory_mb":512,"default":true}"#).unwrap();
            let mut r = LayerRegistry::load_from(&dir2).unwrap();
            r.scan_layers().unwrap();
            r
        };
        let tg = tg_registry.get_layer(&LayerType::Pip, "tinygrad", "0.9.0").unwrap();
        assert_eq!(tg_registry.kernel_profile_from_layers(&[tg]), "gpu-vk");
    }

    #[test]
    fn test_memory_from_registry() {
        let registry = test_registry();
        let numpy = registry.get_layer(&LayerType::Pip, "numpy", "1.26.4").unwrap();
        assert!(registry.memory_mb_from_layers(&[numpy]) >= 256);
    }
}
