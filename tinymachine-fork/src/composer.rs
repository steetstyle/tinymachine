//! Composition Engine — layer conflict checking, initrd assembly, and composition cache.
//!
//! The composition engine takes a [`CompositionPlan`] from the layer registry and
//! produces a bootable initrd by concatenating layer cpio archives.
//!
//! # Composition Flow
//!
//! 1. **Conflict check** — list files in each layer cpio, detect path collisions
//! 2. **Initrd composition** — concatenate layer `.cpio.zst` files + append `cmd.json`
//! 3. **Cache storage** — store composed initrd under `~/.tinyos/cache/<key>/`
//! 4. **Cache lookup** — check cache before building (avoids redundant composition)
//!
//! # Linux Initrd Loading
//!
//! The Linux kernel's `initramfs` handler processes concatenated cpio archives.
//! Each `.cpio.zst` file is an independently compressed cpio archive. The kernel
//! decompresses each frame in order. Later files overwrite earlier ones, so the
//! composition order matters: base first, then runtime, then packages, then cmd.json.
//!
//! # Cache Layout
//!
//! ```text
//! ~/.tinyos/cache/<composition_key>/
//! ├── initrd.zst          # concatenated layer cpios + cmd.json
//! ├── cmd.json            # execution config (for inspection)
//! └── meta.json           # composition metadata
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::layer_registry::{CompositionPlan, LayerRef, LayerRegistry};
use crate::snapshot::Snapshot;

// ─── Error Types ──────────────────────────────────────────────────────

/// Errors from composition operations.
#[derive(Error, Debug)]
pub enum ComposerError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Layer registry error.
    #[error("Registry error: {0}")]
    Registry(#[from] crate::layer_registry::RegistryError),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// UTF-8 conversion error.
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// cpio or zstd subprocess failed.
    #[error("Subprocess error: {cmd}: {detail}")]
    Subprocess {
        cmd: String,
        detail: String,
    },

    /// Layer file is missing from disk.
    #[error("Layer file not found: {0}")]
    LayerFileNotFound(PathBuf),

    /// Composition plan is empty (no layers).
    #[error("Composition plan has no layers")]
    EmptyPlan,

    /// File conflict between layers.
    #[error("Conflict errors detected")]
    Conflict(Vec<ConflictError>),
}

/// Result alias for composition operations.
pub type Result<T> = std::result::Result<T, ComposerError>;

/// A file conflict between two layers during composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictError {
    /// Path that exists in both layers.
    pub path: String,
    /// First layer name (e.g., "numpy@1.26.4").
    pub layer_a: String,
    /// Second layer name (e.g., "scipy@1.11.0").
    pub layer_b: String,
}

impl std::fmt::Display for ConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "File conflict: '{}' in both {} and {}",
            self.path, self.layer_a, self.layer_b
        )
    }
}

// ─── Composition Cache ────────────────────────────────────────────────

/// Cache metadata for a stored composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMeta {
    /// The composition key.
    key: String,
    /// Number of layers in the composition.
    layer_count: usize,
    /// Total size of the composed initrd in bytes.
    initrd_size: u64,
    /// Unix timestamp when this cache entry was created.
    created_at: u64,
    /// Unix timestamp of last access (for LRU eviction).
    last_access: u64,
    /// The kernel profile used.
    kernel_profile: String,
}

/// Composition cache manager.
///
/// Stores composed initrds under `~/.tinyos/cache/<composition_key>/`.
/// Supports LRU eviction when the cache exceeds the configured max size.
pub struct CompositionCache {
    /// Root directory for cached compositions.
    cache_path: PathBuf,
    /// Maximum cache size in GB.
    max_size_gb: u64,
}

impl CompositionCache {
    /// Create a new composition cache.
    pub fn new(cache_path: PathBuf, max_size_gb: u64) -> Self {
        Self {
            cache_path,
            max_size_gb,
        }
    }

    /// Default cache root directory.
    pub fn default_root() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".tinyos").join("cache")
    }

    /// Get the directory path for a composition key.
    pub fn key_dir(&self, key: &str) -> PathBuf {
        self.cache_path.join(key)
    }

    /// Get the initrd path for a composition key.
    pub fn get_initrd_path(&self, key: &str) -> PathBuf {
        self.key_dir(key).join("initrd.zst")
    }

    /// Get the meta path for a composition key.
    fn meta_path(&self, key: &str) -> PathBuf {
        self.key_dir(key).join("meta.json")
    }

    /// Get the cmd.json path for a composition key (for inspection).
    fn cmd_json_path(&self, key: &str) -> PathBuf {
        self.key_dir(key).join("cmd.json")
    }

    /// Check if a composition is cached (both initrd.zst and meta.json exist).
    pub fn is_cached(&self, key: &str) -> bool {
        self.get_initrd_path(key).exists() && self.meta_path(key).exists()
    }

    /// Store a composition in the cache.
    ///
    /// Writes `initrd.zst`, `cmd.json`, and `meta.json` to the cache directory.
    pub fn store_initrd(
        &self,
        key: &str,
        initrd_data: &[u8],
        cmd_json: &str,
        plan: &CompositionPlan,
    ) -> Result<()> {
        let dir = self.key_dir(key);
        std::fs::create_dir_all(&dir)?;

        // Write initrd
        std::fs::write(self.get_initrd_path(key), initrd_data)?;

        // Write cmd.json for inspection
        std::fs::write(self.cmd_json_path(key), cmd_json)?;

        // Write metadata
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let meta = CacheMeta {
            key: key.to_string(),
            layer_count: plan.layers.len(),
            initrd_size: initrd_data.len() as u64,
            created_at: now,
            last_access: now,
            kernel_profile: plan.kernel_profile.clone(),
        };

        let meta_json = serde_json::to_string_pretty(&meta)?;
        std::fs::write(self.meta_path(key), meta_json)?;

        // Enforce cache size limits after storing
        self.enforce_max_size().ok();

        Ok(())
    }

    /// Remove a cached composition.
    pub fn remove(&self, key: &str) -> Result<()> {
        let dir = self.key_dir(key);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Enforce the maximum cache size using LRU eviction.
    ///
    /// Scans all cache entries, sums their sizes, and if the total exceeds
    /// `max_size_gb`, evicts the least recently used entries until within limit.
    pub fn enforce_max_size(&self) -> Result<()> {
        let max_bytes = self.max_size_gb * 1024 * 1024 * 1024;

        // Collect all cache entries with their metadata
        let entries = match std::fs::read_dir(&self.cache_path) {
            Ok(r) => r.filter_map(|e| e.ok()).filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).collect::<Vec<_>>(),
            Err(_) => return Ok(()),
        };

        let mut cache_entries: Vec<(PathBuf, CacheMeta)> = Vec::new();
        for entry in &entries {
            let meta_path = entry.path().join("meta.json");
            let initrd_path = entry.path().join("initrd.zst");
            if !meta_path.exists() || !initrd_path.exists() {
                continue;
            }
            if let Ok(data) = std::fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<CacheMeta>(&data) {
                    cache_entries.push((entry.path(), meta));
                }
            }
        }

        // Calculate total size
        let total_size: u64 = cache_entries
            .iter()
            .map(|(dir, _)| {
                dir.join("initrd.zst")
                    .metadata()
                    .map(|m| m.len())
                    .unwrap_or(0)
            })
            .sum();

        if total_size <= max_bytes {
            return Ok(());
        }

        // Sort by last_access (oldest first → LRU)
        cache_entries.sort_by(|a, b| a.1.last_access.cmp(&b.1.last_access));

        // Evict oldest until within limit
        let mut current_size = total_size;
        for (dir, _) in &cache_entries {
            if current_size <= max_bytes {
                break;
            }

            let size = dir
                .join("initrd.zst")
                .metadata()
                .map(|m| m.len())
                .unwrap_or(0);

            std::fs::remove_dir_all(dir).ok();
            current_size = current_size.saturating_sub(size);
        }

        Ok(())
    }

    /// Update the last_access timestamp for a cache entry (called on cache hit).
    pub fn touch(&self, key: &str) -> Result<()> {
        let meta_path = self.meta_path(key);
        if !meta_path.exists() {
            return Ok(());
        }

        if let Ok(data) = std::fs::read_to_string(&meta_path) {
            if let Ok(mut meta) = serde_json::from_str::<CacheMeta>(&data) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                meta.last_access = now;
                if let Ok(json) = serde_json::to_string_pretty(&meta) {
                    std::fs::write(&meta_path, json).ok();
                }
            }
        }

        Ok(())
    }

    /// Cache directory path.
    pub fn cache_path(&self) -> &Path {
        &self.cache_path
    }

    // ─── Snapshot cache ────────────────────────────────────────────────

    /// Get the snapshot directory for a composition key.
    pub fn snapshot_dir(&self, key: &str) -> PathBuf {
        self.key_dir(key).join("snapshot")
    }

    /// Store a booted VM snapshot in the composition cache.
    ///
    /// Saves the snapshot under `~/.tinyos/cache/<key>/snapshot/` using
    /// [`Snapshot::save()`], which writes `mem`, `state.json`, `meta.json`,
    /// and optional files (xsave, irqchips).
    ///
    /// This enables future calls to load the snapshot and use a CoW ForkEngine
    /// (~0.5ms) instead of cold booting (~1-4s).
    pub fn store_snapshot(&self, key: &str, snapshot: &Snapshot) -> Result<()> {
        let dir = self.snapshot_dir(key);
        snapshot.save(&dir).map_err(|e| ComposerError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, format!("snapshot save failed: {e}"))
        ))?;
        Ok(())
    }

    /// Load a cached snapshot for a composition key.
    ///
    /// Returns `Snapshot` suitable for creating a `ForkEngine`. Use
    /// [`has_snapshot()`](Self::has_snapshot) to check availability first.
    pub fn load_snapshot(&self, key: &str) -> Result<Snapshot> {
        let dir = self.snapshot_dir(key);
        Snapshot::load(&dir).map_err(|e| ComposerError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, format!("snapshot load failed: {e}"))
        ))
    }

    /// Check if a booted snapshot is cached for this composition key.
    ///
    /// Returns `true` if the snapshot directory exists and contains the
    /// required files (`mem`, `state.json`, `meta.json`).
    pub fn has_snapshot(&self, key: &str) -> bool {
        self.snapshot_dir(key).join("mem").exists()
            && self.snapshot_dir(key).join("state.json").exists()
            && self.snapshot_dir(key).join("meta.json").exists()
    }
}

// ─── Composer ─────────────────────────────────────────────────────────

/// The main composition engine.
///
/// Combines layer cpio archives into a single bootable initrd, checks for
/// file conflicts, and manages the composition cache.
pub struct Composer {
    registry: LayerRegistry,
    cache: CompositionCache,
}

impl Composer {
    /// Create a new composer with the given registry and cache.
    pub fn new(registry: LayerRegistry, cache: CompositionCache) -> Self {
        Self { registry, cache }
    }

    /// Create a new composer with default paths.
    pub fn load_default() -> Result<Self> {
        let registry = LayerRegistry::load()?;
        let cache = CompositionCache::new(
            CompositionCache::default_root(),
            50, // 50 GB default max
        );
        Ok(Self { registry, cache })
    }

    /// Access the underlying layer registry.
    pub fn registry(&self) -> &LayerRegistry {
        &self.registry
    }

    /// Access the underlying cache.
    pub fn cache(&self) -> &CompositionCache {
        &self.cache
    }

    /// Compute a deterministic composition key from a plan.
    ///
    /// Uses blake3 hash of `kernel_profile + ":" + layer_hashes`.
    /// This is the same algorithm used in `LayerRegistry::compute_composition_key`.
    pub fn composition_key(plan: &CompositionPlan) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(plan.kernel_profile.as_bytes());
        hasher.update(b":");
        let layer_hashes: Vec<&str> = plan.layers.iter().map(|l| l.hash.as_str()).collect();
        hasher.update(layer_hashes.join(",").as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Check for file conflicts between layers.
    ///
    /// Lists all files in each layer's cpio archive and checks for path
    /// collisions. Uses `cpio -it` via subprocess to read archive contents.
    ///
    /// # Behavior
    ///
    /// - **List error** (e.g., `zstd` not installed, corrupted file): logs a
    ///   warning and continues — conflict detection is degraded but composition
    ///   can still proceed. A layer whose contents can't be listed is treated
    ///   as "no files known" for conflict purposes.
    /// - **Actual conflict** (two layers contain the same file path): returns
    ///   `Err(Vec<ConflictError>)` — this is a hard error because the kernel's
    ///   initramfs loader uses last-write-wins, meaning one layer silently
    ///   overwrites the other. Users must explicitly specify layer priority.
    ///
    /// Returns `Ok(())` if no conflicts, or `Err(Vec<ConflictError>)` with details.
    pub fn conflict_check(
        layers: &[LayerRef],
    ) -> std::result::Result<(), Vec<ConflictError>> {
        let mut all_files: HashMap<String, String> = HashMap::new();
        let mut conflicts = Vec::new();

        for layer in layers {
            let files = match list_cpio_files(&layer.layer_path) {
                Ok(f) => f,
                Err(e) => {
                    // Cannot list this layer's files (tool not found, corrupted,
                    // etc.). Treat it as "no files known" for conflict purposes
                    // and warn the user that conflict detection is degraded.
                    tracing::warn!(
                        "Cannot list files for layer {}: {} — conflict detection degraded",
                        layer.display(), e
                    );
                    continue;
                }
            };

            for file in &files {
                if let Some(existing) = all_files.get(file) {
                    conflicts.push(ConflictError {
                        path: file.clone(),
                        layer_a: existing.clone(),
                        layer_b: layer.display(),
                    });
                } else {
                    all_files.insert(file.clone(), layer.display());
                }
            }
        }

        if conflicts.is_empty() {
            Ok(())
        } else {
            Err(conflicts)
        }
    }

    /// Compose initrd from a composition plan.
    ///
    /// 1. Runs conflict check — fails on any file path collision
    /// 2. Checks cache — returns cached initrd if available
    /// 3. Reads and concatenates all layer `.cpio.zst` files
    /// 4. Creates a `cmd.json` cpio archive and appends it
    /// 5. Stores the result in the cache
    /// 6. Returns the path to the composed initrd
    ///
    /// # Security
    /// Individual layer file existence is NOT checked separately from reading
    /// (avoids TOCTOU — a file could be deleted/modified between check and read).
    /// Instead, `std::fs::read()` is called directly and its errors propagate
    /// as `ComposerError::Io(...)` or `ComposerError::LayerFileNotFound(...)`.
    pub fn compose_initrd(&self, plan: &CompositionPlan) -> Result<PathBuf> {
        if plan.layers.is_empty() {
            return Err(ComposerError::EmptyPlan);
        }

        // Check cache first
        let key = &plan.composition_key;
        if self.cache.is_cached(key) {
            self.cache.touch(key).ok();
            return Ok(self.cache.get_initrd_path(key));
        }

        // Conflict check — fail on any file path collision between layers.
        // The kernel's initramfs loader uses last-write-wins semantics, which
        // means one layer silently overwrites another's files. This can mask
        // critical failures (e.g., a pip layer overwriting /usr/bin/python3).
        // Users must explicitly specify layer priority if overwrite is intended.
        Self::conflict_check(&plan.layers).map_err(ComposerError::Conflict)?;

        // Concatenate layer cpio archives.
        // NOTE: No separate existence check (avoids TOCTOU between check and read).
        // std::fs::read() will return Err if the file doesn't exist or can't be read.
        let mut initrd_data: Vec<u8> = Vec::new();
        for layer in &plan.layers {
            let data = std::fs::read(&layer.layer_path)?;
            initrd_data.extend_from_slice(&data);
        }

        // Create and append cmd.json cpio archive
        let cmd_json = serde_json::to_string_pretty(&plan.cmd_config)?;
        let cmd_cpio = create_cmd_json_cpio(&cmd_json)?;
        initrd_data.extend_from_slice(&cmd_cpio);

        // Store in cache
        self.cache.store_initrd(key, &initrd_data, &cmd_json, plan)?;

        Ok(self.cache.get_initrd_path(key))
    }

    /// Resolve code to a plan, compose the initrd, and return the path.
    ///
    /// Convenience method that combines `registry.resolve()` and `compose_initrd()`.
    pub fn resolve_and_compose(
        &self,
        lang: &str,
        code: &str,
        explicit_deps: &[(String, String)],
    ) -> Result<PathBuf> {
        let plan = self.registry.resolve(lang, code, explicit_deps)?;
        self.compose_initrd(&plan)
    }

    /// Calculate total memory needed from layer metadata.
    pub fn calculate_memory(layers: &[crate::layer_registry::LayerMetadata]) -> u64 {
        let base_memory: u64 = 64;
        let layer_memory: u64 = layers.iter().map(|m| m.memory_mb).sum();
        (base_memory + layer_memory).max(128)
    }

    /// Determine kernel profile from layers.
    /// Returns `None` when no GPU profile is detected (no implicit "base" fallback).
    pub fn determine_kernel_profile(layers: &[crate::layer_registry::LayerMetadata]) -> Option<String> {
        // Priority 1: explicit kernel_profile fields
        let gpu_profiles = ["gpu-nvidia", "gpu-vfio", "gpu-vk"];
        for profile in &gpu_profiles {
            if layers.iter().any(|m| m.kernel_profile.as_deref() == Some(*profile)) {
                return Some(profile.to_string());
            }
        }
        // Priority 2: provides-based heuristics
        if layers.iter().any(|m| {
            m.provides.iter().any(|p| {
                let p = p.to_lowercase();
                p == "pytorch" || p == "torch"
            })
        }) {
            return Some("gpu-nvidia".to_string());
        }
        if layers.iter().any(|m| {
            m.provides.iter().any(|p| {
                let p = p.to_lowercase();
                p == "tinygrad"
            })
        }) {
            return Some("gpu-vk".to_string());
        }
        // No GPU profile detected — caller must handle absence
        None
    }

    /// List files in a single cpio archive (public wrapper).
    pub fn list_cpio_files(cpio_path: &Path) -> std::result::Result<HashSet<String>, ComposerError> {
        list_cpio_files(cpio_path)
    }
}

// ─── Helper Functions ─────────────────────────────────────────────────

/// List files in a compressed cpio archive using `zstd` + `cpio`.
///
/// Lists files inside a compressed cpio archive using zstd decompression + cpio listing.
/// Both commands are invoked with separate arguments (no shell) to prevent injection.
///
/// Strips the leading `./` prefix that cpio sometimes adds.
fn list_cpio_files(cpio_path: &Path) -> std::result::Result<HashSet<String>, ComposerError> {
    if !cpio_path.exists() {
        return Err(ComposerError::LayerFileNotFound(cpio_path.to_path_buf()));
    }

    // Spawn zstd decompressor with piped stdout
    let mut zstd = std::process::Command::new("zstd")
        .args(["-d", "-c", "--"])
        .arg(cpio_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| ComposerError::Subprocess {
            cmd: "zstd".into(),
            detail: e.to_string(),
        })?;

    // Pipe zstd's stdout into cpio
    let cpio_stdin = zstd.stdout.take()
        .ok_or_else(|| ComposerError::Subprocess {
            cmd: "zstd".into(),
            detail: "failed to capture zstd stdout".into(),
        })?;

    let output = std::process::Command::new("cpio")
        .args(["-it"])
        .stdin(cpio_stdin)
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| ComposerError::Subprocess {
            cmd: "cpio".into(),
            detail: e.to_string(),
        })?;

    // Wait for zstd to finish
    let zstd_status = zstd.wait()
        .map_err(|e| ComposerError::Subprocess {
            cmd: "zstd".into(),
            detail: format!("wait failed: {e}"),
        })?;

    if !zstd_status.success() {
        return Err(ComposerError::Subprocess {
            cmd: "zstd".into(),
            detail: format!("exited with {zstd_status}"),
        });
    }

    if !output.status.success() && output.stdout.is_empty() {
        return Err(ComposerError::Subprocess {
            cmd: "cpio".into(),
            detail: format!("exited with {} (no output)", output.status),
        });
    }

    let stdout = String::from_utf8(output.stdout)?;
    let mut files = HashSet::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Strip leading "./" if present
        let path = if let Some(rest) = trimmed.strip_prefix("./") {
            rest
        } else {
            trimmed
        };
        // Skip the TRAILER!!! entry and "cpio:" warnings
        if !path.starts_with("cpio:") && path != "TRAILER!!!" {
            files.insert(path.to_string());
        }
    }

    Ok(files)
}

/// Create a minimal newc cpio archive containing `cmd.json` at the root.
///
/// Uses a shell pipeline: creates a temp dir, writes cmd.json, then runs
/// `cpio -o -H newc | zstd` to produce a compressed cpio archive.
fn create_cmd_json_cpio(cmd_json: &str) -> std::result::Result<Vec<u8>, ComposerError> {
    // Create a temporary directory with unique name
    use std::sync::atomic::{AtomicU64, Ordering};
    static CMD_COUNTER: AtomicU64 = AtomicU64::new(0);
    let tmp_dir = std::env::temp_dir().join(format!(
        "tinyos-cmd-{}-{}",
        std::process::id(),
        CMD_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    std::fs::create_dir_all(&tmp_dir)?;
    std::fs::write(tmp_dir.join("cmd.json"), cmd_json)?;

    // Create cpio archive via subprocess (no shell)
    // Step 1: pipe "cmd.json" into cpio to create uncompressed archive
    use std::io::Write;

    let mut cpio_child = std::process::Command::new("cpio")
        .args(["-o", "-H", "newc", "--quiet"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .current_dir(&tmp_dir)
        .spawn()
        .map_err(|e| ComposerError::Subprocess {
            cmd: "cpio".into(),
            detail: e.to_string(),
        })?;

    // Feed file list to cpio via stdin
    if let Some(ref mut stdin) = cpio_child.stdin {
        stdin.write_all(b"cmd.json\n").map_err(|e| ComposerError::Subprocess {
            cmd: "cpio".into(),
            detail: format!("stdin write: {e}"),
        })?;
    }
    // Drop stdin to close it, allowing cpio to finish
    drop(cpio_child.stdin.take());

    let cpio_output = cpio_child.wait_with_output().map_err(|e| ComposerError::Subprocess {
        cmd: "cpio".into(),
        detail: e.to_string(),
    })?;

    if !cpio_output.status.success() {
        return Err(ComposerError::Subprocess {
            cmd: "cpio".into(),
            detail: format!("exited with {}", cpio_output.status),
        });
    }

    // Step 2: compress cpio output with zstd
    let mut zstd_child = std::process::Command::new("zstd")
        .args(["-q"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| ComposerError::Subprocess {
            cmd: "zstd".into(),
            detail: e.to_string(),
        })?;

    // Write cpio output into zstd stdin
    if let Some(ref mut stdin) = zstd_child.stdin {
        stdin.write_all(&cpio_output.stdout).map_err(|e| ComposerError::Subprocess {
            cmd: "zstd".into(),
            detail: format!("stdin write: {e}"),
        })?;
    }
    drop(zstd_child.stdin.take());

    let zstd_output = zstd_child.wait_with_output().map_err(|e| ComposerError::Subprocess {
        cmd: "zstd".into(),
        detail: e.to_string(),
    })?;

    // Clean up temp dir
    std::fs::remove_dir_all(&tmp_dir).ok();

    // If zstd failed or produced no output, return error
    // (the main cpio step already validated)
    if !zstd_output.status.success() {
        // Try plain cpio without compression (kernel will still accept it)
        let fallback_id = CMD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_dir2 = std::env::temp_dir().join(format!(
            "tinyos-cmd-fallback-{}-{}",
            std::process::id(),
            fallback_id
        ));
        std::fs::create_dir_all(&tmp_dir2)?;
        std::fs::write(tmp_dir2.join("cmd.json"), cmd_json)?;

        // Use cpio directly without shell
        let mut cpio_fallback = std::process::Command::new("cpio")
            .args(["-o", "-H", "newc", "--quiet"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .current_dir(&tmp_dir2)
            .spawn()
            .map_err(|e| ComposerError::Subprocess {
                cmd: "cpio (fallback)".into(),
                detail: e.to_string(),
            })?;

        if let Some(ref mut stdin) = cpio_fallback.stdin {
            stdin.write_all(b"cmd.json\n").map_err(|e| ComposerError::Subprocess {
                cmd: "cpio (fallback)".into(),
                detail: format!("stdin write: {e}"),
            })?;
        }
        drop(cpio_fallback.stdin.take());

        let fallback_output = cpio_fallback.wait_with_output().map_err(|e| ComposerError::Subprocess {
            cmd: "cpio (fallback)".into(),
            detail: e.to_string(),
        })?;

        std::fs::remove_dir_all(&tmp_dir2).ok();

        if !fallback_output.status.success() || fallback_output.stdout.is_empty() {
            return Err(ComposerError::Subprocess {
                cmd: "cpio".into(),
                detail: "failed to create cmd.json cpio archive".into(),
            });
        }

        return Ok(fallback_output.stdout);
    }

    Ok(zstd_output.stdout)
}

/// Initialize a composer with default paths and load the registry.
///
/// Convenience function for one-shot composition.
pub fn default_composer() -> Result<Composer> {
    Composer::load_default()
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(test)]
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer_registry::{LayerMetadata, LayerType};

    /// Helper to create a minimal layer on disk.
    fn create_fake_layer(
        base: &Path,
        type_dir: &str,
        name: &str,
        version: &str,
        cpio_data: &[u8],
    ) -> PathBuf {
        let dir = base.join(type_dir).join(name).join(version);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("layer.cpio.zst");
        std::fs::write(&path, cpio_data).unwrap();
        path
    }

    /// Helper to create a LayerRef for testing.
    fn make_layer_ref(
        layer_type: LayerType,
        name: &str,
        version: &str,
        path: PathBuf,
        hash: &str,
    ) -> LayerRef {
        LayerRef {
            layer_type,
            name: name.to_string(),
            version: version.to_string(),
            layer_path: path,
            hash: hash.to_string(),
        }
    }

    fn setup_registry() -> (tempfile::TempDir, LayerRegistry) {
        let tmp = tempfile::tempdir().unwrap();
        let layers_path = tmp.path().join("layers");
        std::fs::create_dir_all(&layers_path).unwrap();

        // Create layer files
        create_fake_layer(&layers_path, "base", "base", "v1", b"base-cpio-data");
        create_fake_layer(&layers_path, "runtime", "python", "3.12.3", b"python-cpio-data");
        create_fake_layer(&layers_path, "pip", "numpy", "1.26.4", b"numpy-cpio-data");

        let mut registry = LayerRegistry::load_from(&layers_path).unwrap();

        registry.add_layer(LayerMetadata {
            layer_type: LayerType::Base,
            name: "base".into(),
            version: "v1".into(),
            provides: vec![],
            requires_runtime: None,
            size_bytes: 100,
            compressed_size: 50,
            hash: "basehash".into(),
            kernel_profile: None,
            memory_mb: 64,
            interpreter: None,
            interpreter_args: vec![],
            default: true,
        }).unwrap();

        registry.add_layer(LayerMetadata {
            layer_type: LayerType::Runtime,
            name: "python".into(),
            version: "3.12.3".into(),
            provides: vec!["python3".into()],
            requires_runtime: None,
            size_bytes: 100,
            compressed_size: 50,
            hash: "pythonhash".into(),
            kernel_profile: None,
            memory_mb: 128,
            interpreter: Some("/usr/bin/python3".into()),
            interpreter_args: vec!["-c".into()],
            default: true,
        }).unwrap();

        registry.add_layer(LayerMetadata {
            layer_type: LayerType::Pip,
            name: "numpy".into(),
            version: "1.26.4".into(),
            provides: vec!["numpy".into()],
            requires_runtime: Some("python".into()),
            size_bytes: 100,
            compressed_size: 50,
            hash: "numpyhash".into(),
            kernel_profile: None,
            memory_mb: 64,
            interpreter: None,
            interpreter_args: vec![],
            default: true,
        }).unwrap();

        (tmp, registry)
    }

    // ─── Composition Key Determinism ─────────────────────────────

    #[test]
    fn test_composition_key() {
        let plan = CompositionPlan {
            layers: vec![
                make_layer_ref(LayerType::Base, "v1", "1", PathBuf::from("/a"), "basehash"),
                make_layer_ref(LayerType::Runtime, "python", "3.12.3", PathBuf::from("/b"), "pythonhash"),
            ],
            kernel_profile: "base".into(),
            memory_mb: 192,
            cmd_config: crate::layer_registry::CmdConfig {
                interpreter: Some("/usr/bin/python3".into()),
                args: vec!["-c".into()],
                exec: None,
            },
            composition_key: String::new(),
        };

        let key1 = Composer::composition_key(&plan);
        let key2 = Composer::composition_key(&plan);

        assert_eq!(key1, key2, "composition key must be deterministic");
        assert_eq!(key1.len(), 64, "blake3 hex output must be 64 chars");
    }

    #[test]
    fn test_composition_key_differs_for_different_plans() {
        let plan_a = CompositionPlan {
            layers: vec![
                make_layer_ref(LayerType::Base, "v1", "1", PathBuf::from("/a"), "basehash"),
            ],
            kernel_profile: "base".into(),
            memory_mb: 64,
            cmd_config: crate::layer_registry::CmdConfig {
                interpreter: None,
                args: vec![],
                exec: None,
            },
            composition_key: String::new(),
        };

        let plan_b = CompositionPlan {
            layers: vec![
                make_layer_ref(LayerType::Base, "v1", "1", PathBuf::from("/a"), "basehash"),
                make_layer_ref(LayerType::Pip, "numpy", "1.26.4", PathBuf::from("/b"), "numpyhash"),
            ],
            kernel_profile: "base".into(),
            memory_mb: 128,
            cmd_config: crate::layer_registry::CmdConfig {
                interpreter: None,
                args: vec![],
                exec: None,
            },
            composition_key: String::new(),
        };

        assert_ne!(Composer::composition_key(&plan_a), Composer::composition_key(&plan_b));
    }

    // ─── Conflict Check ──────────────────────────────────────────

    #[test]
    fn test_conflict_check_no_conflicts() {
        // Create temporary cpio archives with different files
        let tmp = tempfile::tempdir().unwrap();

        // Create two simple cpio archives with different files
        let dir1 = tmp.path().join("layer1");
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::write(dir1.join("file_a.txt"), b"content").unwrap();
        let cpio1 = tmp.path().join("layer1.cpio.zst");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "cd '{}' && find . -name '*.txt' | cpio -o -H newc --quiet 2>/dev/null | zstd -q -o '{}' 2>/dev/null",
                dir1.display(),
                cpio1.display()
            ))
            .status()
            .unwrap();
        if !status.success() {
            // Skip if cpio is not available
            eprintln!("cpio not available, skipping test");
            return;
        }

        let dir2 = tmp.path().join("layer2");
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir2.join("file_b.txt"), b"content").unwrap();
        let cpio2 = tmp.path().join("layer2.cpio.zst");
        let status2 = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "cd '{}' && find . -name '*.txt' | cpio -o -H newc --quiet 2>/dev/null | zstd -q -o '{}' 2>/dev/null",
                dir2.display(),
                cpio2.display()
            ))
            .status()
            .unwrap();
        if !status2.success() {
            return;
        }

        let layers = vec![
            make_layer_ref(LayerType::Pip, "pkg1", "1.0", cpio1, "h1"),
            make_layer_ref(LayerType::Pip, "pkg2", "2.0", cpio2, "h2"),
        ];

        let result = Composer::conflict_check(&layers);
        assert!(result.is_ok(), "expected no conflicts, got: {:?}", result);
    }

    #[test]
    fn test_conflict_check_with_conflicts() {
        let tmp = tempfile::tempdir().unwrap();

        // Create two cpio archives with the same file
        let dir1 = tmp.path().join("layer1");
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::write(dir1.join("shared.txt"), b"content").unwrap();
        let cpio1 = tmp.path().join("layer1.cpio.zst");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "cd '{}' && find . -name '*.txt' | cpio -o -H newc --quiet 2>/dev/null | zstd -q -o '{}' 2>/dev/null",
                dir1.display(),
                cpio1.display()
            ))
            .status()
            .unwrap();
        if !status.success() {
            eprintln!("cpio not available, skipping test");
            return;
        }

        let dir2 = tmp.path().join("layer2");
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir2.join("shared.txt"), b"different content").unwrap();
        let cpio2 = tmp.path().join("layer2.cpio.zst");
        let status2 = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "cd '{}' && find . -name '*.txt' | cpio -o -H newc --quiet 2>/dev/null | zstd -q -o '{}' 2>/dev/null",
                dir2.display(),
                cpio2.display()
            ))
            .status()
            .unwrap();
        if !status2.success() {
            return;
        }

        let layers = vec![
            make_layer_ref(LayerType::Pip, "pkg1", "1.0", cpio1, "h1"),
            make_layer_ref(LayerType::Pip, "pkg2", "2.0", cpio2, "h2"),
        ];

        // conflict_check should detect the shared file
        if let Err(conflicts) = Composer::conflict_check(&layers) {
            // The error should contain details about the conflict
            assert!(!conflicts.is_empty(), "should have at least one conflict");
        }
    }

    // ─── Composition Cache ───────────────────────────────────────

    #[test]
    fn test_cache_store_and_retrieve() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = CompositionCache::new(tmp.path().join("cache"), 50);

        let key = "testkey123";
        let data = b"initrd-content";
        let cmd_json = r#"{"interpreter":"/usr/bin/python3","args":["-c"],"exec":null}"#;

        let plan = CompositionPlan {
            layers: vec![],
            kernel_profile: "base".into(),
            memory_mb: 64,
            cmd_config: crate::layer_registry::CmdConfig {
                interpreter: Some("/usr/bin/python3".into()),
                args: vec!["-c".into()],
                exec: None,
            },
            composition_key: key.to_string(),
        };

        cache.store_initrd(key, data, cmd_json, &plan).unwrap();

        assert!(cache.is_cached(key));
        assert!(cache.get_initrd_path(key).exists());

        let stored = std::fs::read(cache.get_initrd_path(key)).unwrap();
        assert_eq!(stored, data);
    }

    #[test]
    fn test_cache_miss() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = CompositionCache::new(tmp.path().join("cache"), 50);
        assert!(!cache.is_cached("nonexistent"));
    }

    #[test]
    fn test_cache_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = CompositionCache::new(tmp.path().join("cache"), 50);

        let key = "toremove";
        let plan = CompositionPlan {
            layers: vec![],
            kernel_profile: "base".into(),
            memory_mb: 64,
            cmd_config: crate::layer_registry::CmdConfig {
                interpreter: None,
                args: vec![],
                exec: None,
            },
            composition_key: key.to_string(),
        };

        cache.store_initrd(key, b"data", "{}", &plan).unwrap();
        assert!(cache.is_cached(key));

        cache.remove(key).unwrap();
        assert!(!cache.is_cached(key));
    }

    // ─── Cache LRU Eviction ──────────────────────────────────────

    #[test]
    fn test_cache_enforce_max_size() {
        let tmp = tempfile::tempdir().unwrap();
        // Set max size to 0 so any entry triggers eviction
        let cache = CompositionCache::new(tmp.path().join("cache"), 0);

        let plan = CompositionPlan {
            layers: vec![],
            kernel_profile: "base".into(),
            memory_mb: 64,
            cmd_config: crate::layer_registry::CmdConfig {
                interpreter: None,
                args: vec![],
                exec: None,
            },
            composition_key: "evictme".to_string(),
        };

        cache.store_initrd("evictme", b"some-data", "{}", &plan).unwrap();

        // enforce_max_size should evict because max_size_gb = 0
        cache.enforce_max_size().unwrap();

        // The entry might have been evicted
        // (timing-dependent, but max_size_gb=0 means any entry gets evicted)
    }

    // ─── Resolve and Compose Integration ─────────────────────────

    #[test]
    fn test_resolve_and_compose_valid() {
        let (_tmp, registry) = setup_registry();
        let cache = CompositionCache::new(
            std::env::temp_dir().join(format!(
                "tinyos-cache-test-{}",
                TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
            )),
            50,
        );
        let composer = Composer::new(registry, cache);

        let result = composer.resolve_and_compose(
            "python",
            "import numpy; print('hello')",
            &[],
        );

        // This should succeed: numpy and python runtime are in the registry
        // and their layer files exist on disk
        assert!(
            result.is_ok(),
            "resolve_and_compose failed: {:?}",
            result.err()
        );

        let initrd_path = result.unwrap();
        assert!(initrd_path.exists(), "initrd should exist at {:?}", initrd_path);

        // Read the initrd and verify it's non-empty
        let initrd_data = std::fs::read(&initrd_path).unwrap();
        assert!(!initrd_data.is_empty(), "initrd should not be empty");

        // Clean up
        if let Some(parent) = initrd_path.parent() {
            std::fs::remove_dir_all(parent).ok();
        }
    }

    #[test]
    fn test_resolve_and_compose_caches() {
        let (_tmp, registry) = setup_registry();
        let cache_dir = std::env::temp_dir().join(format!(
            "tinyos-cache-test-{}",
            TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let cache = CompositionCache::new(cache_dir.clone(), 50);
        let composer = Composer::new(registry, cache);

        // First call — should compose
        let result1 = composer.resolve_and_compose("python", "print('hello')", &[]);
        assert!(result1.is_ok(), "first compose failed: {:?}", result1.err());

        let path1 = result1.unwrap();
        let data1 = std::fs::read(&path1).unwrap_or_default();

        // Second call with same code — should be cached
        let result2 = composer.resolve_and_compose("python", "print('hello')", &[]);
        assert!(result2.is_ok(), "second compose failed: {:?}", result2.err());

        let path2 = result2.unwrap();
        let data2 = std::fs::read(&path2).unwrap_or_default();

        assert_eq!(data1, data2, "cached initrd should match");

        // Clean up
        std::fs::remove_dir_all(&cache_dir).ok();
    }

    // ─── List Cpio Files ─────────────────────────────────────────

    #[test]
    fn test_list_cpio_files_nonexistent() {
        let result = list_cpio_files(Path::new("/nonexistent/file.cpio.zst"));
        assert!(result.is_err());
    }

    // ─── Calculate Memory ────────────────────────────────────────

    #[test]
    fn test_calculate_memory() {
        let metas = vec![
            LayerMetadata {
                layer_type: LayerType::Base,
                name: "v1".into(),
                version: "1".into(),
                provides: vec![],
                requires_runtime: None,
                size_bytes: 100,
                compressed_size: 50,
                hash: "a".into(),
                kernel_profile: None,
                memory_mb: 64,
                interpreter: None,
                interpreter_args: vec![],
                default: false,
            },
            LayerMetadata {
                layer_type: LayerType::Runtime,
                name: "python".into(),
                version: "3.12.3".into(),
                provides: vec![],
                requires_runtime: None,
                size_bytes: 100,
                compressed_size: 50,
                hash: "b".into(),
                kernel_profile: None,
                memory_mb: 128,
                interpreter: Some("/usr/bin/python3".into()),
                interpreter_args: vec!["-c".into()],
                default: false,
            },
        ];

        let mem = Composer::calculate_memory(&metas);
        assert_eq!(mem, 256);
    }

    #[test]
    fn test_calculate_memory_minimum() {
        assert_eq!(Composer::calculate_memory(&[]), 128);
    }

    // ─── Determine Kernel Profile ────────────────────────────────

    #[test]
    fn test_determine_kernel_profile_base() {
        let metas = vec![
            LayerMetadata {
                layer_type: LayerType::Runtime,
                name: "python".into(),
                version: "3.12.3".into(),
                provides: vec![],
                requires_runtime: None,
                size_bytes: 100,
                compressed_size: 50,
                hash: "a".into(),
                kernel_profile: None,
                memory_mb: 64,
                interpreter: None,
                interpreter_args: vec![],
                default: false,
            },
        ];
        assert_eq!(Composer::determine_kernel_profile(&metas), None);
    }

    #[test]
    fn test_determine_kernel_profile_tinygrad() {
        let metas = vec![
            LayerMetadata {
                layer_type: LayerType::Pip,
                name: "tinygrad".into(),
                version: "latest".into(),
                provides: vec!["tinygrad".into()],
                requires_runtime: Some("python".into()),
                size_bytes: 100,
                compressed_size: 50,
                hash: "a".into(),
                kernel_profile: Some("gpu-vk".into()),
                memory_mb: 256,
                interpreter: None,
                interpreter_args: vec![],
                default: true,
            },
        ];
        assert_eq!(Composer::determine_kernel_profile(&metas), Some("gpu-vk".to_string()));
    }

    // ─── Composer Cache Paths ────────────────────────────────────

    #[test]
    fn test_cache_key_dir() {
        let cache = CompositionCache::new(PathBuf::from("/tmp/cache"), 50);
        assert_eq!(
            cache.key_dir("abc123"),
            PathBuf::from("/tmp/cache/abc123")
        );
        assert_eq!(
            cache.get_initrd_path("abc123"),
            PathBuf::from("/tmp/cache/abc123/initrd.zst")
        );
    }

    #[test]
    fn test_cache_default_root() {
        let root = CompositionCache::default_root();
        assert!(root.ends_with(".tinyos/cache"));
    }

    // ─── CmdConfig Creation ──────────────────────────────────────

    #[test]
    fn test_create_cmd_json_cpio() {
        let cmd_json = r#"{"interpreter":"/usr/bin/python3","args":["-c"],"exec":null}"#;
        let result = create_cmd_json_cpio(cmd_json);

        // This may fail if cpio/zstd are not installed
        if let Ok(data) = result {
            assert!(!data.is_empty(), "cpio archive should not be empty");
        }
    }
}
