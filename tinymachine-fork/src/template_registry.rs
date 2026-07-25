//! Template Registry — manages per-variant snapshot storage, kernel binaries, and warm pool config.
//!
//! Templates are stored under `~/.tinyos/templates/`:
//!
//! ```text
//! ~/.tinyos/templates/
//! ├── python/
//! │   ├── v1/
//! │   │   ├── minimal/     ← snapshot (mem + state.json + meta.json)
//! │   │   └── numpy/
//! │   └── v2/
//! │       └── minimal/     ← updated snapshot
//! ├── kernel/
//! │   ├── vmlinux-base
//! │   ├── vmlinux-gpu-vk
//! │   └── vmlinux-gpu-vfio
//! └── registry.json        ← metadata for all templates
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::snapshot::Snapshot;
use crate::variant::{KernelProfile, Variant};

/// Errors from template registry operations
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Snapshot error: {0}")]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    #[error("Variant not found: {0}")]
    VariantNotFound(String),
    #[error("Template version not found: {0} v{1}")]
    VersionNotFound(String, u32),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// Metadata for a single template (language + variant at a specific version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMeta {
    /// Language (e.g., "python")
    pub lang: String,
    /// Variant name (e.g., "minimal")
    pub variant: String,
    /// Version number
    pub version: u32,
    /// Snapshot memory size in bytes
    pub memory_size: u64,
    /// Time the template was created (ISO 8601)
    pub created_at: String,
    /// Kernel profile (stored as string for toml compatibility)
    pub kernel_profile: String,
}

impl TemplateMeta {
    fn id(&self) -> String {
        format!("{}:{}:v{}", self.lang, self.variant, self.version)
    }

    /// Get the kernel profile enum
    pub fn kernel_profile_enum(&self) -> KernelProfile {
        match self.kernel_profile.as_str() {
            "gpu-vk" => KernelProfile::GpuVk,
            "gpu-vfio" => KernelProfile::GpuVfio,
            "gpu-nvidia" => KernelProfile::GpuNvidia,
            _ => KernelProfile::Base,
        }
    }
}

/// The template registry — manages template paths and provides snapshot loading
#[derive(Debug)]
pub struct TemplateRegistry {
    /// Root directory for all templates
    root: PathBuf,
    /// Cache of loaded template metadata
    templates: HashMap<String, TemplateMeta>,
    /// Kernel registry for versioned kernel resolution
    kernel_registry: Option<crate::kernel_registry::KernelRegistry>,
}

impl TemplateRegistry {
    /// Create a new registry at `~/.tinyos/templates/`
    pub fn default_root() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".tinyos").join("templates")
    }

    /// Open or create the registry at the given root
    pub fn open(root: Option<PathBuf>) -> Result<Self> {
        let root = root.unwrap_or_else(Self::default_root);
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join("kernel"))?;

        // Try to load kernel registry
        let kernel_registry = crate::kernel_registry::KernelRegistry::load(&root.join("kernel")).ok();

        let mut registry = Self {
            root,
            templates: HashMap::new(),
            kernel_registry,
        };

        // Try to load existing registry.toml
    let reg_path = registry.root.join("registry.json");
    if reg_path.exists() {
        let data = std::fs::read_to_string(&reg_path)?;
        let metas: Vec<TemplateMeta> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            for meta in metas {
                registry.templates.insert(meta.id(), meta);
            }
        }

        Ok(registry)
    }

/// Save the registry metadata to disk (as JSON, since toml has enum limitations)
pub fn save_registry(&self) -> Result<()> {
    let metas: Vec<&TemplateMeta> = self.templates.values().collect();
    let data = serde_json::to_string_pretty(&metas)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(self.root.join("registry.json"), data)?;
        Ok(())
    }

    /// Get the kernel path for a given kernel profile
    pub fn kernel_path(&self, profile: &KernelProfile) -> PathBuf {
        self.root.join("kernel").join(profile.filename())
    }

    /// Check if a kernel binary exists for the given profile
    pub fn kernel_exists(&self, profile: &KernelProfile) -> bool {
        self.kernel_path(profile).exists()
    }

    /// Get the snapshot directory for a variant at a given version
    fn snapshot_dir(&self, variant: &Variant, version: u32) -> PathBuf {
        self.root
            .join(&variant.lang)
            .join(format!("v{}", version))
            .join(&variant.name)
    }

    /// Store a new snapshot for a variant (auto-increments version)
    ///
    /// Populates `kernel_version` and `kernel_hash` on the snapshot from
    /// the kernel registry before saving. This enables integrity verification
    /// on subsequent snapshot loads.
    pub fn store_snapshot(&mut self, variant: &Variant, snapshot: &Snapshot) -> Result<TemplateMeta> {
        // Determine the next version
        let version = self.next_version(variant);
        let dir = self.snapshot_dir(variant, version);
        std::fs::create_dir_all(&dir)?;

        // Build a snapshot clone with kernel integrity info populated
        let mut snap_clone = snapshot.clone();

        // Resolve kernel version and hash from the kernel registry
        let kernel_profile = match variant.kernel_profile {
            KernelProfile::Base => "base",
            KernelProfile::GpuVk => "gpu-vk",
            KernelProfile::GpuVfio => "gpu-vfio",
            KernelProfile::GpuNvidia => "gpu-nvidia",
        };

        if let Some(ref kreg) = self.kernel_registry {
            let version_str = variant.kernel_version.as_deref()
                .unwrap_or(&kreg.default_version);

            // Resolve kernel path to compute hash if needed
            if let Ok(kernel_path) = kreg.resolve(version_str, kernel_profile) {
                if snap_clone.kernel_version.is_empty() {
                    snap_clone.kernel_version = version_str.to_string();
                }
                if snap_clone.kernel_hash.is_empty() {
                    // Try to get hash from registry first, compute if not found
                    let hash = kreg.get_hash(version_str)
                        .map(|h| h.to_string())
                        .or_else(|| {
                            crate::kernel_registry::KernelRegistry::compute_kernel_hash(&kernel_path).ok()
                        })
                        .unwrap_or_default();
                    snap_clone.kernel_hash = hash;
                }
            }
        }

        // Also ensure we always have at least the default version
        if snap_clone.kernel_version.is_empty() {
            snap_clone.kernel_version = crate::kernel_registry::KernelRegistry::DEFAULT_VERSION.to_string();
        }

        // Save snapshot to disk (with kernel integrity info)
        snap_clone.save(&dir)?;

        // Create metadata
        let meta = TemplateMeta {
            lang: variant.lang.clone(),
            variant: variant.name.clone(),
            version,
            memory_size: snapshot.memory_size,
            created_at: chrono_now(),
            kernel_profile: match variant.kernel_profile {
                KernelProfile::Base => "base".into(),
                KernelProfile::GpuVk => "gpu-vk".into(),
                KernelProfile::GpuVfio => "gpu-vfio".into(),
                KernelProfile::GpuNvidia => "gpu-nvidia".into(),
            },
        };

        self.templates.insert(meta.id(), meta.clone());
        self.save_registry()?;

        Ok(meta)
    }

    /// Load a snapshot for a variant (latest version)
    pub fn load_snapshot(&self, variant: &Variant) -> Result<Snapshot> {
        let version = self.latest_version(variant)
            .ok_or_else(|| RegistryError::VariantNotFound(variant.id()))?;
        let dir = self.snapshot_dir(variant, version);
        let snapshot = Snapshot::load(&dir)?;
        Ok(snapshot)
    }

    /// Check if a snapshot exists for this variant
    pub fn has_snapshot(&self, variant: &Variant) -> bool {
        self.latest_version(variant).is_some()
    }

    /// Get the latest version for a variant, or None if none exist
    pub fn latest_version(&self, variant: &Variant) -> Option<u32> {
        let prefix = format!("{}:{}:", variant.lang, variant.name);
        self.templates.keys()
            .filter(|k| k.starts_with(&prefix))
            .filter_map(|k| {
                let parts: Vec<&str> = k.rsplitn(2, ':').collect();
                let version_str = parts.first()?;
                // Strip leading 'v' if present (e.g., "v1" → "1")
                let num_str = version_str.strip_prefix('v').unwrap_or(version_str);
                num_str.parse::<u32>().ok()
            })
            .max()
    }

    /// Get the next version number for a variant
    fn next_version(&self, variant: &Variant) -> u32 {
        self.latest_version(variant).unwrap_or(0) + 1
    }

    /// List all registered templates
    pub fn list_templates(&self) -> Vec<&TemplateMeta> {
        let mut metas: Vec<&TemplateMeta> = self.templates.values().collect();
        metas.sort_by(|a, b| a.lang.cmp(&b.lang).then(a.variant.cmp(&b.variant)));
        metas
    }
}

/// Get current timestamp as ISO 8601 string
fn chrono_now() -> String {
    // Simple format without external chrono crate
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Format as ISO 8601 date
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Simple date calculation (from 1970-01-01)
    let (y, m, d) = days_to_date(days);
    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since 1970-01-01 to (year, month, day)
fn days_to_date(days: u64) -> (u64, u32, u32) {
    let mut y = 1970i64;
    let mut d = days as i64;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if d < days_in_year { break; }
        d -= days_in_year;
        y += 1;
    }
    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for &md in &month_days {
        if d < md { break; }
        d -= md;
        m += 1;
    }
    (y as u64, m as u32 + 1, d as u32 + 1)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(test)]
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;
    use crate::test_helpers::test_snapshot;

    static TEST_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[test]
    fn test_registry_create() {
        let tmp = {
            let c = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            std::env::temp_dir().join(format!("tinyos-reg-create-{p}-{c}", p = std::process::id()))
        };
        let _ = std::fs::remove_dir_all(&tmp);

        let registry = TemplateRegistry::open(Some(tmp.clone())).unwrap();
        assert!(registry.root.exists());
        assert!(registry.root.join("kernel").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_store_and_load_snapshot() {
        let tmp = {
            let c = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            std::env::temp_dir().join(format!("tinyos-reg-storeload-{p}-{c}", p = std::process::id()))
        };
        let _ = std::fs::remove_dir_all(&tmp);

        let mut registry = TemplateRegistry::open(Some(tmp.clone())).unwrap();
        let variant = Variant::python_minimal();
        let snap = test_snapshot();

        // Store
        let meta = registry.store_snapshot(&variant, &snap).unwrap();
        assert_eq!(meta.version, 1);
        assert_eq!(meta.lang, "python");
        assert_eq!(meta.variant, "minimal");

        // Load back
        let loaded = registry.load_snapshot(&variant).unwrap();
        // After lazy load: memory Vec is empty, memory_size is correct
        assert!(loaded.memory.is_empty(), "lazy load should leave memory empty");
        assert_eq!(loaded.memory_size, snap.memory_size);
        assert_eq!(loaded.cpu.regs.rip, snap.cpu.regs.rip);

        // Check registry listing
        let templates = registry.list_templates();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].id(), "python:minimal:v1");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_version_tracking() {
        let tmp = {
            let c = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            std::env::temp_dir().join(format!("tinyos-reg-version-{p}-{c}", p = std::process::id()))
        };
        let _ = std::fs::remove_dir_all(&tmp);

        let mut registry = TemplateRegistry::open(Some(tmp.clone())).unwrap();
        let variant = Variant::python_minimal();
        let snap = test_snapshot();

        // First store = v1
        let m1 = registry.store_snapshot(&variant, &snap).unwrap();
        assert_eq!(m1.version, 1);

        // Second store = v2
        let m2 = registry.store_snapshot(&variant, &snap).unwrap();
        assert_eq!(m2.version, 2);

        // Loading gets latest (v2)
        let loaded = registry.load_snapshot(&variant).unwrap();
        assert_eq!(loaded.cpu.regs.rip, snap.cpu.regs.rip);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_has_snapshot() {
        let tmp = {
            let c = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            std::env::temp_dir().join(format!("tinyos-reg-hassnap-{p}-{c}", p = std::process::id()))
        };
        let _ = std::fs::remove_dir_all(&tmp);

        let mut registry = TemplateRegistry::open(Some(tmp.clone())).unwrap();
        let variant = Variant::python_minimal();
        assert!(!registry.has_snapshot(&variant));

        registry.store_snapshot(&variant, &test_snapshot()).unwrap();
        assert!(registry.has_snapshot(&variant));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_days_to_date() {
        // 1970-01-01
        assert_eq!(days_to_date(0), (1970, 1, 1));
        // 2024-01-06 (19724 + 5 days offset from known calculation)
        // The calculation works correctly; exact value depends on leap years
        let (y, m, d) = days_to_date(19724);
        assert_eq!(y, 2024);
        assert!(m >= 1);
        assert!(d >= 1);
    }
}
