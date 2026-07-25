//! Kernel Registry — manages versioned kernel binaries with integrity verification.
//!
//! TinyMachine kernels are stored under `~/.tinymachine/templates/kernel/` with versioned
//! subdirectories:
//!
//! ```text
//! ~/.tinymachine/templates/kernel/
//! ├── v7.1.4/
//! │   ├── vmlinux-base
//! │   ├── vmlinux-gpu-vk
//! │   ├── vmlinux-gpu-vfio
//! │   └── vmlinux-gpu-nvidia
//! ├── v6.8.1/
//! │   └── vmlinux-base
//! └── registry.toml          ← metadata index
//! ```
//!
//! The `registry.toml` tracks each version, its profiles, the default version,
//! and SHA-256 hashes for integrity verification. When loading a snapshot,
//! the stored `kernel_hash` is compared against the actual kernel file's hash
//! to detect stale snapshots after a kernel rebuild.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from kernel registry operations
#[derive(Error, Debug)]
pub enum KernelRegistryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Version not found: {version}")]
    VersionNotFound { version: String },
    #[error("Profile '{profile}' not found in version '{version}'")]
    ProfileNotFound { profile: String, version: String },
    #[error("Kernel hash mismatch: expected {expected}, computed {computed}")]
    HashMismatch { expected: String, computed: String },
    #[error("Kernel file not found: {path}")]
    KernelFileNotFound { path: String },
}

/// Result alias for kernel registry operations
pub type Result<T> = std::result::Result<T, KernelRegistryError>;

/// Metadata for a single kernel version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelVersion {
    /// List of profiles available in this version (e.g., "base", "gpu-vk")
    pub profiles: Vec<String>,
    /// SHA-256 hash of the vmlinux-base kernel (primary integrity check)
    pub hash: String,
    /// Optional: additional hashes per profile (profile_name → hash)
    #[serde(default)]
    pub profile_hashes: HashMap<String, String>,
}

/// The kernel registry — manages versioned kernel binaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRegistry {
    /// Default version to use when a specific version is not requested
    pub default_version: String,
    /// Per-version metadata
    pub versions: HashMap<String, KernelVersion>,
    /// Root directory for kernel binaries (set at open time)
    #[serde(skip)]
    pub kernel_dir: PathBuf,
}

impl KernelRegistry {
    /// Default kernel version for new installations
    pub const DEFAULT_VERSION: &'static str = "7.1.4";

    /// Get the default TinyMachine kernel directory path
    pub fn default_kernel_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".tinymachine").join("templates").join("kernel")
    }

    /// Load the kernel registry from `registry.toml` in the kernel directory.
    ///
    /// If the file does not exist, returns a default registry (no versions,
    /// default version = `Self::DEFAULT_VERSION`). This allows first-use
    /// scenarios and integration tests where no kernel has been built yet.
    pub fn load(kernel_dir: &Path) -> Result<Self> {
        fs::create_dir_all(kernel_dir)?;

        let reg_path = kernel_dir.join("registry.toml");
        let mut registry = if reg_path.exists() {
            let data = fs::read_to_string(&reg_path)?;
            let reg: KernelRegistry = toml::from_str(&data)
                .map_err(|e| KernelRegistryError::TomlParse(e.to_string()))?;
            reg
        } else {
            // Default: no versions, use DEFAULT_VERSION as default
            Self {
                default_version: Self::DEFAULT_VERSION.to_string(),
                versions: HashMap::new(),
                kernel_dir: kernel_dir.to_path_buf(),
            }
        };

        registry.kernel_dir = kernel_dir.to_path_buf();
        Ok(registry)
    }

    /// Save the registry to `registry.toml` in the kernel directory.
    pub fn save(&self) -> Result<()> {
        let reg_path = self.kernel_dir.join("registry.toml");
        let data = toml::to_string_pretty(&self)
            .map_err(|e| KernelRegistryError::TomlParse(e.to_string()))?;
        fs::write(&reg_path, data)?;
        Ok(())
    }

    /// Resolve a kernel binary path for the given version and profile.
    ///
    /// Resolution order:
    /// 1. Try the exact version
    /// 2. Fall back to the default version
    /// 3. Error if neither exists
    pub fn resolve(&self, version: &str, profile: &str) -> Result<PathBuf> {
        // Try exact version first
        if self.versions.contains_key(version) {
            return self.resolve_version(version, profile);
        }

        // Fall back to default version
        tracing::debug!(
            "Kernel version '{}' not found in registry, falling back to default '{}'",
            version,
            self.default_version
        );
        self.resolve_default(profile)
    }

    /// Resolve a kernel binary path using the default version.
    pub fn resolve_default(&self, profile: &str) -> Result<PathBuf> {
        if self.versions.contains_key(&self.default_version) {
            self.resolve_version(&self.default_version, profile)
        } else {
            Err(KernelRegistryError::VersionNotFound {
                version: self.default_version.clone(),
            })
        }
    }

    /// Resolve within a specific version (internal).
    fn resolve_version(&self, version: &str, profile: &str) -> Result<PathBuf> {
        let kv = self.versions.get(version).ok_or_else(|| {
            KernelRegistryError::VersionNotFound {
                version: version.to_string(),
            }
        })?;

        // Check if the profile exists in this version
        if !kv.profiles.contains(&profile.to_string()) {
            return Err(KernelRegistryError::ProfileNotFound {
                profile: profile.to_string(),
                version: version.to_string(),
            });
        }

        let kernel_path = self.kernel_dir
            .join(format!("v{version}"))
            .join(format!("vmlinux-{profile}"));

        if !kernel_path.exists() {
            return Err(KernelRegistryError::KernelFileNotFound {
                path: kernel_path.to_string_lossy().to_string(),
            });
        }

        Ok(kernel_path)
    }

    /// Get the SHA-256 hash of the base kernel for a given version.
    pub fn get_hash(&self, version: &str) -> Option<&str> {
        self.versions.get(version).map(|kv| kv.hash.as_str())
    }

    /// Add or update a kernel version entry in the registry.
    ///
    /// Walks the version directory to discover profiles, computes SHA-256
    /// hash of `vmlinux-base`, and saves the updated registry.
    pub fn register_version(&mut self, version: &str) -> Result<()> {
        let version_dir = self.kernel_dir.join(format!("v{version}"));
        if !version_dir.exists() {
            return Err(KernelRegistryError::KernelFileNotFound {
                path: version_dir.to_string_lossy().to_string(),
            });
        }

        // Discover profiles by listing vmlinux-* files
        let mut profiles: Vec<String> = Vec::new();
        let mut profile_hashes: HashMap<String, String> = HashMap::new();
        let mut base_hash: Option<String> = None;

        let dir_entries = fs::read_dir(&version_dir)?;
        for entry in dir_entries {
            let entry = entry?;
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy().to_string();

            if let Some(profile) = fname_str.strip_prefix("vmlinux-") {
                profiles.push(profile.to_string());
                let hash = compute_sha256(&entry.path())?;
                if profile == "base" {
                    base_hash = Some(hash.clone());
                }
                profile_hashes.insert(profile.to_string(), hash);
            }
        }

        profiles.sort();
        let hash = base_hash.unwrap_or_else(|| {
            // Fall back to first profile's hash if no base
            profile_hashes.values().next().cloned().unwrap_or_default()
        });

        self.versions.insert(version.to_string(), KernelVersion {
            profiles,
            hash,
            profile_hashes,
        });

        self.save()?;
        Ok(())
    }

    /// Set the default version. Validates it exists in the registry first.
    pub fn set_default(&mut self, version: &str) -> Result<()> {
        if !self.versions.contains_key(version) {
            // Allow setting default even if version not registered yet,
            // but only if the version directory exists
            let version_dir = self.kernel_dir.join(format!("v{version}"));
            if !version_dir.exists() {
                return Err(KernelRegistryError::VersionNotFound {
                    version: version.to_string(),
                });
            }
        }
        self.default_version = version.to_string();
        self.save()?;
        Ok(())
    }

    /// List all installed versions.
    pub fn list_versions(&self) -> Vec<&str> {
        let mut versions: Vec<&str> = self.versions.keys().map(|s| s.as_str()).collect();
        versions.sort_by(|a, b| {
            // Sort by version (semver-like: major.minor.patch)
            let a_parts: Vec<u32> = a.split('.').filter_map(|p| p.parse().ok()).collect();
            let b_parts: Vec<u32> = b.split('.').filter_map(|p| p.parse().ok()).collect();
            a_parts.cmp(&b_parts)
        });
        versions
    }

    /// Check if a specific version + profile is available.
    pub fn has_kernel(&self, version: &str, profile: &str) -> bool {
        self.versions.get(version).map_or(false, |kv| {
            kv.profiles.contains(&profile.to_string())
        })
    }

    /// Compute the SHA-256 hash of a kernel file for integrity verification.
    pub fn compute_kernel_hash(path: &Path) -> Result<String> {
        compute_sha256(path)
    }

    /// Verify that a kernel file matches a given hash.
    pub fn verify_kernel_hash(path: &Path, expected_hash: &str) -> Result<()> {
        let computed = compute_sha256(path)?;
        if computed != expected_hash {
            return Err(KernelRegistryError::HashMismatch {
                expected: expected_hash.to_string(),
                computed,
            });
        }
        Ok(())
    }
}

/// Compute the SHA-256 hex digest of a file.
fn compute_sha256(path: &Path) -> Result<String> {
    use sha2::{Sha256, Digest};
    let data = fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_registry() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let kernel_dir = tmp.path().join("kernel");
        fs::create_dir_all(&kernel_dir).unwrap();
        (tmp, kernel_dir)
    }

    fn create_fake_kernel(kernel_dir: &Path, version: &str, profile: &str) {
        let version_dir = kernel_dir.join(format!("v{version}"));
        fs::create_dir_all(&version_dir).unwrap();
        let kernel_path = version_dir.join(format!("vmlinux-{profile}"));
        // Write some deterministic content so hash is stable
        let content = format!("fake kernel {version} {profile}");
        fs::write(&kernel_path, content).unwrap();
    }

    #[test]
    fn test_load_empty_registry() {
        let (tmp, kernel_dir) = setup_test_registry();
        let reg = KernelRegistry::load(&kernel_dir).unwrap();
        assert_eq!(reg.default_version, KernelRegistry::DEFAULT_VERSION);
        assert!(reg.versions.is_empty());
        let _ = tmp;
    }

    #[test]
    fn test_register_version_discovers_profiles() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        create_fake_kernel(&kernel_dir, "7.1.4", "gpu-vk");

        reg.register_version("7.1.4").unwrap();

        let kv = reg.versions.get("7.1.4").unwrap();
        assert!(kv.profiles.contains(&"base".to_string()));
        assert!(kv.profiles.contains(&"gpu-vk".to_string()));
        assert!(!kv.hash.is_empty());

        // Verify registry.toml was saved
        let reg_path = kernel_dir.join("registry.toml");
        assert!(reg_path.exists());

        let _ = tmp;
    }

    #[test]
    fn test_resolve_exact_version() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("7.1.4").unwrap();

        let path = reg.resolve("7.1.4", "base").unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("v7.1.4/vmlinux-base"));

        let _ = tmp;
    }

    #[test]
    fn test_resolve_fallback_to_default() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("7.1.4").unwrap();

        // Request a non-existent version → fall back to default (7.1.4)
        let path = reg.resolve("6.8.1", "base").unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("v7.1.4/vmlinux-base"));

        let _ = tmp;
    }

    #[test]
    fn test_resolve_profile_not_found() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("7.1.4").unwrap();

        let result = reg.resolve("7.1.4", "gpu-vfio");
        assert!(result.is_err());
        match result {
            Err(KernelRegistryError::ProfileNotFound { profile, .. }) => {
                assert_eq!(profile, "gpu-vfio");
            }
            _ => panic!("expected ProfileNotFound error"),
        }

        let _ = tmp;
    }

    #[test]
    fn test_resolve_no_versions_error() {
        let (_tmp, kernel_dir) = setup_test_registry();
        let reg = KernelRegistry::load(&kernel_dir).unwrap();

        // No versions registered → error
        let result = reg.resolve("7.1.4", "base");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_default_version() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "6.8.1", "base");
        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("6.8.1").unwrap();
        reg.register_version("7.1.4").unwrap();

        reg.set_default("6.8.1").unwrap();
        assert_eq!(reg.default_version, "6.8.1");

        // Reload to verify persistence
        let reg2 = KernelRegistry::load(&kernel_dir).unwrap();
        assert_eq!(reg2.default_version, "6.8.1");

        let _ = tmp;
    }

    #[test]
    fn test_get_hash() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("7.1.4").unwrap();

        let hash = reg.get_hash("7.1.4").unwrap();
        assert!(!hash.is_empty());

        let hash2 = reg.get_hash("6.8.1");
        assert!(hash2.is_none());

        let _ = tmp;
    }

    #[test]
    fn test_verify_kernel_hash() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("7.1.4").unwrap();

        let kernel_path = kernel_dir.join("v7.1.4/vmlinux-base");
        let stored_hash = reg.get_hash("7.1.4").unwrap();

        // Should pass
        KernelRegistry::verify_kernel_hash(&kernel_path, stored_hash).unwrap();

        // Should fail with mismatched hash
        let result = KernelRegistry::verify_kernel_hash(&kernel_path, "deadbeef");
        assert!(result.is_err());
        match result {
            Err(KernelRegistryError::HashMismatch { expected, .. }) => {
                assert_eq!(expected, "deadbeef");
            }
            _ => panic!("expected HashMismatch error"),
        }

        let _ = tmp;
    }

    #[test]
    fn test_list_versions() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "6.8.1", "base");
        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        reg.register_version("6.8.1").unwrap();
        reg.register_version("7.1.4").unwrap();

        let versions = reg.list_versions();
        assert_eq!(versions.len(), 2);
        // Should be sorted: 6.8.1, 7.1.4
        assert!(versions[0] < versions[1]);

        let _ = tmp;
    }

    #[test]
    fn test_has_kernel() {
        let (tmp, kernel_dir) = setup_test_registry();
        let mut reg = KernelRegistry::load(&kernel_dir).unwrap();

        create_fake_kernel(&kernel_dir, "7.1.4", "base");
        create_fake_kernel(&kernel_dir, "7.1.4", "gpu-vk");
        reg.register_version("7.1.4").unwrap();

        assert!(reg.has_kernel("7.1.4", "base"));
        assert!(reg.has_kernel("7.1.4", "gpu-vk"));
        assert!(!reg.has_kernel("7.1.4", "gpu-vfio"));
        assert!(!reg.has_kernel("6.8.1", "base"));

        let _ = tmp;
    }

    #[test]
    fn test_compute_sha256_consistency() {
        let (tmp, kernel_dir) = setup_test_registry();

        let test_file = kernel_dir.join("test_kernel.bin");
        fs::write(&test_file, b"hello kernel world").unwrap();

        let hash1 = compute_sha256(&test_file).unwrap();
        let hash2 = compute_sha256(&test_file).unwrap();
        assert_eq!(hash1, hash2, "SHA-256 should be deterministic");

        let _ = tmp;
    }

}
