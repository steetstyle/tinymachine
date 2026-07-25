//! Execution Cache — result memoization by code hash
//!
//! Caches execution results keyed by `blake3` hash of `(lang, code)`.
//! When the same code is submitted again, the cached result is returned
//! instantly (O(1) lookup) — the fork engine is skipped entirely.
//!
//! # Phase 1: In-Memory HashMap
//! Phase 1 uses `std::cell::RefCell<HashMap>` for simplicity. Entries
//! have a configurable TTL (default: 1 hour) and maximum count
//! (default: 10,000).
//!
//! # Phase 2: SQLite
//! Phase 2 will replace the HashMap with a SQLite database (via
//! `tinyos-memory`), enabling persistent cache across restarts and
//! concurrent access from multiple threads.
//!
//! # Safety
//! This module uses `RefCell` for interior mutability, which is safe
//! (runtime borrow-checked). No raw `unsafe` blocks.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default maximum number of cache entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default TTL for cache entries (1 hour).
const DEFAULT_TTL_SECS: u64 = 3600;

// ─── Error Types ──────────────────────────────────────────────────────

/// Errors from cache operations.
#[derive(Error, Debug)]
pub enum CacheError {
    /// The cache has reached its maximum capacity.
    #[error("Cache is full (max {max} entries). Evict entries or increase capacity.")]
    Full { max: usize },
}

/// Result alias for cache operations.
pub type Result<T> = std::result::Result<T, CacheError>;

// ─── Internal Cache Entry ─────────────────────────────────────────────

/// A cached execution result with expiration metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached execution result (stdout or serial output).
    result: String,
    /// When this entry was created (for TTL checking).
    created_at: Instant,
    /// Time-to-live for this entry.
    ttl: Duration,
}

impl CacheEntry {
    /// Check if this entry has expired.
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

// ─── Execution Cache ──────────────────────────────────────────────────

/// Execution cache — result memoization by code hash.
///
/// Stores execution results keyed by `blake3` hash of `(lang, code)`.
/// Phase 1 uses an in-memory `HashMap` with `RefCell` interior mutability.
///
/// # Examples
///
/// ```ignore
/// let cache = ExecutionCache::new(None)?;
///
/// // First execution: cache miss
/// assert!(cache.get("print(1)", "python").is_none());
///
/// // Store result
/// cache.set("print(1)", "python", "1\n")?;
///
/// // Second execution: cache hit
/// assert_eq!(cache.get("print(1)", "python"), Some("1\n".into()));
/// ```
#[derive(Debug)]
pub struct ExecutionCache {
    /// The underlying storage. `RefCell` provides interior mutability so
    /// that `get()` and `set()` can both take `&self`.
    entries: RefCell<HashMap<String, CacheEntry>>,
    /// Maximum number of entries before `set()` returns `CacheError::Full`.
    max_entries: usize,
    /// Default TTL for new entries.
    default_ttl: Duration,
}

impl ExecutionCache {
    /// Create a new execution cache.
    ///
    /// `path` is ignored in Phase 1 (HashMap-based). In Phase 2, it
    /// specifies the SQLite database path for persistent storage.
    ///
    /// # Errors
    /// Never errors in Phase 1. Returns `Ok` with an empty cache.
    pub fn new(_path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            entries: RefCell::new(HashMap::new()),
            max_entries: DEFAULT_MAX_ENTRIES,
            default_ttl: Duration::from_secs(DEFAULT_TTL_SECS),
        })
    }

    /// Compute the `blake3` hash for `(lang, code)`.
    ///
    /// The hash is computed as `hash(lang || ":" || code)` to ensure
    /// that the same code in different languages produces different keys.
    pub fn hash(code: &str, lang: &str) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(lang.as_bytes());
        hasher.update(b":");
        hasher.update(code.as_bytes());
        hasher.finalize()
    }

    /// Get cached result for `(code, lang)` if present and not expired.
    ///
    /// Returns `None` if:
    /// - The code has not been cached (cache miss).
    /// - The cached entry has expired (TTL exceeded).
    /// - The cached entry was evicted.
    pub fn get(&self, code: &str, lang: &str) -> Option<String> {
        let hash = Self::hash(code, lang);
        let key = hash.to_hex().to_string();

        let entries = self.entries.borrow();
        entries.get(&key).and_then(|entry| {
            if entry.is_expired() {
                // Entry expired — treat as cache miss.
                // The expired entry will be cleaned up on the next `set()` call.
                None
            } else {
                Some(entry.result.clone())
            }
        })
    }

    /// Store a result in the cache.
    ///
    /// Before inserting, expired entries are evicted (lazy cleanup) and
    /// the total count is checked against `max_entries`.
    ///
    /// # Errors
    /// Returns `CacheError::Full` if the cache has reached capacity
    /// after expired-entry eviction.
    pub fn set(&self, code: &str, lang: &str, result: &str) -> Result<()> {
        let hash = Self::hash(code, lang);
        let key = hash.to_hex().to_string();

        let mut entries = self.entries.borrow_mut();

        // Lazy cleanup: evict expired entries before inserting
        entries.retain(|_, entry| !entry.is_expired());

        // Check capacity after cleanup
        if entries.len() >= self.max_entries {
            return Err(CacheError::Full {
                max: self.max_entries,
            });
        }

        entries.insert(
            key,
            CacheEntry {
                result: result.to_string(),
                created_at: Instant::now(),
                ttl: self.default_ttl,
            },
        );

        Ok(())
    }

    /// Clear all entries from the cache.
    pub fn clear(&self) -> Result<()> {
        let mut entries = self.entries.borrow_mut();
        entries.clear();
        Ok(())
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }

    /// Evict all expired entries. Returns the number of entries removed.
    pub fn evict_expired(&self) -> usize {
        let mut entries = self.entries.borrow_mut();
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        before - entries.len()
    }

    /// Set a custom maximum number of entries.
    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
    }

    /// Set a custom default TTL for new entries.
    pub fn set_default_ttl(&mut self, ttl: Duration) {
        self.default_ttl = ttl;
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_miss() {
        let cache = ExecutionCache::new(None).unwrap();
        assert!(cache.get("print(1)", "python").is_none());
    }

    #[test]
    fn test_cache_hit() {
        let cache = ExecutionCache::new(None).unwrap();
        cache.set("print(1)", "python", "1\n").unwrap();
        assert_eq!(cache.get("print(1)", "python"), Some("1\n".into()));
    }

    #[test]
    fn test_cache_different_lang_different_key() {
        let cache = ExecutionCache::new(None).unwrap();
        cache.set("print(1)", "python", "1\n").unwrap();
        // Same code, different language → different hash → cache miss
        assert!(cache.get("print(1)", "node").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = ExecutionCache::new(None).unwrap();
        cache.set("foo", "python", "bar").unwrap();
        assert_eq!(cache.len(), 1);
        cache.clear().unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let cache = ExecutionCache::new(None).unwrap();
        cache.set("x", "python", "y").unwrap();
        assert_eq!(cache.len(), 1);

        // Clear expired entries — none should be expired since we just created them
        assert_eq!(cache.evict_expired(), 0);
    }

    #[test]
    fn test_cache_hash_deterministic() {
        let h1 = ExecutionCache::hash("print(1)", "python");
        let h2 = ExecutionCache::hash("print(1)", "python");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_cache_hash_differs_for_lang() {
        let h1 = ExecutionCache::hash("print(1)", "python");
        let h2 = ExecutionCache::hash("print(1)", "node");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_cache_overwrite() {
        let cache = ExecutionCache::new(None).unwrap();
        cache.set("key", "py", "old").unwrap();
        cache.set("key", "py", "new").unwrap();
        assert_eq!(cache.get("key", "py"), Some("new".into()));
    }

    #[test]
    fn test_cache_max_entries() {
        let mut cache = ExecutionCache::new(None).unwrap();
        cache.set_max_entries(2);

        cache.set("a", "py", "1").unwrap();
        cache.set("b", "py", "2").unwrap();
        // Third entry should fail
        let result = cache.set("c", "py", "3");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CacheError::Full { max: 2 }));
    }

    #[test]
    fn test_cache_lazy_eviction() {
        let mut cache = ExecutionCache::new(None).unwrap();
        cache.set_max_entries(2);
        cache.set_default_ttl(Duration::from_millis(1));

        cache.set("a", "py", "1").unwrap();

        // Wait for TTL expiry
        std::thread::sleep(Duration::from_millis(2));

        // set() should evict expired "a" and then insert "b" and "c"
        cache.set("b", "py", "2").unwrap();
        cache.set("c", "py", "3").unwrap();

        // "a" should no longer be available
        assert!(cache.get("a", "py").is_none());
        // "b" and "c" should be available
        assert_eq!(cache.get("b", "py"), Some("2".into()));
        assert_eq!(cache.get("c", "py"), Some("3".into()));
    }
}
