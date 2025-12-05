//! DNS cache implementation for reducing repeated DNS lookups
//!
//! This module provides a thread-safe LRU cache for DNS resolutions with TTL support.
//! It significantly improves performance by avoiding redundant DNS queries.

use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use crate::hash::{HashMap, HASHER};
use crate::sync::Mutex;

/// Default TTL for cached DNS entries (60 seconds)
const DEFAULT_DNS_TTL: Duration = Duration::from_secs(60);

/// Maximum number of entries in the cache
const DEFAULT_MAX_ENTRIES: usize = 1000;

/// A cached DNS resolution result with expiration time
#[derive(Clone, Debug)]
struct CachedEntry {
    addrs: Vec<SocketAddr>,
    expires_at: Instant,
}

impl CachedEntry {
    fn new(addrs: Vec<SocketAddr>, ttl: Duration) -> Self {
        Self {
            addrs,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// DNS cache with TTL and LRU eviction
#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<Mutex<DnsCacheInner>>,
    default_ttl: Duration,
}

struct DnsCacheInner {
    cache: HashMap<String, CachedEntry>,
    max_entries: usize,
}

impl DnsCache {
    /// Creates a new DNS cache with default settings
    pub fn new() -> Self {
        Self::with_config(DEFAULT_DNS_TTL, DEFAULT_MAX_ENTRIES)
    }

    /// Creates a new DNS cache with custom TTL and max entries
    pub fn with_config(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DnsCacheInner {
                cache: HashMap::with_hasher(HASHER),
                max_entries,
            })),
            default_ttl,
        }
    }

    /// Gets cached addresses for a hostname if available and not expired
    pub fn get(&self, host: &str) -> Option<Vec<SocketAddr>> {
        let mut inner = self.inner.lock();

        if let Some(entry) = inner.cache.get(host) {
            if !entry.is_expired() {
                trace!("DNS cache hit for {}", host);
                return Some(entry.addrs.clone());
            } else {
                trace!("DNS cache entry expired for {}", host);
                inner.cache.remove(host);
            }
        }

        trace!("DNS cache miss for {}", host);
        None
    }

    /// Inserts addresses into the cache with default TTL
    pub fn insert(&self, host: String, addrs: Vec<SocketAddr>) {
        self.insert_with_ttl(host, addrs, self.default_ttl);
    }

    /// Inserts addresses into the cache with custom TTL
    pub fn insert_with_ttl(&self, host: String, addrs: Vec<SocketAddr>, ttl: Duration) {
        let mut inner = self.inner.lock();

        // Simple eviction strategy: remove oldest entries if cache is full
        if inner.cache.len() >= inner.max_entries {
            // Remove expired entries first
            inner.cache.retain(|_, entry| !entry.is_expired());

            // If still full, remove one random entry (HashMap doesn't preserve insertion order)
            if inner.cache.len() >= inner.max_entries {
                if let Some(key) = inner.cache.keys().next().cloned() {
                    trace!("Evicting DNS cache entry for {}", key);
                    inner.cache.remove(&key);
                }
            }
        }

        trace!("Caching DNS result for {} (TTL: {:?})", host, ttl);
        inner.cache.insert(host, CachedEntry::new(addrs, ttl));
    }

    /// Clears all entries from the cache
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.inner.lock().cache.clear();
    }

    /// Returns the number of cached entries (including expired ones)
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.lock().cache.len()
    }

    /// Returns true if the cache is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().cache.is_empty()
    }

    /// Removes expired entries from the cache
    #[allow(dead_code)]
    pub fn cleanup_expired(&self) {
        let mut inner = self.inner.lock();
        let before = inner.cache.len();
        inner.cache.retain(|_, entry| !entry.is_expired());
        let removed = before - inner.cache.len();
        if removed > 0 {
            trace!("Cleaned up {} expired DNS cache entries", removed);
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global DNS cache instance shared across all resolvers
pub static GLOBAL_DNS_CACHE: LazyLock<DnsCache> = LazyLock::new(DnsCache::new);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_cache_insert_and_get() {
        let cache = DnsCache::new();
        let addrs = vec![SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 80)];

        cache.insert("example.com".to_string(), addrs.clone());

        let cached = cache.get("example.com").unwrap();
        assert_eq!(cached, addrs);
    }

    #[test]
    fn test_cache_expiration() {
        let cache = DnsCache::with_config(Duration::from_millis(10), 100);
        let addrs = vec![SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 80)];

        cache.insert("example.com".to_string(), addrs.clone());

        // Should be cached
        assert!(cache.get("example.com").is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Should be expired
        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn test_cache_miss() {
        let cache = DnsCache::new();
        assert!(cache.get("nonexistent.com").is_none());
    }

    #[test]
    fn test_cache_cleanup() {
        let cache = DnsCache::with_config(Duration::from_millis(10), 100);
        let addrs = vec![SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 80)];

        cache.insert("example.com".to_string(), addrs);
        assert_eq!(cache.len(), 1);

        std::thread::sleep(Duration::from_millis(20));
        cache.cleanup_expired();

        assert_eq!(cache.len(), 0);
    }
}
