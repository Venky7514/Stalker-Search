use crate::models::RawSearchResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_TTL_SECS: u64 = 24 * 60 * 60; // 24 hours

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueryCache {
    pub entries: HashMap<String, CachedQueryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedQueryEntry {
    pub timestamp: u64,
    pub results: Vec<RawSearchResult>,
}

impl QueryCache {
    pub fn cache_path() -> Option<PathBuf> {
        let base = dirs::home_dir().or_else(dirs::cache_dir)?;
        Some(base.join(".stalker-search").join("query_cache.json"))
    }

    pub fn purge_disk() -> bool {
        if let Some(path) = Self::cache_path() {
            if path.exists() {
                return fs::remove_file(path).is_ok();
            }
        }
        false
    }

    pub fn load() -> Self {
        let _ = Self::purge_disk();
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<Vec<RawSearchResult>> {
        let now = current_unix_time();
        if let Some(entry) = self.entries.get(key) {
            if now.saturating_sub(entry.timestamp) <= CACHE_TTL_SECS && !entry.results.is_empty() {
                return Some(entry.results.clone());
            }
        }
        // Also check unquoted equivalent key
        let unquoted = key.replace('"', "");
        if let Some(entry) = self.entries.get(&unquoted) {
            if now.saturating_sub(entry.timestamp) <= CACHE_TTL_SECS && !entry.results.is_empty() {
                return Some(entry.results.clone());
            }
        }
        None
    }

    pub fn insert(&mut self, key: String, results: Vec<RawSearchResult>) {
        if results.is_empty() {
            return;
        }
        self.entries.insert(
            key,
            CachedQueryEntry {
                timestamp: current_unix_time(),
                results,
            },
        );
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
