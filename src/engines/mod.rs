pub mod free;
pub mod searxng;

use crate::config::AppConfig;
use crate::models::{DorkQuery, EngineKind, RawSearchResult};
use anyhow::{bail, Result};
use async_trait::async_trait;

/// Common trait implemented by all search engine backends.
#[async_trait]
pub trait SearchEngine: Send + Sync {
    /// Human-readable engine name.
    fn name(&self) -> &'static str;

    /// Executes a single dork query and returns up to `max_results` hits.
    async fn search(&self, dork: &DorkQuery, max_results: usize) -> Result<Vec<RawSearchResult>>;
}

/// Builds the active `SearchEngine` (`Free` zero-key mode by default, or `Searxng`).
pub fn build_engine(
    kind: EngineKind,
    config: &AppConfig,
    url_override: Option<String>,
) -> Result<Box<dyn SearchEngine>> {
    match kind {
        EngineKind::Free => {
            let searx_url = url_override
                .or_else(|| config.searxng.base_url.clone())
                .filter(|s| !s.trim().is_empty());
            Ok(Box::new(free::FreeSearchEngine::new(searx_url)?))
        }
        EngineKind::Searxng => {
            let base_url = url_override
                .or_else(|| config.searxng.base_url.clone())
                .filter(|s| !s.trim().is_empty());

            match base_url {
                Some(url) => Ok(Box::new(searxng::SearxngSearch::new(url)?)),
                None => bail!(
                    "SearXNG requires an instance base URL.\n\
                     Tip: Set it via `cargo run -- config set --engine searxng --url http://localhost:8080` or use `--engine free`."
                ),
            }
        }
    }
}
