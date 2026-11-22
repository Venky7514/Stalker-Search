pub mod brave;
pub mod free;
pub mod google;
pub mod searxng;
pub mod serper;

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

/// Builds the selected `SearchEngine` from the user's configuration and optional CLI overrides.
pub fn build_engine(
    kind: EngineKind,
    config: &AppConfig,
    api_key_override: Option<String>,
    cx_override: Option<String>,
    url_override: Option<String>,
) -> Result<Box<dyn SearchEngine>> {
    match kind {
        EngineKind::Free => {
            let searx_url = url_override
                .or_else(|| config.searxng.base_url.clone())
                .filter(|s| !s.trim().is_empty());
            Ok(Box::new(free::FreeSearchEngine::new(searx_url)?))
        }
        EngineKind::Google => {
            let api_key = api_key_override
                .or_else(|| config.google.api_key.clone())
                .filter(|s| !s.trim().is_empty());
            let cx = cx_override
                .or_else(|| config.google.cx.clone())
                .filter(|s| !s.trim().is_empty());

            match (api_key, cx) {
                (Some(key), Some(cx_id)) => {
                    Ok(Box::new(google::GoogleCustomSearch::new(key, cx_id)?))
                }
                _ => bail!(
                    "Google Custom Search requires both an API Key and a Programmable Search Engine ID (cx).\n\
                     Tip: Run `cargo run -- login` for a guided 1-click browser setup, or use `--engine free`!"
                ),
            }
        }
        EngineKind::Serper => {
            let api_key = api_key_override
                .or_else(|| config.serper.api_key.clone())
                .filter(|s| !s.trim().is_empty());

            match api_key {
                Some(key) => Ok(Box::new(serper::SerperSearch::new(key)?)),
                None => bail!(
                    "Serper.dev requires an API Key.\n\
                     Tip: Run `cargo run -- login` to sign in with Google in your browser in 1 click!"
                ),
            }
        }
        EngineKind::Brave => {
            let api_key = api_key_override
                .or_else(|| config.brave.api_key.clone())
                .filter(|s| !s.trim().is_empty());

            match api_key {
                Some(key) => Ok(Box::new(brave::BraveSearch::new(key)?)),
                None => bail!(
                    "Brave Search requires an API Key.\n\
                     Tip: Run with `--engine free` (the default) to scan with zero API keys!"
                ),
            }
        }
        EngineKind::Searxng => {
            let base_url = url_override
                .or_else(|| config.searxng.base_url.clone())
                .filter(|s| !s.trim().is_empty());

            match base_url {
                Some(url) => Ok(Box::new(searxng::SearxngSearch::new(url)?)),
                None => bail!(
                    "SearXNG requires an instance base URL.\n\
                     Tip: Run `cargo run -- login` to configure your SearXNG URL!"
                ),
            }
        }
    }
}
