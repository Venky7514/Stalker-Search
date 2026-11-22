use crate::engines::SearchEngine;
use crate::models::{DorkQuery, RawSearchResult};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Brave Web Search API client (`https://api.search.brave.com/res/v1/web/search`).
pub struct BraveSearch {
    client: Client,
    api_key: String,
}

impl BraveSearch {
    pub fn new(api_key: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("stalker-search/0.1.0")
            .build()?;
        Ok(Self { client, api_key })
    }
}

#[derive(Debug, Deserialize)]
struct BraveResponse {
    web: Option<BraveWebResults>,
}

#[derive(Debug, Deserialize)]
struct BraveWebResults {
    #[serde(default)]
    results: Vec<BraveItem>,
}

#[derive(Debug, Deserialize)]
struct BraveItem {
    title: Option<String>,
    url: Option<String>,
    description: Option<String>,
}

#[async_trait]
impl SearchEngine for BraveSearch {
    fn name(&self) -> &'static str {
        "Brave Search"
    }

    async fn search(&self, dork: &DorkQuery, max_results: usize) -> Result<Vec<RawSearchResult>> {
        let count = max_results.clamp(1, 20).to_string();

        let resp = self
            .client
            .get("https://api.search.brave.com/res/v1/web/search")
            .header("Accept", "application/json")
            .header("X-Subscription-Token", &self.api_key)
            .query(&[("q", dork.query.as_str()), ("count", count.as_str())])
            .send()
            .await
            .context("Failed to send request to Brave Search API")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Brave Search API returned HTTP {}: {}", status, body);
        }

        let parsed: BraveResponse = resp
            .json()
            .await
            .context("Failed to parse Brave Search JSON response")?;

        let items = parsed.web.map(|w| w.results).unwrap_or_default();
        let results = items
            .into_iter()
            .filter_map(|item| {
                let url = item.url?;
                Some(RawSearchResult {
                    title: item.title.unwrap_or_else(|| url.clone()),
                    url,
                    snippet: item.description.unwrap_or_default(),
                    category: dork.category,
                    dork_used: dork.query.clone(),
                    engine: self.name().to_string(),
                })
            })
            .collect();

        Ok(results)
    }
}
