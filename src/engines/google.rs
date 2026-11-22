use crate::engines::SearchEngine;
use crate::models::{DorkQuery, RawSearchResult};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Official Google Custom Search JSON API client (`https://www.googleapis.com/customsearch/v1`).
/// Supports multi-page pagination via `start` parameter (`1, 11, 21...`).
pub struct GoogleCustomSearch {
    client: Client,
    api_key: String,
    cx: String,
}

impl GoogleCustomSearch {
    pub fn new(api_key: String, cx: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("stalker-search/0.1.0")
            .build()?;
        Ok(Self {
            client,
            api_key,
            cx,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GoogleSearchResponse {
    #[serde(default)]
    items: Vec<GoogleSearchItem>,
}

#[derive(Debug, Deserialize)]
struct GoogleSearchItem {
    title: Option<String>,
    link: Option<String>,
    snippet: Option<String>,
}

#[async_trait]
impl SearchEngine for GoogleCustomSearch {
    fn name(&self) -> &'static str {
        "Google Custom Search (Multi-Page)"
    }

    async fn search(&self, dork: &DorkQuery, max_results: usize) -> Result<Vec<RawSearchResult>> {
        let mut all_results = Vec::new();
        let target_total = max_results.clamp(1, 50);
        let mut start_idx = 1usize;

        while all_results.len() < target_total && start_idx <= 41 {
            let num = (target_total - all_results.len()).clamp(1, 10).to_string();
            let start_str = start_idx.to_string();

            let resp = self
                .client
                .get("https://www.googleapis.com/customsearch/v1")
                .query(&[
                    ("key", self.api_key.as_str()),
                    ("cx", self.cx.as_str()),
                    ("q", dork.query.as_str()),
                    ("num", num.as_str()),
                    ("start", start_str.as_str()),
                ])
                .send()
                .await
                .context("Failed to send request to Google Custom Search API")?;

            let status = resp.status();
            if !status.is_success() {
                if all_results.is_empty() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("Google Custom Search API returned HTTP {}: {}", status, body);
                }
                break;
            }

            let parsed: GoogleSearchResponse = resp
                .json()
                .await
                .context("Failed to parse Google Custom Search JSON response")?;

            let page_count = parsed.items.len();
            if page_count == 0 {
                break;
            }

            for item in parsed.items {
                if let Some(url) = item.link {
                    all_results.push(RawSearchResult {
                        title: item.title.unwrap_or_else(|| url.clone()),
                        url,
                        snippet: item.snippet.unwrap_or_default(),
                        category: dork.category,
                        dork_used: dork.query.clone(),
                        engine: self.name().to_string(),
                    });
                }
            }

            if page_count < 10 {
                break;
            }
            start_idx += 10;
        }

        Ok(all_results)
    }
}
