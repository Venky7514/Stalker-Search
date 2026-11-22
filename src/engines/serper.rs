use crate::engines::SearchEngine;
use crate::models::{DorkQuery, RawSearchResult};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Serper.dev Google Search API client (`https://google.serper.dev/search`).
/// Supports multi-page pagination via `page` (`1, 2, 3...`).
pub struct SerperSearch {
    client: Client,
    api_key: String,
}

impl SerperSearch {
    pub fn new(api_key: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("stalker-search/0.1.0")
            .build()?;
        Ok(Self { client, api_key })
    }
}

#[derive(Debug, Serialize)]
struct SerperRequest<'a> {
    q: &'a str,
    num: usize,
    page: usize,
}

#[derive(Debug, Deserialize)]
struct SerperResponse {
    #[serde(default)]
    organic: Vec<SerperItem>,
}

#[derive(Debug, Deserialize)]
struct SerperItem {
    title: Option<String>,
    link: Option<String>,
    snippet: Option<String>,
}

#[async_trait]
impl SearchEngine for SerperSearch {
    fn name(&self) -> &'static str {
        "Serper.dev Google (Multi-Page)"
    }

    async fn search(&self, dork: &DorkQuery, max_results: usize) -> Result<Vec<RawSearchResult>> {
        let mut all_results = Vec::new();
        let pages = ((max_results + 9) / 10).clamp(1, 5);

        for page in 1..=pages {
            let payload = SerperRequest {
                q: &dork.query,
                num: 10,
                page,
            };

            let resp = self
                .client
                .post("https://google.serper.dev/search")
                .header("X-API-KEY", &self.api_key)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .context("Failed to send request to Serper.dev API")?;

            let status = resp.status();
            if !status.is_success() {
                if all_results.is_empty() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("Serper.dev API returned HTTP {}: {}", status, body);
                }
                break;
            }

            let parsed: SerperResponse = resp
                .json()
                .await
                .context("Failed to parse Serper.dev JSON response")?;

            let count = parsed.organic.len();
            if count == 0 {
                break;
            }

            for item in parsed.organic {
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

            if count < 10 || all_results.len() >= max_results {
                break;
            }
        }

        Ok(all_results)
    }
}
