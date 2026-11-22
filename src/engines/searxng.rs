use crate::engines::SearchEngine;
use crate::models::{DorkQuery, RawSearchResult};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::time::Duration;

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Self-hosted or public SearXNG instance client.
/// Supports multi-page pagination (`pageno=1, 2, 3...`) across both JSON and HTML modes.
pub struct SearxngSearch {
    client: Client,
    base_url: String,
}

impl SearxngSearch {
    pub fn new(base_url: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(BROWSER_UA)
            .build()?;
        let trimmed = base_url.trim_end_matches('/').to_string();
        Ok(Self {
            client,
            base_url: trimmed,
        })
    }

    async fn search_json(
        &self,
        endpoint: &str,
        dork: &DorkQuery,
        max_results: usize,
    ) -> Result<Vec<RawSearchResult>> {
        let mut all_results = Vec::new();
        let pages = ((max_results + 9) / 10).clamp(1, 5);

        for pageno in 1..=pages {
            let p_str = pageno.to_string();
            let resp = self
                .client
                .get(endpoint)
                .query(&[
                    ("q", dork.query.as_str()),
                    ("format", "json"),
                    ("pageno", p_str.as_str()),
                ])
                .send()
                .await?;

            if !resp.status().is_success() {
                if all_results.is_empty() {
                    bail!("SearXNG JSON returned HTTP {}", resp.status());
                }
                break;
            }

            let parsed: SearxngResponse = resp.json().await?;
            if parsed.results.is_empty() {
                break;
            }

            for item in parsed.results {
                if let Some(url) = item.url {
                    all_results.push(RawSearchResult {
                        title: item.title.unwrap_or_else(|| url.clone()),
                        url,
                        snippet: item.content.unwrap_or_default(),
                        category: dork.category,
                        dork_used: dork.query.clone(),
                        engine: "SearXNG (JSON)".to_string(),
                    });
                }
                if all_results.len() >= max_results {
                    break;
                }
            }

            if all_results.len() >= max_results {
                break;
            }
        }

        Ok(all_results)
    }

    async fn search_html(
        &self,
        endpoint: &str,
        dork: &DorkQuery,
        max_results: usize,
    ) -> Result<Vec<RawSearchResult>> {
        let mut all_results = Vec::new();
        let pages = ((max_results + 9) / 10).clamp(1, 5);
        let article_sel = Selector::parse("article.result, div.result").unwrap();
        let link_sel = Selector::parse("h3 a, a.url_header, h4 a").unwrap();
        let snippet_sel = Selector::parse("p.content, div.content, p.result-content").unwrap();

        for pageno in 1..=pages {
            let p_str = pageno.to_string();
            let resp = self
                .client
                .get(endpoint)
                .query(&[("q", dork.query.as_str()), ("pageno", p_str.as_str())])
                .send()
                .await
                .with_context(|| format!("Failed to reach SearXNG instance at {}", endpoint))?;

            let status = resp.status();
            if !status.is_success() {
                if all_results.is_empty() {
                    bail!("SearXNG HTML returned HTTP {}", status);
                }
                break;
            }

            let html = resp.text().await.unwrap_or_default();
            if html.contains("Making sure you&#39;re not a bot!")
                || html.contains("Making sure you're not a bot!")
            {
                bail!(
                    "SearXNG instance at {} is gated by an anti-bot challenge.",
                    self.base_url
                );
            }

            let doc = Html::parse_document(&html);
            let mut page_hits = 0usize;
            for node in doc.select(&article_sel) {
                if all_results.len() >= max_results {
                    break;
                }
                let Some(link_el) = node.select(&link_sel).next() else {
                    continue;
                };
                let Some(href) = link_el.value().attr("href") else {
                    continue;
                };
                if !href.starts_with("http://") && !href.starts_with("https://") {
                    continue;
                }

                let title = link_el
                    .text()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim()
                    .to_string();
                let snippet = node
                    .select(&snippet_sel)
                    .next()
                    .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                    .unwrap_or_default();

                all_results.push(RawSearchResult {
                    title: if title.is_empty() {
                        href.to_string()
                    } else {
                        title
                    },
                    url: href.to_string(),
                    snippet,
                    category: dork.category,
                    dork_used: dork.query.clone(),
                    engine: "SearXNG (HTML)".to_string(),
                });
                page_hits += 1;
            }

            if page_hits == 0 || all_results.len() >= max_results {
                break;
            }
        }

        Ok(all_results)
    }
}

#[derive(Debug, Deserialize)]
struct SearxngResponse {
    #[serde(default)]
    results: Vec<SearxngItem>,
}

#[derive(Debug, Deserialize)]
struct SearxngItem {
    title: Option<String>,
    url: Option<String>,
    content: Option<String>,
}

#[async_trait]
impl SearchEngine for SearxngSearch {
    fn name(&self) -> &'static str {
        "SearXNG Metasearch (Multi-Page)"
    }

    async fn search(&self, dork: &DorkQuery, max_results: usize) -> Result<Vec<RawSearchResult>> {
        let endpoint = format!("{}/search", self.base_url);

        if let Ok(hits) = self.search_json(&endpoint, dork, max_results).await {
            if !hits.is_empty() {
                return Ok(hits);
            }
        }

        self.search_html(&endpoint, dork, max_results).await
    }
}
