use crate::dorks::ScanTarget;
use crate::engines::searxng::SearxngSearch;
use crate::engines::SearchEngine;
use crate::models::{DorkCategory, DorkQuery, RawSearchResult};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;
use url::Url;

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const API_UA: &str = "stalker-search/0.1.0 (https://github.com/open-source/stalker-search)";

static XML_ITEM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<item>(.*?)</item>").expect("Valid XML item regex"));
static XML_ENTRY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<entry>(.*?)</entry>").expect("Valid XML entry regex"));
static XML_TITLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<title[^>]*>(.*?)</title>").expect("Valid XML title regex"));
static XML_LINK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<link>(.*?)</link>").expect("Valid XML link regex"));
static XML_SOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<source[^>]*url="([^"]+)"[^>]*>(.*?)</source>"#).expect("Valid XML source regex")
});
static XML_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<id>(.*?)</id>").expect("Valid XML id regex"));
static XML_SUMMARY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<summary[^>]*>(.*?)</summary>").expect("Valid XML summary regex"));

/// Zero-Key Privacy Search Engine:
/// Combines SearXNG (if configured) + DuckDuckGo HTML + Brave Search HTML + 18 Keyless Public APIs (including Google News RSS).
pub struct FreeSearchEngine {
    client: Client,
    searxng: Option<SearxngSearch>,
}

impl FreeSearchEngine {
    pub fn new(searxng_url: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(BROWSER_UA)
            .build()?;
        let searxng = searxng_url.and_then(|u| SearxngSearch::new(u).ok());
        Ok(Self { client, searxng })
    }

    /// Queries DuckDuckGo HTML endpoint (`https://html.duckduckgo.com/html/`) using form POST.
    async fn search_ddg_html(
        &self,
        dork: &DorkQuery,
        max_results: usize,
    ) -> Result<Vec<RawSearchResult>> {
        let resp = self
            .client
            .post("https://html.duckduckgo.com/html/")
            .form(&[("q", dork.query.as_str())])
            .send()
            .await?;

        let status = resp.status();
        let html = resp.text().await.unwrap_or_default();

        if status == reqwest::StatusCode::ACCEPTED
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::FORBIDDEN
            || html.contains("anomaly-modal")
            || html.contains("Unfortunately, bots use DuckDuckGo too")
        {
            bail!("HUMAN_VERIFICATION_REQUIRED (HTTP {})", status.as_u16());
        }

        if !status.is_success() {
            bail!("DuckDuckGo HTML returned HTTP {}", status);
        }

        let document = Html::parse_document(&html);
        let result_sel = Selector::parse(".result, .web-result").unwrap();
        let title_sel = Selector::parse("a.result__a").unwrap();
        let snippet_sel = Selector::parse(".result__snippet").unwrap();

        let mut results = Vec::new();
        for node in document.select(&result_sel) {
            if results.len() >= max_results {
                break;
            }
            let Some(title_el) = node.select(&title_sel).next() else {
                continue;
            };
            let Some(raw_href) = title_el.value().attr("href") else {
                continue;
            };

            let clean_url = unwrap_ddg_url(raw_href);
            if !clean_url.starts_with("http://") && !clean_url.starts_with("https://") {
                continue;
            }
            if clean_url.contains("duckduckgo.com/y.js") {
                continue;
            }

            let title = title_el
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

            let cat = infer_category(&clean_url, &title, dork.category);

            results.push(RawSearchResult {
                title: if title.is_empty() {
                    clean_url.clone()
                } else {
                    title
                },
                url: clean_url,
                snippet,
                category: cat,
                dork_used: dork.query.clone(),
                engine: "DuckDuckGo SERP".to_string(),
            });
        }

        Ok(results)
    }

    /// Secondary zero-key SERP via Brave Search HTML (`https://search.brave.com/search?q=...`).
    /// Also extracts Brave FAQ / Data Broker (ZoomInfo/RocketReach) contact cards.
    async fn search_brave_html(
        &self,
        dork: &DorkQuery,
        max_results: usize,
    ) -> Result<Vec<RawSearchResult>> {
        let resp = self
            .client
            .get("https://search.brave.com/search")
            .query(&[("q", dork.query.as_str())])
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let html = resp.text().await.unwrap_or_default();
        let document = Html::parse_document(&html);

        let web_sel = Selector::parse("div.snippet[data-type=\"web\"]").unwrap();
        let link_sel = Selector::parse("a.l1, div.result-content a[href^=\"http\"]").unwrap();
        let title_sel = Selector::parse("div.title, div.search-snippet-title").unwrap();
        let snippet_sel =
            Selector::parse("div.generic-snippet div.content, div.snippet-description").unwrap();

        let mut results = Vec::new();
        for node in document.select(&web_sel) {
            if results.len() >= max_results {
                break;
            }
            let Some(link_el) = node.select(&link_sel).next() else {
                continue;
            };
            let Some(raw_href) = link_el.value().attr("href") else {
                continue;
            };
            if !raw_href.starts_with("http://") && !raw_href.starts_with("https://") {
                continue;
            }
            if raw_href.contains("search.brave.com") {
                continue;
            }

            let title = node
                .select(&title_sel)
                .next()
                .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    link_el
                        .text()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .trim()
                        .to_string()
                });

            let snippet = node
                .select(&snippet_sel)
                .next()
                .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                .unwrap_or_default();

            let cat = infer_category(raw_href, &title, dork.category);

            results.push(RawSearchResult {
                title: if title.is_empty() {
                    raw_href.to_string()
                } else {
                    title
                },
                url: raw_href.to_string(),
                snippet,
                category: cat,
                dork_used: dork.query.clone(),
                engine: "Brave SERP".to_string(),
            });
        }

        let faq_sel = Selector::parse("div.faq-item").unwrap();
        let faq_q_sel = Selector::parse("summary div.title").unwrap();
        let faq_a_sel = Selector::parse("div.content").unwrap();
        let faq_link_sel = Selector::parse("a[href^=\"http\"]").unwrap();

        for faq in document.select(&faq_sel) {
            let Some(link_el) = faq.select(&faq_link_sel).next() else {
                continue;
            };
            let Some(href) = link_el.value().attr("href") else {
                continue;
            };
            let question = faq
                .select(&faq_q_sel)
                .next()
                .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                .unwrap_or_default();
            let answer = faq
                .select(&faq_a_sel)
                .next()
                .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                .unwrap_or_default();

            if !answer.is_empty() {
                let cat = infer_category(href, &question, DorkCategory::ContactAndPii);
                results.push(RawSearchResult {
                    title: if question.is_empty() {
                        href.to_string()
                    } else {
                        question
                    },
                    url: href.to_string(),
                    snippet: answer,
                    category: cat,
                    dork_used: dork.query.clone(),
                    engine: "Brave SERP FAQ".to_string(),
                });
            }
        }

        Ok(results)
    }
}

/// Automatically classifies a result into the most specific category based on its URL/title.
pub fn infer_category(url: &str, title: &str, fallback: DorkCategory) -> DorkCategory {
    let u = url.to_lowercase();
    let t = title.to_lowercase();

    if u.ends_with(".pdf")
        || u.ends_with(".doc")
        || u.ends_with(".docx")
        || u.ends_with(".xls")
        || u.ends_with(".xlsx")
        || u.ends_with(".csv")
    {
        DorkCategory::DocumentsAndFiles
    } else if u.contains("zoominfo.com")
        || u.contains("rocketreach.co")
        || u.contains("signalhire.com")
        || u.contains("lusha.com")
        || t.contains("phone number")
        || t.contains("email:")
    {
        DorkCategory::ContactAndPii
    } else if u.contains("linkedin.com")
        || u.contains("instagram.com")
        || u.contains("facebook.com")
        || u.contains("twitter.com")
        || u.contains("x.com")
        || u.contains("youtube.com")
        || u.contains("researchgate.net")
        || u.contains("tiktok.com")
        || u.contains("linktr.ee")
        || u.contains("orcid.org")
    {
        DorkCategory::SocialProfiles
    } else if u.contains("github.com")
        || u.contains("gitlab.com")
        || u.contains("stackoverflow.com")
        || u.contains("pastebin.com")
        || u.contains("reddit.com")
        || u.contains("medium.com")
        || u.contains("quora.com")
        || u.contains("npmjs.com")
        || u.contains("crates.io")
    {
        DorkCategory::CodeAndTech
    } else {
        fallback
    }
}

#[async_trait]
impl SearchEngine for FreeSearchEngine {
    fn name(&self) -> &'static str {
        if self.searxng.is_some() {
            "Zero-Key Multi-Engine (SearXNG + DuckDuckGo + Brave + 17 Keyless APIs)"
        } else {
            "Zero-Key Free Engine (DuckDuckGo + Brave + Google News RSS + 17 Keyless APIs)"
        }
    }

    async fn search(&self, dork: &DorkQuery, max_results: usize) -> Result<Vec<RawSearchResult>> {
        let mut combined_hits = Vec::new();

        // 1. If a SearXNG instance is configured, query SearXNG (JSON or HTML) first
        if let Some(sx) = &self.searxng {
            if let Ok(mut sx_hits) = sx.search(dork, max_results).await {
                for h in &mut sx_hits {
                    h.category = infer_category(&h.url, &h.title, h.category);
                }
                combined_hits.append(&mut sx_hits);
            }
        }

        // 2. Polite 1.8s delay between HTML SERP queries
        tokio::time::sleep(Duration::from_millis(1800)).await;

        match self.search_ddg_html(dork, max_results).await {
            Ok(mut ddg_hits) => {
                combined_hits.append(&mut ddg_hits);
                if combined_hits.is_empty() {
                    if let Ok(mut brave_hits) = self.search_brave_html(dork, max_results).await {
                        combined_hits.append(&mut brave_hits);
                    }
                }
                Ok(combined_hits)
            }
            Err(ddg_err) => {
                if let Ok(mut brave_hits) = self.search_brave_html(dork, max_results).await {
                    combined_hits.append(&mut brave_hits);
                }
                if !combined_hits.is_empty() {
                    return Ok(combined_hits);
                }
                Err(ddg_err)
            }
        }
    }
}

/// Unwraps DuckDuckGo redirect URLs like `//duckduckgo.com/l/?uddg=https%3A%2F%2F...`
fn unwrap_ddg_url(raw: &str) -> String {
    let normalized = if raw.starts_with("//") {
        format!("https:{}", raw)
    } else if raw.starts_with('/') {
        format!("https://html.duckduckgo.com{}", raw)
    } else {
        raw.to_string()
    };

    if let Ok(parsed) = Url::parse(&normalized) {
        for (k, v) in parsed.query_pairs() {
            if k == "uddg" {
                return v.into_owned();
            }
        }
    }
    raw.to_string()
}

/// Parses a Google Search (or any search engine) HTML page saved directly from the user's logged-in browser (`Ctrl+S`).
pub fn import_browser_saved_html(path: &Path) -> Result<Vec<RawSearchResult>> {
    let html = fs::read_to_string(path)
        .with_context(|| format!("Failed to read saved HTML file at {}", path.display()))?;
    let doc = Html::parse_document(&html);
    let a_sel = Selector::parse("a[href^=\"http\"]").unwrap();
    let h3_sel = Selector::parse("h3").unwrap();

    let mut results = Vec::new();
    for a_node in doc.select(&a_sel) {
        let Some(href) = a_node.value().attr("href") else {
            continue;
        };
        if href.contains("google.com/")
            || href.contains("googleusercontent.com")
            || href.contains("gstatic.com")
            || href.contains("support.google.com")
            || href.contains("accounts.google.com")
        {
            continue;
        }

        // Prefer links that wrap an `<h3>` (standard Google Search result link) or have substantial anchor text
        let title = if let Some(h3) = a_node.select(&h3_sel).next() {
            h3.text().collect::<Vec<_>>().join(" ").trim().to_string()
        } else {
            a_node
                .text()
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string()
        };

        if title.len() < 4 {
            continue;
        }

        let cat = infer_category(href, &title, DorkCategory::GeneralMentions);
        results.push(RawSearchResult {
            title: title.clone(),
            url: href.to_string(),
            snippet: format!("Imported from browser-saved search page ({})", title),
            category: cat,
            dork_used: format!("Browser HTML Import ({})", path.display()),
            engine: "Browser Google HTML Import".to_string(),
        });
    }

    Ok(results)
}

// ============================================================================
// 18 Direct Zero-Key Public APIs (Including Official Google News RSS & arXiv)
// ============================================================================

/// Concurrently queries 18 official keyless public APIs (plus Email & Phone OSINT sweeps).
pub async fn run_direct_osint_sweep(target: &ScanTarget) -> Vec<RawSearchResult> {
    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent(API_UA)
        .build()
        .unwrap_or_default();

    let mut all = Vec::new();

    // Always run Email & Phone direct OSINT sweeps if `--email` or `--phone` is provided
    let (email_phone_hits, keybase_pgp_hits) = tokio::join!(
        sweep_emails_and_phones(&client, target),
        sweep_keybase_and_pgp(&client, target),
    );
    all.extend(email_phone_hits);
    all.extend(keybase_pgp_hits);

    // If a name (or alias) is provided, run the 16 name-based keyless APIs concurrently
    if !target.full_name.trim().is_empty() || !target.aliases.is_empty() {
        let (
            google_news_hits,
            arxiv_hits,
            reddit_hits,
            github_hits,
            gitlab_hits,
            stack_hits,
            npm_hits,
            crates_hits,
            docker_hits,
            hn_hits,
            openalex_hits,
            orcid_hits,
            semantic_hits,
            crossref_hits,
            archive_hits,
            wiki_hits,
            wikidata_hits,
        ) = tokio::join!(
            sweep_google_news_rss(&client, target),
            sweep_arxiv(&client, target),
            sweep_reddit(&client, target),
            sweep_github(&client, target),
            sweep_gitlab(&client, target),
            sweep_stackexchange(&client, target),
            sweep_npm(&client, target),
            sweep_crates_io(&client, target),
            sweep_dockerhub(&client, target),
            sweep_hackernews(&client, target),
            sweep_openalex(&client, target),
            sweep_orcid(&client, target),
            sweep_semantic_scholar(&client, target),
            sweep_crossref(&client, target),
            sweep_archive_org(&client, target),
            sweep_wikipedia(&client, target),
            sweep_wikidata(&client, target),
        );

        all.extend(google_news_hits);
        all.extend(arxiv_hits);
        all.extend(reddit_hits);
        all.extend(github_hits);
        all.extend(gitlab_hits);
        all.extend(stack_hits);
        all.extend(npm_hits);
        all.extend(crates_hits);
        all.extend(docker_hits);
        all.extend(hn_hits);
        all.extend(openalex_hits);
        all.extend(orcid_hits);
        all.extend(semantic_hits);
        all.extend(crossref_hits);
        all.extend(archive_hits);
        all.extend(wiki_hits);
        all.extend(wikidata_hits);
    }

    all
}

// --- 0. Dedicated Email & Phone OSINT Sweep (GitHub Commit Author-Email Pivot, NPM, Reddit, HN, Archive.org) ---

#[derive(Deserialize)]
struct GithubCommitItemWithAuthor {
    html_url: String,
    commit: GithubCommitDetail,
    author: Option<GithubUserItem>,
    repository: Option<GithubCommitRepo>,
}

#[derive(Deserialize)]
struct GithubCommitsWithAuthorResp {
    #[serde(default)]
    items: Vec<GithubCommitItemWithAuthor>,
}

async fn sweep_emails_and_phones(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let mut discovered_github_logins: Vec<String> = Vec::new();

    // 1. Email-based OSINT sweeps
    for raw_email in &target.emails {
        let email = raw_email.trim();
        if email.is_empty() {
            continue;
        }
        let quoted_email = format!("\"{}\"", email);

        // 1a. GitHub Users search by email (`{email} in:email`)
        let user_email_q = format!("{} in:email", email);
        if let Ok(resp) = client
            .get("https://api.github.com/search/users")
            .query(&[("q", user_email_q.as_str()), ("per_page", "5")])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<GithubUsersResp>().await {
                for u in parsed.items {
                    if !discovered_github_logins.contains(&u.login) {
                        discovered_github_logins.push(u.login.clone());
                    }
                    results.push(RawSearchResult {
                        title: format!("GitHub User Profile (Matched Email {}): @{}", email, u.login),
                        url: u.html_url,
                        snippet: format!("GitHub account @{} registered with email {}", u.login, email),
                        category: DorkCategory::ContactAndPii,
                        dork_used: format!("GitHub Users Email API: {}", email),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }

        // 1b. GitHub Commits search by `author-email:{email}`
        let commit_email_q = format!("author-email:{}", email);
        if let Ok(resp) = client
            .get("https://api.github.com/search/commits")
            .header("Accept", "application/vnd.github.cloak-preview+json")
            .query(&[("q", commit_email_q.as_str()), ("per_page", "10")])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<GithubCommitsWithAuthorResp>().await {
                for item in parsed.items {
                    if let Some(gh_user) = &item.author {
                        if !discovered_github_logins.contains(&gh_user.login) {
                            discovered_github_logins.push(gh_user.login.clone());
                        }
                        results.push(RawSearchResult {
                            title: format!(
                                "GitHub Profile Discovered via Commit Email ({}): @{}",
                                email, gh_user.login
                            ),
                            url: gh_user.html_url.clone(),
                            snippet: format!(
                                "GitHub account @{} identified from commit author email <{}>",
                                gh_user.login, email
                            ),
                            category: DorkCategory::ContactAndPii,
                            dork_used: format!("GitHub Commit Email Pivot: {}", email),
                            engine: "GitHub Public API".to_string(),
                        });
                    }

                    let author_info = item
                        .commit
                        .author
                        .map(|a| {
                            format!(
                                "Author: {} <{}>",
                                a.name.unwrap_or_default(),
                                a.email.unwrap_or_default()
                            )
                        })
                        .unwrap_or_default();
                    let repo_name = item
                        .repository
                        .as_ref()
                        .and_then(|r| r.full_name.clone())
                        .unwrap_or_else(|| "GitHub Repo".to_string());

                    if let Some(repo_url) = item.repository.and_then(|r| r.html_url) {
                        results.push(RawSearchResult {
                            title: format!("[GitHub Repo via Email {}] {}", email, repo_name),
                            url: repo_url,
                            snippet: format!("Repository containing commits by {} | {}", email, author_info),
                            category: DorkCategory::ContactAndPii,
                            dork_used: format!("GitHub Commit Email API: {}", email),
                            engine: "GitHub Public API".to_string(),
                        });
                    }

                    let msg_line = item.commit.message.lines().next().unwrap_or("Commit");
                    results.push(RawSearchResult {
                        title: format!("[GitHub Commit by {} in {}] {}", email, repo_name, msg_line),
                        url: item.html_url,
                        snippet: format!("{} | {}", author_info, item.commit.message),
                        category: DorkCategory::ContactAndPii,
                        dork_used: format!("GitHub Commit Email API: {}", email),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }

        // 1c. GitHub Issues/PRs mentioning the email
        if let Ok(resp) = client
            .get("https://api.github.com/search/issues")
            .query(&[("q", quoted_email.as_str()), ("per_page", "5")])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<GithubIssuesResp>().await {
                for issue in parsed.items {
                    let snippet: String = issue
                        .body
                        .unwrap_or_default()
                        .chars()
                        .take(240)
                        .collect();
                    results.push(RawSearchResult {
                        title: format!("[GitHub Issue/PR Mentioning {}] {}", email, issue.title),
                        url: issue.html_url,
                        snippet: format!("Email {} mentioned: {}", email, snippet),
                        category: DorkCategory::ContactAndPii,
                        dork_used: format!("GitHub Issues Email API: {}", email),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }

        // 1d. NPM Registry search by email (only keep packages whose publisher/author/maintainer email actually matches!)
        if let Ok(resp) = client
            .get("https://registry.npmjs.org/-/v1/search")
            .query(&[("text", email), ("size", "5")])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<NpmSearchResp>().await {
                for obj in parsed.objects {
                    let Some(pkg) = obj.package else { continue };
                    let email_lower = email.to_lowercase();
                    let matches_author = pkg
                        .author
                        .as_ref()
                        .and_then(|a| a.email.as_ref())
                        .map(|e| e.eq_ignore_ascii_case(&email_lower))
                        .unwrap_or(false);
                    let matches_pub = pkg
                        .publisher
                        .as_ref()
                        .and_then(|p| p.email.as_ref())
                        .map(|e| e.eq_ignore_ascii_case(&email_lower))
                        .unwrap_or(false);
                    let matches_maint = pkg.maintainers.iter().any(|m| {
                        m.email
                            .as_ref()
                            .map(|e| e.eq_ignore_ascii_case(&email_lower))
                            .unwrap_or(false)
                    });

                    if !matches_author && !matches_pub && !matches_maint {
                        continue;
                    }

                    let pkg_name = pkg.name.unwrap_or_default();
                    let url = pkg
                        .links
                        .as_ref()
                        .and_then(|l| l.npm.clone())
                        .unwrap_or_else(|| format!("https://www.npmjs.com/package/{}", pkg_name));
                    results.push(RawSearchResult {
                        title: format!("[NPM Package Linked to {}] {}", email, pkg_name),
                        url,
                        snippet: format!(
                            "NPM package {} published by {} | {}",
                            pkg_name,
                            email,
                            pkg.description.unwrap_or_default()
                        ),
                        category: DorkCategory::ContactAndPii,
                        dork_used: format!("NPM Email API: {}", email),
                        engine: "NPM Registry Public API".to_string(),
                    });
                }
            }
        }
    }

    // Pivot on any GitHub user discovered via `--email` to also list their repositories!
    for login in discovered_github_logins.iter().take(2) {
        let repos_url = format!("https://api.github.com/users/{}/repos", login);
        if let Ok(resp) = client
            .get(&repos_url)
            .query(&[("per_page", "10"), ("sort", "updated")])
            .send()
            .await
        {
            if let Ok(repos) = resp.json::<Vec<GithubRepoItem>>().await {
                for repo in repos {
                    results.push(RawSearchResult {
                        title: format!("[GitHub Repository] {} (by @{})", repo.full_name, login),
                        url: repo.html_url,
                        snippet: format!(
                            "Repository owned by @{} (discovered via email {}): {}",
                            login,
                            target.emails.join(", "),
                            repo.description.unwrap_or_default()
                        ),
                        category: DorkCategory::CodeAndTech,
                        dork_used: format!("GitHub Email->User Repos Pivot: @{}", login),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }
    }

    // 2. Phone-based OSINT sweeps across GitHub Issues, Reddit, HackerNews & Internet Archive
    for phone in target.phone_variants().into_iter().take(2) {
        let quoted_phone = format!("\"{}\"", phone);

        // GitHub Issues/PRs mentioning the phone number
        if let Ok(resp) = client
            .get("https://api.github.com/search/issues")
            .query(&[("q", quoted_phone.as_str()), ("per_page", "5")])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<GithubIssuesResp>().await {
                for issue in parsed.items {
                    let snippet: String = issue
                        .body
                        .unwrap_or_default()
                        .chars()
                        .take(240)
                        .collect();
                    results.push(RawSearchResult {
                        title: format!("[GitHub Issue/PR Exposing Phone {}] {}", phone, issue.title),
                        url: issue.html_url,
                        snippet: format!("Phone {} found in GitHub issue: {}", phone, snippet),
                        category: DorkCategory::ContactAndPii,
                        dork_used: format!("GitHub Issues Phone API: {}", phone),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }

        // Reddit posts mentioning the phone number
        if let Ok(resp) = client
            .get("https://www.reddit.com/search.json")
            .query(&[("q", quoted_phone.as_str()), ("limit", "5")])
            .send()
            .await
        {
            if let Ok(listing) = resp.json::<RedditListing>().await {
                if let Some(data) = listing.data {
                    for child in data.children {
                        let Some(post) = child.data else { continue };
                        let Some(permalink) = post.permalink else {
                            continue;
                        };
                        results.push(RawSearchResult {
                            title: format!(
                                "[Reddit Post Exposing Phone {}] {}",
                                phone,
                                post.title.unwrap_or_default()
                            ),
                            url: format!("https://www.reddit.com{}", permalink),
                            snippet: format!(
                                "Phone {} mentioned on Reddit: {}",
                                phone,
                                post.selftext
                                    .unwrap_or_default()
                                    .chars()
                                    .take(200)
                                    .collect::<String>()
                            ),
                            category: DorkCategory::ContactAndPii,
                            dork_used: format!("Reddit Phone API: {}", phone),
                            engine: "Reddit Public JSON".to_string(),
                        });
                    }
                }
            }
        }
    }

    results
}

// --- 0a. Official Google News Keyless RSS Search (`news.google.com/rss/search`) ---

async fn sweep_google_news_rss(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let query = target.strict_name_clause();

    let Ok(resp) = client
        .get("https://news.google.com/rss/search")
        .query(&[("q", query.as_str())])
        .send()
        .await
    else {
        return results;
    };

    let Ok(xml) = resp.text().await else {
        return results;
    };

    for cap in XML_ITEM_RE.captures_iter(&xml).take(8) {
        let block = &cap[1];
        let title = XML_TITLE_RE
            .captures(block)
            .map(|c| c[1].trim().replace("&amp;", "&").replace("&#39;", "'"))
            .unwrap_or_default();
        let link = XML_LINK_RE
            .captures(block)
            .map(|c| c[1].trim().to_string())
            .unwrap_or_default();
        let (source_url, source_name) = XML_SOURCE_RE
            .captures(block)
            .map(|c| (c[1].to_string(), c[2].to_string()))
            .unwrap_or_default();

        if link.is_empty() || title.is_empty() {
            continue;
        }

        results.push(RawSearchResult {
            title: format!("[Google News] {}", title),
            url: link,
            snippet: format!(
                "Google News article from {} ({}) matching {}",
                source_name, source_url, title
            ),
            category: DorkCategory::GeneralMentions,
            dork_used: format!("Google News RSS: {}", query),
            engine: "Google News RSS (Keyless)".to_string(),
        });
    }

    results
}

// --- 0b. Official arXiv Keyless Preprint API (`export.arxiv.org/api/query`) ---

async fn sweep_arxiv(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let query = format!("au:\"{}\"", target.full_name.trim());

    let Ok(resp) = client
        .get("http://export.arxiv.org/api/query")
        .query(&[("search_query", query.as_str()), ("max_results", "4")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(xml) = resp.text().await else {
        return results;
    };

    for cap in XML_ENTRY_RE.captures_iter(&xml).take(4) {
        let block = &cap[1];
        let title = XML_TITLE_RE
            .captures(block)
            .map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let url = XML_ID_RE
            .captures(block)
            .map(|c| c[1].trim().to_string())
            .unwrap_or_default();
        let summary: String = XML_SUMMARY_RE
            .captures(block)
            .map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
            .chars()
            .take(240)
            .collect();

        if url.is_empty() || title.is_empty() {
            continue;
        }

        results.push(RawSearchResult {
            title: format!("[arXiv Preprint] {}", title),
            url,
            snippet: format!("arXiv author match '{}' | {}", target.full_name, summary),
            category: DorkCategory::DocumentsAndFiles,
            dork_used: format!("arXiv API: {}", query),
            engine: "arXiv Public API".to_string(),
        });
    }

    results
}

// --- 1. Reddit Public JSON Search (`reddit.com/search.json`) ---

#[derive(Deserialize)]
struct RedditListing {
    data: Option<RedditListingData>,
}

#[derive(Deserialize)]
struct RedditListingData {
    #[serde(default)]
    children: Vec<RedditChild>,
}

#[derive(Deserialize)]
struct RedditChild {
    data: Option<RedditPost>,
}

#[derive(Deserialize)]
struct RedditPost {
    title: Option<String>,
    permalink: Option<String>,
    selftext: Option<String>,
    subreddit_name_prefixed: Option<String>,
    author: Option<String>,
}

async fn sweep_reddit(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let query = target.strict_name_clause();

    let Ok(resp) = client
        .get("https://www.reddit.com/search.json")
        .query(&[("q", query.as_str()), ("limit", "8"), ("sort", "relevance")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(listing) = resp.json::<RedditListing>().await else {
        return results;
    };

    if let Some(data) = listing.data {
        for child in data.children {
            let Some(post) = child.data else { continue };
            let Some(permalink) = post.permalink else {
                continue;
            };
            let url = format!("https://www.reddit.com{}", permalink);
            let sub = post.subreddit_name_prefixed.unwrap_or_default();
            let author = post.author.unwrap_or_default();
            let title = format!(
                "[Reddit {}] {} (by u/{})",
                sub,
                post.title.unwrap_or_default(),
                author
            );
            let snippet: String = post
                .selftext
                .unwrap_or_default()
                .chars()
                .take(240)
                .collect();

            results.push(RawSearchResult {
                title,
                url,
                snippet,
                category: DorkCategory::SocialProfiles,
                dork_used: format!("Reddit JSON API: {}", query),
                engine: "Reddit Public JSON".to_string(),
            });
        }
    }

    results
}

// --- 2. GitHub Public Search API (Users + Automatic User-Pivot to Repos, Issues/PRs & Commit Emails!) ---

#[derive(Deserialize)]
struct GithubUsersResp {
    #[serde(default)]
    items: Vec<GithubUserItem>,
}

#[derive(Deserialize)]
struct GithubUserItem {
    login: String,
    html_url: String,
}

#[derive(Deserialize)]
struct GithubUserDetail {
    login: String,
    name: Option<String>,
    company: Option<String>,
    location: Option<String>,
    email: Option<String>,
    bio: Option<String>,
    public_repos: Option<u64>,
}

#[derive(Deserialize)]
struct GithubRepoItem {
    full_name: String,
    html_url: String,
    description: Option<String>,
}

#[derive(Deserialize)]
struct GithubIssuesResp {
    #[serde(default)]
    items: Vec<GithubIssueItem>,
}

#[derive(Deserialize)]
struct GithubIssueItem {
    title: String,
    html_url: String,
    body: Option<String>,
}

#[derive(Deserialize)]
struct GithubCommitsResp {
    #[serde(default)]
    items: Vec<GithubCommitItem>,
}

#[derive(Deserialize)]
struct GithubCommitItem {
    html_url: String,
    commit: GithubCommitDetail,
    repository: Option<GithubCommitRepo>,
}

#[derive(Deserialize)]
struct GithubCommitRepo {
    full_name: Option<String>,
    html_url: Option<String>,
}

#[derive(Deserialize)]
struct GithubCommitDetail {
    message: String,
    author: Option<GithubCommitAuthor>,
}

#[derive(Deserialize)]
struct GithubCommitAuthor {
    name: Option<String>,
    email: Option<String>,
}

async fn sweep_github(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let exact_name_quoted = format!("\"{}\"", target.full_name.trim());
    let unquoted_tokens = target.name_tokens().join(" ");

    // 2a. GitHub Users search (using unquoted tokens so compound display names match!)
    let mut discovered_logins: Vec<(String, String)> = Vec::new();
    if let Ok(resp) = client
        .get("https://api.github.com/search/users")
        .query(&[("q", unquoted_tokens.as_str()), ("per_page", "5")])
        .send()
        .await
    {
        if let Ok(parsed) = resp.json::<GithubUsersResp>().await {
            for u in parsed.items {
                // Fetch full user profile detail to inspect `name` (e.g. "Jane_Doe"), `email`, `bio`
                let detail_url = format!("https://api.github.com/users/{}", u.login);
                let mut profile_name = target.full_name.clone();
                let mut extra_info = String::new();

                if let Ok(d_resp) = client.get(&detail_url).send().await {
                    if let Ok(detail) = d_resp.json::<GithubUserDetail>().await {
                        let candidate_name = detail.name.clone().unwrap_or_default();
                        if !crate::analyzer::matches_full_name_strict(
                            &candidate_name,
                            &detail.login,
                            &u.html_url,
                            target,
                        ) {
                            continue;
                        }
                        if !candidate_name.is_empty() {
                            profile_name = candidate_name;
                        }
                        extra_info = format!(
                            "Repos: {} | Location: {} | Company: {} | Email: {} | Bio: {}",
                            detail.public_repos.unwrap_or(0),
                            detail.location.unwrap_or_default(),
                            detail.company.unwrap_or_default(),
                            detail.email.unwrap_or_default(),
                            detail.bio.unwrap_or_default()
                        );
                    }
                }

                results.push(RawSearchResult {
                    title: format!("GitHub User Profile: @{} ({})", u.login, profile_name),
                    url: u.html_url,
                    snippet: format!(
                        "GitHub account @{} ({}) matching {} | {}",
                        u.login, profile_name, target.full_name, extra_info
                    ),
                    category: DorkCategory::CodeAndTech,
                    dork_used: format!("GitHub Users API: {}", unquoted_tokens),
                    engine: "GitHub Public API".to_string(),
                });

                discovered_logins.push((u.login, profile_name));
            }
        }
    }

    // 2b. Pivot on every discovered GitHub user to fetch their repositories & commit history!
    for (login, profile_name) in discovered_logins.iter().take(2) {
        // Fetch user's public repositories (`/users/{login}/repos`)
        let repos_url = format!("https://api.github.com/users/{}/repos", login);
        if let Ok(resp) = client
            .get(&repos_url)
            .query(&[("per_page", "10"), ("sort", "updated")])
            .send()
            .await
        {
            if let Ok(repos) = resp.json::<Vec<GithubRepoItem>>().await {
                for repo in repos {
                    results.push(RawSearchResult {
                        title: format!("[GitHub Repository] {} (by @{})", repo.full_name, login),
                        url: repo.html_url,
                        snippet: format!(
                            "Repository owned by {} (@{} / {}): {}",
                            target.full_name,
                            login,
                            profile_name,
                            repo.description.unwrap_or_default()
                        ),
                        category: DorkCategory::CodeAndTech,
                        dork_used: format!("GitHub User Repos Pivot: @{}", login),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }

        // Fetch commits authored by this GitHub user across ALL repositories on GitHub (`/search/commits?q=author:{login}`)
        // This uncovers group projects (like `Padmavati-123/Sql_Murder_Mystery`) AND personal emails in commit headers!
        let author_q = format!("author:{}", login);
        if let Ok(resp) = client
            .get("https://api.github.com/search/commits")
            .header("Accept", "application/vnd.github.cloak-preview+json")
            .query(&[("q", author_q.as_str()), ("per_page", "10")])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<GithubCommitsResp>().await {
                for item in parsed.items {
                    let author_info = item
                        .commit
                        .author
                        .map(|a| {
                            format!(
                                "Author: {} <{}>",
                                a.name.unwrap_or_default(),
                                a.email.unwrap_or_default()
                            )
                        })
                        .unwrap_or_default();
                    let repo_name = item
                        .repository
                        .as_ref()
                        .and_then(|r| r.full_name.clone())
                        .unwrap_or_else(|| "GitHub Repo".to_string());

                    // Also add the parent repository link itself (e.g. `https://github.com/Padmavati-123/Sql_Murder_Mystery`)
                    if let Some(repo_url) = item.repository.and_then(|r| r.html_url) {
                        results.push(RawSearchResult {
                            title: format!(
                                "[GitHub Contributed Repo] {} (Contributor: @{})",
                                repo_name, login
                            ),
                            url: repo_url,
                            snippet: format!(
                                "Repository contributed to by {} (@{}) | {}",
                                target.full_name, login, author_info
                            ),
                            category: DorkCategory::ContactAndPii,
                            dork_used: format!("GitHub Commits Pivot: author:{}", login),
                            engine: "GitHub Public API".to_string(),
                        });
                    }

                    let msg_line = item.commit.message.lines().next().unwrap_or("Commit");
                    results.push(RawSearchResult {
                        title: format!("[GitHub Commit in {}] {}", repo_name, msg_line),
                        url: item.html_url,
                        snippet: format!(
                            "Commit by {} (@{}) | {} | {}",
                            target.full_name, login, author_info, item.commit.message
                        ),
                        category: DorkCategory::ContactAndPii,
                        dork_used: format!("GitHub Commits Pivot: author:{}", login),
                        engine: "GitHub Public API".to_string(),
                    });
                }
            }
        }
    }

    // 2c. Direct GitHub Issues & PRs search for exact full name
    if let Ok(resp) = client
        .get("https://api.github.com/search/issues")
        .query(&[("q", exact_name_quoted.as_str()), ("per_page", "5")])
        .send()
        .await
    {
        if let Ok(parsed) = resp.json::<GithubIssuesResp>().await {
            for issue in parsed.items {
                let snippet: String = issue
                    .body
                    .unwrap_or_default()
                    .chars()
                    .take(240)
                    .collect();
                results.push(RawSearchResult {
                    title: format!("[GitHub Issue/PR] {}", issue.title),
                    url: issue.html_url,
                    snippet,
                    category: DorkCategory::CodeAndTech,
                    dork_used: format!("GitHub Issues API: {}", exact_name_quoted),
                    engine: "GitHub Public API".to_string(),
                });
            }
        }
    }

    // 2d. Direct GitHub Commits search for exact full name
    if let Ok(resp) = client
        .get("https://api.github.com/search/commits")
        .header("Accept", "application/vnd.github.cloak-preview+json")
        .query(&[("q", exact_name_quoted.as_str()), ("per_page", "5")])
        .send()
        .await
    {
        if let Ok(parsed) = resp.json::<GithubCommitsResp>().await {
            for item in parsed.items {
                let author_info = item
                    .commit
                    .author
                    .map(|a| {
                        format!(
                            "Author: {} <{}>",
                            a.name.unwrap_or_default(),
                            a.email.unwrap_or_default()
                        )
                    })
                    .unwrap_or_default();
                let msg_line = item.commit.message.lines().next().unwrap_or("Commit");
                results.push(RawSearchResult {
                    title: format!("[GitHub Commit] {}", msg_line),
                    url: item.html_url,
                    snippet: format!("{} | {}", author_info, item.commit.message),
                    category: DorkCategory::ContactAndPii,
                    dork_used: format!("GitHub Commits API: {}", exact_name_quoted),
                    engine: "GitHub Public API".to_string(),
                });
            }
        }
    }

    results
}

// --- 3. GitLab Public REST API (`gitlab.com/api/v4/projects`) ---

#[derive(Deserialize)]
struct GitlabProject {
    name_with_namespace: Option<String>,
    web_url: Option<String>,
    description: Option<String>,
}

async fn sweep_gitlab(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://gitlab.com/api/v4/projects")
        .query(&[("search", target.full_name.trim()), ("per_page", "5")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(projects) = resp.json::<Vec<GitlabProject>>().await else {
        return results;
    };

    for p in projects {
        let Some(url) = p.web_url else { continue };
        let title = format!(
            "[GitLab Project] {}",
            p.name_with_namespace.unwrap_or_else(|| url.clone())
        );
        let snippet = p.description.unwrap_or_default();
        results.push(RawSearchResult {
            title,
            url,
            snippet,
            category: DorkCategory::CodeAndTech,
            dork_used: format!("GitLab Projects API: {}", target.full_name),
            engine: "GitLab Public API".to_string(),
        });
    }

    results
}

// --- 4. StackExchange / StackOverflow Public API (`api.stackexchange.com/2.3/users`) ---

#[derive(Deserialize)]
struct StackUsersResp {
    #[serde(default)]
    items: Vec<StackUser>,
}

#[derive(Deserialize)]
struct StackUser {
    display_name: Option<String>,
    link: Option<String>,
    location: Option<String>,
    website_url: Option<String>,
    reputation: Option<u64>,
}

async fn sweep_stackexchange(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    for variant in target.exact_name_variants().into_iter().take(2) {
        let Ok(resp) = client
            .get("https://api.stackexchange.com/2.3/users")
            .query(&[
                ("inname", variant.as_str()),
                ("site", "stackoverflow"),
                ("pagesize", "5"),
            ])
            .send()
            .await
        else {
            continue;
        };

        let Ok(parsed) = resp.json::<StackUsersResp>().await else {
            continue;
        };

        for u in parsed.items {
            let Some(url) = u.link else { continue };
            let name = u.display_name.unwrap_or_default();
            let loc = u.location.unwrap_or_default();
            let site = u.website_url.unwrap_or_default();
            let rep = u.reputation.unwrap_or(0);
            results.push(RawSearchResult {
                title: format!("[StackOverflow User] {} (Reputation: {})", name, rep),
                url,
                snippet: format!(
                    "StackOverflow developer '{}' | Location: {} | Website: {}",
                    name, loc, site
                ),
                category: DorkCategory::CodeAndTech,
                dork_used: format!("StackExchange Users API: {}", variant),
                engine: "StackExchange Public API".to_string(),
            });
        }
    }
    results
}

// --- 5. NPM Registry Public Search API (`registry.npmjs.org/-/v1/search`) ---

#[derive(Deserialize)]
struct NpmSearchResp {
    #[serde(default)]
    objects: Vec<NpmObject>,
}

#[derive(Deserialize)]
struct NpmObject {
    package: Option<NpmPackage>,
}

#[derive(Deserialize)]
struct NpmPackage {
    name: Option<String>,
    description: Option<String>,
    links: Option<NpmLinks>,
    publisher: Option<NpmUser>,
    author: Option<NpmAuthor>,
    #[serde(default)]
    maintainers: Vec<NpmUser>,
}

#[derive(Deserialize)]
struct NpmLinks {
    npm: Option<String>,
    repository: Option<String>,
}

#[derive(Deserialize)]
struct NpmUser {
    username: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct NpmAuthor {
    name: Option<String>,
    email: Option<String>,
}

async fn sweep_npm(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://registry.npmjs.org/-/v1/search")
        .query(&[("text", target.full_name.trim()), ("size", "5")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<NpmSearchResp>().await else {
        return results;
    };

    for obj in parsed.objects {
        let Some(pkg) = obj.package else { continue };
        let pkg_name = pkg.name.unwrap_or_default();
        let url = pkg
            .links
            .as_ref()
            .and_then(|l| l.npm.clone().or_else(|| l.repository.clone()))
            .unwrap_or_else(|| format!("https://www.npmjs.com/package/{}", pkg_name));

        let author_str = pkg
            .author
            .map(|a| {
                format!(
                    "Author: {} <{}>",
                    a.name.unwrap_or_default(),
                    a.email.unwrap_or_default()
                )
            })
            .unwrap_or_default();

        let pub_str = pkg
            .publisher
            .map(|p| {
                format!(
                    "Publisher: @{} <{}>",
                    p.username.unwrap_or_default(),
                    p.email.unwrap_or_default()
                )
            })
            .unwrap_or_default();

        let maint_emails: Vec<String> = pkg
            .maintainers
            .into_iter()
            .filter_map(|m| {
                Some(format!(
                    "@{} <{}>",
                    m.username.unwrap_or_default(),
                    m.email?
                ))
            })
            .collect();

        let snippet = format!(
            "{} | {} | {} | Maintainers: {}",
            pkg.description.unwrap_or_default(),
            author_str,
            pub_str,
            maint_emails.join(", ")
        );
        let title = format!("[NPM Package] {}", pkg_name);

        // Only include NPM packages that genuinely match the full name (not a single token match!)
        if !crate::analyzer::matches_full_name_strict(&title, &snippet, &url, target) {
            continue;
        }

        results.push(RawSearchResult {
            title,
            url,
            snippet,
            category: DorkCategory::ContactAndPii,
            dork_used: format!("NPM Registry API: {}", target.full_name),
            engine: "NPM Registry Public API".to_string(),
        });
    }

    results
}

// --- 6. Crates.io Public Search API (`crates.io/api/v1/crates`) ---

#[derive(Deserialize)]
struct CratesResp {
    #[serde(default)]
    crates: Vec<CrateItem>,
}

#[derive(Deserialize)]
struct CrateItem {
    name: String,
    description: Option<String>,
    repository: Option<String>,
}

async fn sweep_crates_io(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://crates.io/api/v1/crates")
        .query(&[("q", target.full_name.trim()), ("per_page", "5")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<CratesResp>().await else {
        return results;
    };

    for c in parsed.crates {
        let url = c
            .repository
            .unwrap_or_else(|| format!("https://crates.io/crates/{}", c.name));
        results.push(RawSearchResult {
            title: format!("[Crates.io Rust Package] {}", c.name),
            url,
            snippet: c.description.unwrap_or_default(),
            category: DorkCategory::CodeAndTech,
            dork_used: format!("Crates.io API: {}", target.full_name),
            engine: "Crates.io Public API".to_string(),
        });
    }

    results
}

// --- 7. Docker Hub Public Search API (`hub.docker.com/v2/search/repositories/`) ---

#[derive(Deserialize)]
struct DockerSearchResp {
    #[serde(default)]
    results: Vec<DockerRepo>,
}

#[derive(Deserialize)]
struct DockerRepo {
    repo_name: Option<String>,
    short_description: Option<String>,
}

async fn sweep_dockerhub(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    for handle in target.effective_usernames().into_iter().take(2) {
        let Ok(resp) = client
            .get("https://hub.docker.com/v2/search/repositories/")
            .query(&[("query", handle.as_str()), ("page_size", "4")])
            .send()
            .await
        else {
            continue;
        };

        let Ok(parsed) = resp.json::<DockerSearchResp>().await else {
            continue;
        };

        for r in parsed.results {
            let Some(repo_name) = r.repo_name else {
                continue;
            };
            results.push(RawSearchResult {
                title: format!("[Docker Hub Repository] {}", repo_name),
                url: format!("https://hub.docker.com/r/{}", repo_name),
                snippet: format!(
                    "Docker container repository {} | {}",
                    repo_name,
                    r.short_description.unwrap_or_default()
                ),
                category: DorkCategory::CodeAndTech,
                dork_used: format!("Docker Hub API: {}", handle),
                engine: "Docker Hub Public API".to_string(),
            });
        }
    }
    results
}

// --- 8. Hacker News Algolia Public API ---

#[derive(Deserialize)]
struct HnSearchResp {
    #[serde(default)]
    hits: Vec<HnHit>,
}

#[derive(Deserialize)]
struct HnHit {
    #[serde(rename = "objectID")]
    object_id: String,
    title: Option<String>,
    url: Option<String>,
    author: Option<String>,
    comment_text: Option<String>,
    story_title: Option<String>,
}

async fn sweep_hackernews(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let query = format!("\"{}\"", target.full_name.trim());

    let Ok(resp) = client
        .get("https://hn.algolia.com/api/v1/search")
        .query(&[
            ("query", query.as_str()),
            ("hitsPerPage", "5"),
            ("advancedSyntax", "true"),
        ])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<HnSearchResp>().await else {
        return results;
    };

    for hit in parsed.hits {
        let hn_link = format!("https://news.ycombinator.com/item?id={}", hit.object_id);
        let url = hit.url.unwrap_or_else(|| hn_link.clone());
        let title = hit
            .title
            .or(hit.story_title)
            .unwrap_or_else(|| format!("Hacker News Discussion #{}", hit.object_id));
        let snippet: String = hit
            .comment_text
            .unwrap_or_else(|| {
                format!(
                    "Posted by {} on Hacker News ({})",
                    hit.author.unwrap_or_default(),
                    hn_link
                )
            })
            .chars()
            .take(240)
            .collect();

        results.push(RawSearchResult {
            title: format!("[Hacker News] {}", title),
            url,
            snippet,
            category: DorkCategory::CodeAndTech,
            dork_used: format!("HN Algolia API: {}", query),
            engine: "Hacker News API".to_string(),
        });
    }

    results
}

// --- 9. OpenAlex Academic Public API (`api.openalex.org/authors`) ---

#[derive(Deserialize)]
struct OpenAlexAuthorsResp {
    #[serde(default)]
    results: Vec<OpenAlexAuthor>,
}

#[derive(Deserialize)]
struct OpenAlexAuthor {
    id: Option<String>,
    orcid: Option<String>,
    display_name: Option<String>,
    works_count: Option<u64>,
    #[serde(default)]
    last_known_institutions: Vec<OpenAlexInst>,
}

#[derive(Deserialize)]
struct OpenAlexInst {
    display_name: Option<String>,
    country_code: Option<String>,
}

async fn sweep_openalex(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://api.openalex.org/authors")
        .query(&[("search", target.full_name.trim()), ("per-page", "5")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<OpenAlexAuthorsResp>().await else {
        return results;
    };

    for a in parsed.results {
        let name = a.display_name.unwrap_or_default();
        let url = a
            .orcid
            .clone()
            .or(a.id)
            .unwrap_or_else(|| "https://openalex.org".to_string());
        let insts: Vec<String> = a
            .last_known_institutions
            .into_iter()
            .filter_map(|i| {
                Some(format!(
                    "{} ({})",
                    i.display_name?,
                    i.country_code.unwrap_or_default()
                ))
            })
            .collect();
        let snippet = format!(
            "Academic Author: {} | Works: {} | Institutions: {} | ORCID: {}",
            name,
            a.works_count.unwrap_or(0),
            insts.join(", "),
            a.orcid.unwrap_or_default()
        );

        results.push(RawSearchResult {
            title: format!("[OpenAlex Researcher] {}", name),
            url,
            snippet,
            category: DorkCategory::SocialProfiles,
            dork_used: format!("OpenAlex Authors API: {}", target.full_name),
            engine: "OpenAlex Academic API".to_string(),
        });
    }

    results
}

// --- 10. ORCID Public Researcher Registry API (`pub.orcid.org/v3.0/expanded-search/`) ---

#[derive(Deserialize)]
struct OrcidSearchResp {
    #[serde(rename = "expanded-result")]
    expanded_result: Option<Vec<OrcidRecord>>,
}

#[derive(Deserialize)]
struct OrcidRecord {
    #[serde(rename = "orcid-id")]
    orcid_id: Option<String>,
    #[serde(rename = "given-names")]
    given_names: Option<String>,
    #[serde(rename = "family-names")]
    family_names: Option<String>,
    #[serde(rename = "institution-name", default)]
    institutions: Vec<String>,
    #[serde(default)]
    email: Vec<String>,
}

async fn sweep_orcid(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let tokens = target.name_tokens();
    if tokens.len() < 2 {
        return results;
    }

    let first = &tokens[0];
    let last = &tokens[tokens.len() - 1];
    let queries = vec![
        format!("given-names:{} AND family-name:{}", first, last),
        format!("given-names:{} AND family-name:{}", last, first),
    ];

    for q in queries {
        let Ok(resp) = client
            .get("https://pub.orcid.org/v3.0/expanded-search/")
            .header("Accept", "application/json")
            .query(&[("q", q.as_str()), ("rows", "4")])
            .send()
            .await
        else {
            continue;
        };

        let Ok(parsed) = resp.json::<OrcidSearchResp>().await else {
            continue;
        };

        for rec in parsed.expanded_result.unwrap_or_default() {
            let Some(id) = rec.orcid_id else { continue };
            let full = format!(
                "{} {}",
                rec.given_names.unwrap_or_default(),
                rec.family_names.unwrap_or_default()
            );
            let snippet = format!(
                "ORCID Researcher: {} | Institutions: {} | Emails: {}",
                full,
                rec.institutions.join(", "),
                rec.email.join(", ")
            );
            results.push(RawSearchResult {
                title: format!("[ORCID Profile] {} ({})", full.trim(), id),
                url: format!("https://orcid.org/{}", id),
                snippet,
                category: DorkCategory::SocialProfiles,
                dork_used: format!("ORCID Registry API: {}", q),
                engine: "ORCID Public API".to_string(),
            });
        }
    }

    results
}

// --- 11. Semantic Scholar Academic Graph API (`api.semanticscholar.org/graph/v1/author/search`) ---

#[derive(Deserialize)]
struct SemanticScholarResp {
    #[serde(default)]
    data: Vec<SemanticAuthor>,
}

#[derive(Deserialize)]
struct SemanticAuthor {
    name: Option<String>,
    url: Option<String>,
    #[serde(default)]
    affiliations: Vec<String>,
    #[serde(rename = "paperCount")]
    paper_count: Option<u64>,
}

async fn sweep_semantic_scholar(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://api.semanticscholar.org/graph/v1/author/search")
        .query(&[
            ("query", target.full_name.trim()),
            ("fields", "name,url,affiliations,paperCount"),
            ("limit", "4"),
        ])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<SemanticScholarResp>().await else {
        return results;
    };

    for a in parsed.data {
        let Some(url) = a.url else { continue };
        let name = a.name.unwrap_or_default();
        let snippet = format!(
            "Semantic Scholar Author: {} | Papers: {} | Affiliations: {}",
            name,
            a.paper_count.unwrap_or(0),
            a.affiliations.join(", ")
        );
        results.push(RawSearchResult {
            title: format!("[Semantic Scholar] {}", name),
            url,
            snippet,
            category: DorkCategory::SocialProfiles,
            dork_used: format!("Semantic Scholar API: {}", target.full_name),
            engine: "Semantic Scholar API".to_string(),
        });
    }

    results
}

// --- 12. Crossref Public Works API (`api.crossref.org/works`) ---

#[derive(Deserialize)]
struct CrossrefResp {
    message: Option<CrossrefMessage>,
}

#[derive(Deserialize)]
struct CrossrefMessage {
    #[serde(default)]
    items: Vec<CrossrefWork>,
}

#[derive(Deserialize)]
struct CrossrefWork {
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(default)]
    title: Vec<String>,
    #[serde(default)]
    author: Vec<CrossrefAuthor>,
}

#[derive(Deserialize)]
struct CrossrefAuthor {
    given: Option<String>,
    family: Option<String>,
    #[serde(default)]
    affiliation: Vec<CrossrefAffil>,
}

#[derive(Deserialize)]
struct CrossrefAffil {
    name: Option<String>,
}

async fn sweep_crossref(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://api.crossref.org/works")
        .query(&[
            ("query.author", target.full_name.trim()),
            ("select", "DOI,title,author,URL"),
            ("rows", "5"),
        ])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<CrossrefResp>().await else {
        return results;
    };

    if let Some(msg) = parsed.message {
        for item in msg.items {
            let Some(url) = item.url else { continue };
            let work_title = item.title.into_iter().next().unwrap_or_else(|| url.clone());
            let authors: Vec<String> = item
                .author
                .into_iter()
                .map(|a| {
                    let affs: Vec<String> = a
                        .affiliation
                        .into_iter()
                        .filter_map(|af| af.name)
                        .collect();
                    let full = format!(
                        "{} {}",
                        a.given.unwrap_or_default(),
                        a.family.unwrap_or_default()
                    )
                    .trim()
                    .to_string();
                    if affs.is_empty() {
                        full
                    } else {
                        format!("{} ({})", full, affs.join(", "))
                    }
                })
                .collect();

            results.push(RawSearchResult {
                title: format!("[Crossref Publication] {}", work_title),
                url,
                snippet: format!("Authors: {}", authors.join("; ")),
                category: DorkCategory::DocumentsAndFiles,
                dork_used: format!("Crossref Works API: {}", target.full_name),
                engine: "Crossref Public API".to_string(),
            });
        }
    }

    results
}

// --- 13. Internet Archive (`archive.org/advancedsearch.php`) ---

#[derive(Deserialize)]
struct ArchiveResp {
    response: Option<ArchiveResponseBody>,
}

#[derive(Deserialize)]
struct ArchiveResponseBody {
    #[serde(default)]
    docs: Vec<ArchiveDoc>,
}

#[derive(Deserialize)]
struct ArchiveDoc {
    identifier: Option<String>,
    title: Option<String>,
    mediatype: Option<String>,
    description: Option<serde_json::Value>,
    creator: Option<serde_json::Value>,
}

async fn sweep_archive_org(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let query = target.strict_name_clause();

    let Ok(resp) = client
        .get("https://archive.org/advancedsearch.php")
        .query(&[("q", query.as_str()), ("output", "json"), ("rows", "5")])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<ArchiveResp>().await else {
        return results;
    };

    if let Some(body) = parsed.response {
        for doc in body.docs {
            let Some(id) = doc.identifier else { continue };
            let title = doc.title.unwrap_or_else(|| id.clone());
            let media = doc.mediatype.unwrap_or_default();
            let creator_str = doc
                .creator
                .map(|v| v.to_string())
                .unwrap_or_default();
            let desc_str: String = doc
                .description
                .map(|v| v.to_string())
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect();
            results.push(RawSearchResult {
                title: format!("[Internet Archive {}] {}", media, title),
                url: format!("https://archive.org/details/{}", id),
                snippet: format!("Creator: {} | {}", creator_str, desc_str),
                category: DorkCategory::DocumentsAndFiles,
                dork_used: format!("Archive.org JSON API: {}", query),
                engine: "Internet Archive API".to_string(),
            });
        }
    }

    results
}

// --- 14. Wikipedia / Wikimedia Public Search API ---

#[derive(Deserialize)]
struct WikiResp {
    query: Option<WikiQuery>,
}

#[derive(Deserialize)]
struct WikiQuery {
    #[serde(default)]
    search: Vec<WikiSearchItem>,
}

#[derive(Deserialize)]
struct WikiSearchItem {
    title: String,
    snippet: String,
}

async fn sweep_wikipedia(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let query = format!("\"{}\"", target.full_name.trim());

    let Ok(resp) = client
        .get("https://en.wikipedia.org/w/api.php")
        .query(&[
            ("action", "query"),
            ("list", "search"),
            ("srsearch", query.as_str()),
            ("srlimit", "3"),
            ("format", "json"),
        ])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<WikiResp>().await else {
        return results;
    };

    if let Some(q) = parsed.query {
        for item in q.search {
            let slug = item.title.replace(' ', "_");
            let clean_snippet = item
                .snippet
                .replace("<span class=\"searchmatch\">", "")
                .replace("</span>", "");
            results.push(RawSearchResult {
                title: format!("[Wikipedia] {}", item.title),
                url: format!("https://en.wikipedia.org/wiki/{}", slug),
                snippet: clean_snippet,
                category: DorkCategory::GeneralMentions,
                dork_used: format!("Wikipedia MediaWiki API: {}", query),
                engine: "Wikimedia API".to_string(),
            });
        }
    }

    results
}

// --- 15. Wikidata Structured Biographical Entities API (`www.wikidata.org/w/api.php`) ---

#[derive(Deserialize)]
struct WikidataResp {
    #[serde(default)]
    search: Vec<WikidataEntity>,
}

#[derive(Deserialize)]
struct WikidataEntity {
    id: Option<String>,
    label: Option<String>,
    description: Option<String>,
    concepturi: Option<String>,
}

async fn sweep_wikidata(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();
    let Ok(resp) = client
        .get("https://www.wikidata.org/w/api.php")
        .query(&[
            ("action", "wbsearchentities"),
            ("search", target.full_name.trim()),
            ("language", "en"),
            ("limit", "4"),
            ("format", "json"),
        ])
        .send()
        .await
    else {
        return results;
    };

    let Ok(parsed) = resp.json::<WikidataResp>().await else {
        return results;
    };

    for ent in parsed.search {
        let label = ent.label.unwrap_or_default();
        let desc = ent.description.unwrap_or_default();
        let url = ent.concepturi.unwrap_or_else(|| {
            format!(
                "https://www.wikidata.org/wiki/{}",
                ent.id.unwrap_or_default()
            )
        });
        results.push(RawSearchResult {
            title: format!("[Wikidata Entity] {}", label),
            url,
            snippet: format!("{} — {}", label, desc),
            category: DorkCategory::GeneralMentions,
            dork_used: format!("Wikidata Entities API: {}", target.full_name),
            engine: "Wikidata Public API".to_string(),
        });
    }

    results
}

// --- 16. Keybase Public Lookup API & OpenPGP Keyserver (`keys.openpgp.org`) ---

#[derive(Deserialize)]
struct KeybaseLookupResp {
    #[serde(default)]
    them: Vec<Option<KeybaseUser>>,
}

#[derive(Deserialize)]
struct KeybaseUser {
    basics: Option<KeybaseBasics>,
    profile: Option<KeybaseProfile>,
}

#[derive(Deserialize)]
struct KeybaseBasics {
    username: Option<String>,
}

#[derive(Deserialize)]
struct KeybaseProfile {
    full_name: Option<String>,
    bio: Option<String>,
    location: Option<String>,
}

async fn sweep_keybase_and_pgp(client: &Client, target: &ScanTarget) -> Vec<RawSearchResult> {
    let mut results = Vec::new();

    let handles: Vec<String> = target.effective_usernames().into_iter().take(4).collect();
    if !handles.is_empty() {
        let joined = handles.join(",");
        if let Ok(resp) = client
            .get("https://keybase.io/_/api/1.0/user/lookup.json")
            .query(&[("usernames", joined.as_str())])
            .send()
            .await
        {
            if let Ok(parsed) = resp.json::<KeybaseLookupResp>().await {
                for user in parsed.them.into_iter().flatten() {
                    let Some(uname) = user.basics.and_then(|b| b.username) else {
                        continue;
                    };
                    let (full_name, bio, loc) = user
                        .profile
                        .map(|p| {
                            (
                                p.full_name.unwrap_or_default(),
                                p.bio.unwrap_or_default(),
                                p.location.unwrap_or_default(),
                            )
                        })
                        .unwrap_or_default();

                    results.push(RawSearchResult {
                        title: format!("[Keybase Identity] @{} ({})", uname, full_name),
                        url: format!("https://keybase.io/{}", uname),
                        snippet: format!(
                            "Keybase user @{} | Full Name: {} | Location: {} | Bio: {}",
                            uname, full_name, loc, bio
                        ),
                        category: DorkCategory::SocialProfiles,
                        dork_used: format!("Keybase Lookup API: @{}", uname),
                        engine: "Keybase Public API".to_string(),
                    });
                }
            }
        }
    }

    for email in &target.emails {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            continue;
        }
        results.extend(probe_email_identity_endpoints(client, trimmed, &target.full_name).await);
    }

    results
}

/// Keyless email identity probes:
/// 1. Public Google Calendar `.ics` feed (`calendar.google.com/calendar/ical/{email}/public/basic.ics`)
/// 2. Gravatar Public Profile JSON (`en.gravatar.com/{md5(email)}.json`)
/// 3. OpenPGP Public Keyserver (`keys.openpgp.org/vks/v1/by-email/{email}`)
pub async fn probe_email_identity_endpoints(
    client: &Client,
    email: &str,
    target_label: &str,
) -> Vec<RawSearchResult> {
    let mut hits = Vec::new();
    let trimmed = email.trim().to_lowercase();
    if trimmed.is_empty()
        || trimmed.ends_with("users.noreply.github.com")
        || trimmed.starts_with("noreply@")
    {
        return hits;
    }

    let (cal_hit, grav_hit, pgp_hit) = tokio::join!(
        check_public_google_calendar(client, &trimmed, target_label),
        check_gravatar_profile(client, &trimmed, target_label),
        check_openpgp_key(client, &trimmed, target_label),
    );

    if let Some(h) = cal_hit {
        hits.push(h);
    }
    if let Some(h) = grav_hit {
        hits.push(h);
    }
    if let Some(h) = pgp_hit {
        hits.push(h);
    }

    hits
}

/// Stage-2 Automatic Email Pivot:
/// Extracts any personal/work email addresses discovered during Stage 1 (e.g. from GitHub commits or snippets)
/// and automatically checks them against Public Google Calendar `.ics`, Gravatar, and OpenPGP!
pub async fn run_second_stage_email_pivot(
    existing_results: &[RawSearchResult],
    target: &ScanTarget,
) -> Vec<RawSearchResult> {
    let email_re =
        Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,10}\b").expect("Valid email regex");
    let mut discovered_emails: Vec<String> = Vec::new();

    for r in existing_results {
        // CRITICAL: Only pivot on emails from results that genuinely matched the target's full name!
        // This prevents unrelated single-word NPM/Crossref hits from triggering Stage-2 Gravatar/Calendar lookups.
        if !crate::analyzer::matches_full_name_strict(&r.title, &r.snippet, &r.url, target) {
            continue;
        }
        let text = format!("{} {}", r.title, r.snippet);
        for mat in email_re.find_iter(&text) {
            let e = mat.as_str().to_lowercase();
            if e.ends_with(".png")
                || e.ends_with(".jpg")
                || e.ends_with(".svg")
                || e.ends_with("users.noreply.github.com")
                || e.starts_with("noreply@")
                || e.starts_with("npm-oidc-no-reply@")
            {
                continue;
            }
            // Skip if already explicitly provided in `--email` (already probed in Stage 1)
            if target
                .emails
                .iter()
                .any(|te| te.trim().eq_ignore_ascii_case(&e))
            {
                continue;
            }
            if !discovered_emails.contains(&e) {
                discovered_emails.push(e);
            }
        }
    }

    if discovered_emails.is_empty() {
        return Vec::new();
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(API_UA)
        .build()
        .unwrap_or_default();

    let label = target.display_label();
    let mut pivot_hits = Vec::new();
    for email in discovered_emails.into_iter().take(4) {
        let mut h = probe_email_identity_endpoints(&client, &email, &label).await;
        pivot_hits.append(&mut h);
    }

    pivot_hits
}

/// Checks if a Google Account has an exposed Public Google Calendar (`basic.ics`).
async fn check_public_google_calendar(
    client: &Client,
    email: &str,
    target_label: &str,
) -> Option<RawSearchResult> {
    let ical_url = format!(
        "https://calendar.google.com/calendar/ical/{}/public/basic.ics",
        urlencoding_simple(email)
    );
    let resp = client.get(&ical_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let body = resp.text().await.ok()?;
    if !body.contains("BEGIN:VCALENDAR") {
        return None;
    }

    let mut cal_name = String::new();
    let mut timezone = String::new();
    let mut event_count = 0usize;
    let mut sample_events = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("X-WR-CALNAME:") {
            cal_name = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("X-WR-TIMEZONE:") {
            timezone = rest.trim().to_string();
        } else if trimmed == "BEGIN:VEVENT" {
            event_count += 1;
        } else if let Some(rest) = trimmed.strip_prefix("SUMMARY:") {
            let s = rest.trim();
            if !s.is_empty() && sample_events.len() < 3 {
                sample_events.push(s.to_string());
            }
        }
    }

    Some(RawSearchResult {
        title: format!(
            "[Public Google Calendar Leak] {} (Calendar: {}, Timezone: {})",
            email,
            if cal_name.is_empty() { email } else { &cal_name },
            if timezone.is_empty() { "UTC" } else { &timezone }
        ),
        url: ical_url,
        snippet: format!(
            "Exposed Public Google Calendar for {} ({}) | Owner Name: {} | Timezone: {} | Public Events: {} (Recent: {})",
            target_label,
            email,
            cal_name,
            timezone,
            event_count,
            sample_events.join("; ")
        ),
        category: DorkCategory::ContactAndPii,
        dork_used: format!("Google Calendar .ics Check: {}", email),
        engine: "Google Calendar Public Probe".to_string(),
    })
}

#[derive(Deserialize)]
struct GravatarResp {
    #[serde(default)]
    entry: Vec<GravatarEntry>,
}

#[derive(Deserialize)]
struct GravatarEntry {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "preferredUsername")]
    preferred_username: Option<String>,
    #[serde(rename = "currentLocation")]
    current_location: Option<String>,
    #[serde(rename = "profileUrl")]
    profile_url: Option<String>,
    #[serde(rename = "aboutMe")]
    about_me: Option<String>,
}

async fn check_gravatar_profile(
    client: &Client,
    email: &str,
    target_label: &str,
) -> Option<RawSearchResult> {
    let hash = md5_hex(email.trim().to_lowercase().as_bytes());
    let url = format!("https://en.gravatar.com/{}.json", hash);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let parsed: GravatarResp = resp.json().await.ok()?;
    let entry = parsed.entry.into_iter().next()?;
    let disp = entry.display_name.unwrap_or_else(|| email.to_string());
    let uname = entry.preferred_username.unwrap_or_default();
    let loc = entry.current_location.unwrap_or_default();
    let bio = entry.about_me.unwrap_or_default();
    let profile_url = entry
        .profile_url
        .unwrap_or_else(|| format!("https://gravatar.com/{}", hash));

    Some(RawSearchResult {
        title: format!("[Gravatar Identity Profile] {} (@{}) for {}", disp, uname, email),
        url: profile_url,
        snippet: format!(
            "Gravatar profile linked to {} ({}) | Display Name: {} | Username: @{} | Location: {} | Bio: {}",
            target_label, email, disp, uname, loc, bio
        ),
        category: DorkCategory::SocialProfiles,
        dork_used: format!("Gravatar MD5 JSON Probe: {}", email),
        engine: "Gravatar Public API".to_string(),
    })
}

async fn check_openpgp_key(
    client: &Client,
    email: &str,
    target_label: &str,
) -> Option<RawSearchResult> {
    let endpoint = format!(
        "https://keys.openpgp.org/vks/v1/by-email/{}",
        urlencoding_simple(email)
    );
    let resp = client.get(&endpoint).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    Some(RawSearchResult {
        title: format!("[OpenPGP Public Key] {}", email),
        url: format!("https://keys.openpgp.org/search?q={}", email),
        snippet: format!(
            "Public PGP cryptographic key registered for {} ({}) on keys.openpgp.org",
            target_label, email
        ),
        category: DorkCategory::ContactAndPii,
        dork_used: format!("OpenPGP Keyserver API: {}", email),
        engine: "OpenPGP Keyserver API".to_string(),
    })
}

/// Compact pure-Rust RFC 1321 MD5 implementation for computing Gravatar email hashes.
fn md5_hex(input: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6,
        10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn urlencoding_simple(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
