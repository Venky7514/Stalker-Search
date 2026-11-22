use crate::dorks::ScanTarget;
use crate::models::{AnalyzedFinding, DorkCategory, PiiLeakType, RawSearchResult, RiskLevel};
use futures::stream::{self, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:\b[a-z0-9._%+-]+|\*{2,})@[a-z0-9.-]+\.[a-z]{2,10}\b")
        .expect("Valid email regex")
});

static PHONE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}|\b[6-9]\d{9}\b)\b",
    )
    .expect("Valid phone regex")
});

static SENSITIVE_KEYWORDS: &[&str] = &[
    "resume",
    "curriculum vitae",
    "date of birth",
    "dob",
    "home address",
    "mailing address",
    "phone number",
    "mobile number",
    "contact info",
    "ssn",
    "passport",
];

static DOC_EXTENSIONS: &[&str] = &[".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv"];

static DATA_BROKER_DOMAINS: &[&str] = &[
    "zoominfo.com",
    "rocketreach.co",
    "apollo.io",
    "signalhire.com",
    "lusha.com",
    "contactout.com",
    "spokeo.com",
    "whitepages.com",
    "radaris.com",
    "truepeoplesearch.com",
];

/// Domains that require login or use aggressive anti-bot WAFs (e.g., ResearchGate, LinkedIn, Instagram, ZoomInfo).
/// We NEVER scrape these directly—we report the found link & search engine snippet directly so the
/// user's network never gets "Access is temporarily restricted".
static LOGIN_OR_WAF_PROTECTED_DOMAINS: &[&str] = &[
    "researchgate.net",
    "linkedin.com",
    "instagram.com",
    "facebook.com",
    "x.com",
    "twitter.com",
    "tiktok.com",
    "threads.net",
    "academia.edu",
    "quora.com",
    "pinterest.com",
    "medium.com",
    "glassdoor.com",
    "indeed.com",
    "sciencedirect.com",
    "ieeexplore.ieee.org",
    "springer.com",
    "zoominfo.com",
    "rocketreach.co",
    "signalhire.com",
    "lusha.com",
];

/// Returns true if a domain is known to require login or enforce strict anti-bot WAF rules.
pub fn is_login_or_waf_protected(domain: &str) -> bool {
    let d = domain.to_lowercase();
    LOGIN_OR_WAF_PROTECTED_DOMAINS
        .iter()
        .any(|protected| d == *protected || d.ends_with(&format!(".{}", protected)))
}

pub fn is_data_broker(domain: &str) -> bool {
    let d = domain.to_lowercase();
    DATA_BROKER_DOMAINS
        .iter()
        .any(|broker| d == *broker || d.ends_with(&format!(".{}", broker)))
}

/// Checks whether a search result genuinely references the FULL name (either `"Jane Doe"` or `"Doe Jane"` /
/// all name tokens present together / combined full-name handle), rejecting partial single-word hits
/// (like only `"Jane"` or only `"Doe"`).
pub fn matches_full_name_strict(
    title: &str,
    snippet: &str,
    url: &str,
    target: &ScanTarget,
) -> bool {
    let raw_combined = format!("{} {} {}", title, snippet, url).to_lowercase();
    // Normalize underscores, hyphens, dots, slashes, and punctuation into spaces so `_Surname`
    // is treated as a clean word boundary (since regex `\b` treats `_` as a word character!).
    let combined: String = raw_combined
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();

    // Also strip common compound name suffixes attached directly to a first name
    // (e.g. "ArjunReddy" -> "Arjun", "RohanBabu" -> "Rohan")
    let decompounded = strip_attached_name_suffixes(&combined);

    // 1. Check exact forward or swapped full-name phrase with word boundaries ("jane doe", "doe jane")
    for variant in target.exact_name_variants() {
        let v_lower = variant.to_lowercase();
        if contains_whole_word(&combined, &v_lower) || contains_whole_word(&decompounded, &v_lower)
        {
            return true;
        }
    }

    // 2. Check combined full-name handle slugs ("janedoe", "doejane")
    for handle in target.effective_usernames() {
        let h_lower = handle.trim().to_lowercase();
        if h_lower.len() >= 4
            && (raw_combined.contains(&h_lower) || decompounded.replace(' ', "").contains(&h_lower))
        {
            return true;
        }
    }

    // 3. Check explicit user-provided emails
    for email in &target.emails {
        let e_lower = email.trim().to_lowercase();
        if !e_lower.is_empty() && raw_combined.contains(&e_lower) {
            return true;
        }
    }

    // 4. Check explicit user-provided phone numbers (comparing pure digits so formatting differences don't matter)
    let combined_digits: String = raw_combined.chars().filter(|c| c.is_ascii_digit()).collect();
    for norm_phone in target.normalized_phone_digits() {
        if !norm_phone.is_empty() && combined_digits.contains(&norm_phone) {
            return true;
        }
    }

    // 5. Check that ALL tokens of any full name or `--alias` appear as whole words in `combined` or `decompounded`
    for token_set in target.all_name_token_sets() {
        if token_set.len() >= 2 {
            let all_tokens_present = token_set.iter().all(|tok| {
                let t_lower = tok.to_lowercase();
                contains_whole_word(&combined, &t_lower)
                    || contains_whole_word(&decompounded, &t_lower)
            });
            if all_tokens_present {
                return true;
            }
        }
    }

    false
}

fn strip_attached_name_suffixes(text: &str) -> String {
    const SUFFIXES: &[&str] = &[
        "reddy", "rao", "kumar", "naidu", "babu", "sharma", "goud", "varma", "verma", "devi",
    ];
    let mut words = Vec::new();
    for w in text.split_whitespace() {
        words.push(w.to_string());
        for suf in SUFFIXES {
            if w.len() > suf.len() + 3 && w.ends_with(suf) {
                words.push(w[..w.len() - suf.len()].to_string());
            }
        }
    }
    words.join(" ")
}

fn contains_whole_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let pattern = format!(r"\b{}\b", regex::escape(word));
    Regex::new(&pattern)
        .map(|re| re.is_match(haystack))
        .unwrap_or_else(|_| haystack.contains(word))
}

/// Intermediate grouped representation of a single canonical URL found across 1 or more dorks.
struct GroupedHit {
    canonical_url: String,
    domain: String,
    title: String,
    snippet: String,
    categories: Vec<DorkCategory>,
    dorks_matched: Vec<String>,
}

/// Normalizes a URL by stripping common tracking parameters and fragment identifiers.
pub fn normalize_url(raw_url: &str) -> (String, String) {
    if let Ok(mut parsed) = Url::parse(raw_url) {
        parsed.set_fragment(None);
        let domain = parsed.host_str().unwrap_or("unknown").to_lowercase();

        let clean_pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .filter(|(k, _)| {
                let key = k.to_lowercase();
                !key.starts_with("utm_")
                    && key != "fbclid"
                    && key != "gclid"
                    && key != "ref"
                    && key != "source"
            })
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        if clean_pairs.is_empty() {
            parsed.set_query(None);
        } else {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in clean_pairs {
                serializer.append_pair(&k, &v);
            }
            parsed.set_query(Some(&serializer.finish()));
        }

        let mut normalized = parsed.to_string();
        if normalized.ends_with('/') && parsed.path() == "/" {
            normalized.pop();
        }
        (normalized, domain)
    } else {
        (raw_url.to_string(), "unknown".to_string())
    }
}

/// Filters out partial single-name hits, deduplicates URLs, safely skips login/WAF sites during
/// optional deep verification, and scores confidence & privacy risk.
pub async fn analyze_results(
    raw_results: Vec<RawSearchResult>,
    target: &ScanTarget,
    deep_verify: bool,
) -> Vec<AnalyzedFinding> {
    let mut grouped_map: HashMap<String, GroupedHit> = HashMap::new();

    for hit in raw_results {
        if !matches_full_name_strict(&hit.title, &hit.snippet, &hit.url, target) {
            continue;
        }

        let (canonical_url, domain) = normalize_url(&hit.url);
        let entry = grouped_map
            .entry(canonical_url.clone())
            .or_insert_with(|| GroupedHit {
                canonical_url,
                domain,
                title: hit.title.clone(),
                snippet: hit.snippet.clone(),
                categories: Vec::new(),
                dorks_matched: Vec::new(),
            });

        if !entry.categories.contains(&hit.category) {
            entry.categories.push(hit.category);
        }
        if !entry.dorks_matched.contains(&hit.dork_used) {
            entry.dorks_matched.push(hit.dork_used);
        }
        // Merge rich snippets (e.g. FAQ phone/email answers) for the same URL
        if !hit.snippet.is_empty() && !entry.snippet.contains(&hit.snippet) {
            if entry.snippet.is_empty() {
                entry.snippet = hit.snippet;
            } else {
                entry.snippet = format!("{} | {}", entry.snippet, hit.snippet);
            }
        }
    }

    let grouped_hits: Vec<GroupedHit> = grouped_map.into_values().collect();
    let client = Client::builder()
        .timeout(Duration::from_secs(7))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .build()
        .unwrap_or_default();

    let semaphore = Arc::new(Semaphore::new(2));
    let target_arc = Arc::new(target.clone());

    let mut findings: Vec<AnalyzedFinding> = stream::iter(grouped_hits)
        .map(|hit| {
            let client = client.clone();
            let sem = Arc::clone(&semaphore);
            let target_ref = Arc::clone(&target_arc);
            async move {
                evaluate_single_hit(hit, &target_ref, deep_verify, &client, &sem).await
            }
        })
        .buffer_unordered(2)
        .collect()
        .await;

    // If `--strict-context` is enabled, keep only findings that matched at least one `--context` keyword,
    // `--email`, `--phone`, or explicit `--username`!
    if target.strict_context && !target.context_keywords.is_empty() {
        findings.retain(|f| {
            target
                .context_keywords
                .iter()
                .any(|ctx| f.matched_context.iter().any(|m| m.eq_ignore_ascii_case(ctx)))
                || f.matched_context
                    .iter()
                    .any(|m| m.starts_with("Target Email:") || m.starts_with("Target Phone:"))
        });
    }

    findings.sort_by(|a, b| {
        b.risk_level.cmp(&a.risk_level).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    findings
}

async fn evaluate_single_hit(
    hit: GroupedHit,
    target: &ScanTarget,
    deep_verify: bool,
    client: &Client,
    semaphore: &Semaphore,
) -> AnalyzedFinding {
    let mut inspect_text = format!("{} {} {}", hit.title, hit.snippet, hit.canonical_url);
    let mut page_verified = false;

    let url_lower = hit.canonical_url.to_lowercase();
    let is_binary_doc = DOC_EXTENSIONS.iter().any(|ext| url_lower.ends_with(ext));
    let is_protected = is_login_or_waf_protected(&hit.domain);
    let is_broker = is_data_broker(&hit.domain);

    if deep_verify && !is_binary_doc && !is_protected {
        if let Ok(_permit) = semaphore.acquire().await {
            tokio::time::sleep(Duration::from_millis(350)).await;
            if let Some(page_body) = fetch_visible_text_safely(client, &hit.canonical_url).await {
                let body_lower = page_body.to_lowercase();
                if target
                    .exact_name_variants()
                    .iter()
                    .any(|v| body_lower.contains(&v.to_lowercase()))
                {
                    page_verified = true;
                }
                let window = extract_context_window(&page_body, &target.full_name, 500);
                inspect_text.push(' ');
                inspect_text.push_str(&window);
            }
        }
    }

    let inspect_lower = inspect_text.to_lowercase();
    let mut pii_leaks_set: HashSet<PiiLeakType> = HashSet::new();

    if is_broker {
        pii_leaks_set.insert(PiiLeakType::SensitiveKeyword(
            "Data Broker Profile".to_string(),
        ));
    }

    for ext in DOC_EXTENSIONS {
        if url_lower.contains(ext) {
            pii_leaks_set.insert(PiiLeakType::DocumentFile(ext.to_string()));
        }
    }

    for mat in EMAIL_REGEX.find_iter(&inspect_text) {
        let email = mat.as_str().to_lowercase();
        if !email.ends_with(".png")
            && !email.ends_with(".jpg")
            && !email.ends_with(".svg")
            && !email.ends_with("users.noreply.github.com")
            && !email.starts_with("noreply@")
            && !email.starts_with("npm-oidc-no-reply@")
        {
            pii_leaks_set.insert(PiiLeakType::Email(email));
        }
    }

    // Scan title + snippet + page text (excluding raw URL path digits) for phone numbers
    let text_without_url = inspect_text.replace(&hit.canonical_url, " ");
    for mat in PHONE_REGEX.find_iter(&text_without_url) {
        pii_leaks_set.insert(PiiLeakType::Phone(mat.as_str().to_string()));
    }

    for kw in SENSITIVE_KEYWORDS {
        if inspect_lower.contains(kw) {
            pii_leaks_set.insert(PiiLeakType::SensitiveKeyword((*kw).to_string()));
        }
    }

    let mut matched_context = Vec::new();
    let mut context_kw_hits = 0usize;
    for ctx in &target.context_keywords {
        if !ctx.trim().is_empty() && inspect_lower.contains(&ctx.to_lowercase()) {
            matched_context.push(ctx.clone());
            context_kw_hits += 1;
        }
    }

    // Check if user's target email or phone number specifically matched
    let mut target_pii_matched = false;
    for t_email in &target.emails {
        let te = t_email.trim().to_lowercase();
        if !te.is_empty() && inspect_lower.contains(&te) {
            target_pii_matched = true;
            pii_leaks_set.insert(PiiLeakType::Email(te.clone()));
            matched_context.push(format!("Target Email: {}", te));
        }
    }

    let text_digits: String = text_without_url
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    for norm_phone in target.normalized_phone_digits() {
        if !norm_phone.is_empty() && text_digits.contains(&norm_phone) {
            target_pii_matched = true;
            pii_leaks_set.insert(PiiLeakType::Phone(norm_phone.clone()));
            matched_context.push(format!("Target Phone: {}", norm_phone));
        }
    }

    let effective_handles = target.effective_usernames();
    let mut handle_matched = false;
    for handle in &effective_handles {
        if !handle.trim().is_empty() && inspect_lower.contains(&handle.to_lowercase()) {
            handle_matched = true;
            let badge = format!("@{}", handle);
            if !matched_context.contains(&badge) {
                matched_context.push(badge);
            }
        }
    }

    let variants = target.exact_name_variants();
    let exact_phrase_matched = variants
        .iter()
        .any(|v| inspect_lower.contains(&v.to_lowercase()));
    for alt_v in variants.iter().skip(1) {
        if inspect_lower.contains(&alt_v.to_lowercase()) {
            matched_context.push(format!("Variant: \"{}\"", alt_v));
        }
    }

    if is_protected {
        matched_context.push("SERP Link (Login/WAF skipped)".to_string());
    }

    let mut confidence: f32 = 0.45;
    if exact_phrase_matched {
        confidence += 0.25;
    }
    if handle_matched {
        confidence += 0.15;
    }
    if context_kw_hits > 0 {
        confidence += (context_kw_hits as f32 * 0.22).min(0.35);
    }
    if target_pii_matched {
        confidence = 0.99;
    }
    if page_verified {
        confidence += 0.08;
    }
    confidence = confidence.clamp(0.40, 0.99);

    let pii_leaks: Vec<PiiLeakType> = pii_leaks_set.into_iter().collect();

    let risk_level = if !pii_leaks.is_empty()
        || is_broker
        || hit.categories.contains(&DorkCategory::DocumentsAndFiles)
    {
        RiskLevel::High
    } else if hit.categories.contains(&DorkCategory::ContactAndPii)
        || hit.categories.contains(&DorkCategory::SocialProfiles)
        || hit.categories.contains(&DorkCategory::CodeAndTech)
        || confidence >= 0.75
    {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    let (remediation_advice, remediation_url) =
        build_remediation_guidance(&hit.domain, &risk_level, &pii_leaks);

    AnalyzedFinding {
        url: hit.canonical_url,
        domain: hit.domain,
        title: hit.title,
        snippet: hit.snippet,
        categories: hit.categories,
        dorks_matched: hit.dorks_matched,
        confidence,
        risk_level,
        pii_leaks,
        matched_context,
        page_verified,
        remediation_advice,
        remediation_url,
    }
}

async fn fetch_visible_text_safely(client: &Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.contains("text/html") && !content_type.contains("text/plain") {
        return None;
    }

    let html_str = resp.text().await.ok()?;
    let lower_check = html_str.to_lowercase();
    if lower_check.contains("access is temporarily restricted")
        || lower_check.contains("just a moment...")
        || lower_check.contains("attention required! | cloudflare")
        || lower_check.contains("verify you are human")
    {
        return None;
    }

    let document = Html::parse_document(&html_str);
    let body_selector = Selector::parse("body").ok()?;

    let mut text = String::new();
    if let Some(body) = document.select(&body_selector).next() {
        for piece in body.text() {
            let trimmed = piece.trim();
            if !trimmed.is_empty() {
                text.push_str(trimmed);
                text.push(' ');
            }
            if text.len() > 20_000 {
                break;
            }
        }
    }
    Some(text)
}

fn extract_context_window(text: &str, name: &str, radius: usize) -> String {
    let lower = text.to_lowercase();
    let target = name.to_lowercase();
    if let Some(idx) = lower.find(&target) {
        let start = idx.saturating_sub(radius);
        let end = (idx + target.len() + radius).min(text.len());
        let valid_start = text
            .char_indices()
            .map(|(i, _)| i)
            .find(|&i| i >= start)
            .unwrap_or(0);
        let valid_end = text
            .char_indices()
            .map(|(i, _)| i)
            .rfind(|&i| i <= end)
            .unwrap_or(text.len());
        text[valid_start..valid_end].to_string()
    } else {
        text.chars().take(radius * 2).collect()
    }
}

fn build_remediation_guidance(
    domain: &str,
    risk: &RiskLevel,
    leaks: &[PiiLeakType],
) -> (String, Option<String>) {
    if domain.contains("calendar.google.com") {
        (
            "CRITICAL: Your Google Calendar is publicly readable! Open Google Calendar Settings > Access permissions for events and uncheck 'Make available to public'.".to_string(),
            Some("https://calendar.google.com/calendar/u/0/r/settings".to_string()),
        )
    } else if domain.contains("gravatar.com") {
        (
            "Review or hide your public Gravatar profile, linked social accounts, and avatar at Gravatar Profile Settings.".to_string(),
            Some("https://gravatar.com/profile".to_string()),
        )
    } else if domain.contains("zoominfo.com") {
        (
            "Submit a ZoomInfo Data Broker Removal Request to delete your exposed business email, phone number, and employment profile.".to_string(),
            Some("https://www.zoominfo.com/about-zoominfo/privacy-manage-profile".to_string()),
        )
    } else if domain.contains("rocketreach.co") {
        (
            "Request removal of your contact profile from RocketReach's database.".to_string(),
            Some("https://rocketreach.co/remove".to_string()),
        )
    } else if domain.contains("linkedin.com") {
        (
            "Adjust LinkedIn Public Profile Visibility or hide off-LinkedIn search indexing in Settings > Visibility.".to_string(),
            Some("https://www.linkedin.com/mypreferences/d/settings/edit-public-profile".to_string()),
        )
    } else if domain.contains("researchgate.net") {
        (
            "Adjust ResearchGate profile privacy & search engine indexing in Account Settings > Privacy.".to_string(),
            Some("https://www.researchgate.net/account.PrivacySettings.html".to_string()),
        )
    } else if domain.contains("github.com") || domain.contains("gist.github.com") {
        (
            "Enable 'Keep my email addresses private' in GitHub Email Settings and audit public repositories/gists.".to_string(),
            Some("https://github.com/settings/emails".to_string()),
        )
    } else if domain.contains("x.com") || domain.contains("twitter.com") {
        (
            "Protect your posts (private account) or delete old posts/accounts via X Privacy & Safety settings.".to_string(),
            Some("https://x.com/settings/audience_and_tagging".to_string()),
        )
    } else if domain.contains("reddit.com") {
        (
            "Disable 'Show up in search results' in Reddit Safety & Privacy settings and redact identifying comments.".to_string(),
            Some("https://www.reddit.com/settings/privacy".to_string()),
        )
    } else if domain.contains("instagram.com") || domain.contains("facebook.com") {
        (
            "Switch profile to Private and disable external search engine indexing in Meta Accounts Center.".to_string(),
            Some("https://accountscenter.meta.com/privacy".to_string()),
        )
    } else if domain.contains("pastebin.com") {
        (
            "Submit a Pastebin Abuse / PII Takedown Report if this paste leaks your personal contact info.".to_string(),
            Some("https://pastebin.com/contact".to_string()),
        )
    } else if *risk == RiskLevel::High || !leaks.is_empty() {
        (
            "Contact the site webmaster to remove exposed PII/documents, then request Google Personal Content Removal.".to_string(),
            Some("https://support.google.com/websearch/troubleshooter/9685456".to_string()),
        )
    } else {
        (
            "Review the page; if content is already deleted on the host, use Google's Remove Outdated Content tool.".to_string(),
            Some("https://search.google.com/search-console/remove-outdated-content".to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url_strips_tracking() {
        let (clean, domain) = normalize_url(
            "https://www.linkedin.com/in/johndoe?utm_source=google&fbclid=12345&id=42#bio",
        );
        assert_eq!(domain, "www.linkedin.com");
        assert_eq!(clean, "https://www.linkedin.com/in/johndoe?id=42");
    }

    #[test]
    fn test_matches_full_name_strict_rejects_partial_and_accepts_swapped() {
        let target = ScanTarget {
            full_name: "Jane Doe".to_string(),
            aliases: vec!["J. Doe".to_string()],
            usernames: vec![],
            context_keywords: vec![],
            emails: vec!["jane.personal@gmail.com".to_string()],
            phones: vec!["+91 9876543210".to_string()],
            auto_handles: true,
            strict_context: false,
        };

        assert!(matches_full_name_strict(
            "Jane Doe - Software Engineer",
            "Profile of Jane Doe",
            "https://example.com/profile",
            &target
        ));

        assert!(matches_full_name_strict(
            "Author Roster: Doe Jane",
            "Published paper",
            "https://example.com/roster",
            &target
        ));
        assert!(matches_full_name_strict(
            "Contact Directory",
            "Call +91-9876543210 for inquiries",
            "https://example.com/contact",
            &target
        ));

        assert!(!matches_full_name_strict(
            "Jane - Wikipedia",
            "Jane is a popular first name",
            "https://en.wikipedia.org/wiki/Jane",
            &target
        ));
    }

    #[test]
    fn test_protected_domains_are_detected() {
        assert!(is_login_or_waf_protected("www.researchgate.net"));
        assert!(is_login_or_waf_protected("in.linkedin.com"));
        assert!(is_login_or_waf_protected("www.instagram.com"));
        assert!(is_login_or_waf_protected("www.zoominfo.com"));
        assert!(!is_login_or_waf_protected("oldlinux.org"));
    }
}
