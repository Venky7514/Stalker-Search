use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported search engine providers (defaults to `Free` zero-key privacy mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    /// Zero-Key Privacy Mode: DuckDuckGo HTML + Yahoo fallback + GitHub/Reddit/HN/Direct Profile OSINT (No API key needed)
    #[default]
    Free,
    /// Official Google Custom Search JSON API (requires API Key + CX ID)
    Google,
    /// Serper.dev Google Search API (requires API Key only)
    Serper,
    /// Brave Web Search API (requires API Key)
    Brave,
    /// Self-hosted or public SearXNG instance (requires Base URL with JSON format enabled)
    Searxng,
}

impl fmt::Display for EngineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineKind::Free => write!(
                f,
                "Zero-Key Free Mode (DuckDuckGo + GitHub + Reddit + HN + Profile Probe)"
            ),
            EngineKind::Google => write!(f, "Google Custom Search"),
            EngineKind::Serper => write!(f, "Serper.dev (Google)"),
            EngineKind::Brave => write!(f, "Brave Search"),
            EngineKind::Searxng => write!(f, "SearXNG"),
        }
    }
}

/// Categories of search dorks used to uncover different kinds of personal exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DorkCategory {
    GeneralMentions,
    SocialProfiles,
    DocumentsAndFiles,
    CodeAndTech,
    ContactAndPii,
    UsernameMentions,
}

impl fmt::Display for DorkCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DorkCategory::GeneralMentions => write!(f, "General Mention"),
            DorkCategory::SocialProfiles => write!(f, "Social Profile"),
            DorkCategory::DocumentsAndFiles => write!(f, "Document / File"),
            DorkCategory::CodeAndTech => write!(f, "Code / Forum / Paste"),
            DorkCategory::ContactAndPii => write!(f, "Contact / PII Exposure"),
            DorkCategory::UsernameMentions => write!(f, "Username / Handle"),
        }
    }
}

/// A single generated search query ("dork") ready to be sent to a SearchEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkQuery {
    pub category: DorkCategory,
    pub query: String,
    pub description: String,
}

/// A raw search hit returned by a SearchEngine provider before deduplication and analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawSearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub category: DorkCategory,
    pub dork_used: String,
    pub engine: String,
}

/// Privacy risk classification for an analyzed web reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low = 1,
    Medium = 2,
    High = 3,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
        }
    }
}

/// Specific types of potentially sensitive personal information detected near a name reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiLeakType {
    Email(String),
    Phone(String),
    DocumentFile(String),
    SensitiveKeyword(String),
}

impl fmt::Display for PiiLeakType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PiiLeakType::Email(e) => write!(f, "Email ({})", e),
            PiiLeakType::Phone(p) => write!(f, "Phone ({})", p),
            PiiLeakType::DocumentFile(ext) => write!(f, "Document ({})", ext),
            PiiLeakType::SensitiveKeyword(kw) => write!(f, "Keyword ({})", kw),
        }
    }
}

/// Final deduplicated, verified, and risk-scored finding ready for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedFinding {
    pub url: String,
    pub domain: String,
    pub title: String,
    pub snippet: String,
    pub categories: Vec<DorkCategory>,
    pub dorks_matched: Vec<String>,
    /// 0.0 to 1.0 score estimating how likely this reference belongs to the target person.
    pub confidence: f32,
    pub risk_level: RiskLevel,
    pub pii_leaks: Vec<PiiLeakType>,
    pub matched_context: Vec<String>,
    /// True if `--deep-verify` fetched the live page and confirmed the name is present.
    pub page_verified: bool,
    pub remediation_advice: String,
    pub remediation_url: Option<String>,
}
