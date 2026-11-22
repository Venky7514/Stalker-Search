use crate::models::EngineKind;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Root configuration saved in `~/.stalker-search/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub default_engine: EngineKind,
    #[serde(default)]
    pub google: GoogleConfig,
    #[serde(default)]
    pub serper: SerperConfig,
    #[serde(default)]
    pub brave: BraveConfig,
    #[serde(default)]
    pub searxng: SearxngConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoogleConfig {
    pub api_key: Option<String>,
    /// Programmable Search Engine ID (cx)
    pub cx: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SerperConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BraveConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearxngConfig {
    pub base_url: Option<String>,
}

impl AppConfig {
    /// Returns the path to the user's configuration file (`~/.stalker-search/config.toml`).
    pub fn config_path() -> Result<PathBuf> {
        if let Ok(custom) = std::env::var("STALKER_SEARCH_CONFIG") {
            return Ok(PathBuf::from(custom));
        }

        let base = dirs::home_dir()
            .or_else(dirs::config_dir)
            .context("Could not determine user home or config directory")?;

        Ok(base.join(".stalker-search").join("config.toml"))
    }

    /// Loads config from disk (if present) and overlays any environment variables.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        let mut cfg = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config file at {}", path.display()))?;
            toml::from_str::<AppConfig>(&raw)
                .with_context(|| format!("Failed to parse TOML in {}", path.display()))?
        } else {
            AppConfig::default()
        };

        // Overlay environment variables for convenience
        if let Ok(val) = std::env::var("STALKER_GOOGLE_API_KEY") {
            if !val.trim().is_empty() {
                cfg.google.api_key = Some(val);
            }
        }
        if let Ok(val) = std::env::var("STALKER_GOOGLE_CX") {
            if !val.trim().is_empty() {
                cfg.google.cx = Some(val);
            }
        }
        if let Ok(val) = std::env::var("STALKER_SERPER_API_KEY") {
            if !val.trim().is_empty() {
                cfg.serper.api_key = Some(val);
            }
        }
        if let Ok(val) = std::env::var("STALKER_BRAVE_API_KEY") {
            if !val.trim().is_empty() {
                cfg.brave.api_key = Some(val);
            }
        }
        if let Ok(val) = std::env::var("STALKER_SEARXNG_URL") {
            if !val.trim().is_empty() {
                cfg.searxng.base_url = Some(val);
            }
        }

        Ok(cfg)
    }

    /// Saves the configuration to `~/.stalker-search/config.toml`.
    pub fn save(&self) -> Result<PathBuf> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory {}", parent.display())
            })?;
        }

        let toml_str =
            toml::to_string_pretty(self).context("Failed to serialize configuration to TOML")?;
        fs::write(&path, toml_str)
            .with_context(|| format!("Failed to write config file to {}", path.display()))?;
        Ok(path)
    }
}

/// Masks an API key for safe terminal display (e.g., `AIza****...****9aB`).
pub fn mask_secret(secret: &Option<String>) -> String {
    match secret {
        None => "<not set>".to_string(),
        Some(s) if s.len() <= 8 => "********".to_string(),
        Some(s) => {
            let prefix = &s[..4];
            let suffix = &s[s.len() - 3..];
            format!("{}...{}", prefix, suffix)
        }
    }
}
