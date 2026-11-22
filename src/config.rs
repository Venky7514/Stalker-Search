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
    pub searxng: SearxngConfig,
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

    /// Loads config from disk (if present) and overlays `STALKER_SEARXNG_URL` if set.
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
