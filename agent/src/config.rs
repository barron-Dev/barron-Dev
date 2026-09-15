use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub host_id: String,
    pub api_url: String,
    pub state_dir: PathBuf,
    pub model_sync_secs: u64,
}

impl AgentConfig {
    pub fn from_env() -> Result<Self> {
        let host_id = std::env::var("SENTINEL_HOST_ID")
            .context("SENTINEL_HOST_ID must identify this endpoint")?;
        let api_url = std::env::var("SENTINEL_API_URL")
            .context("SENTINEL_API_URL must identify the Sentinel API")?;
        let state_dir = std::env::var("SENTINEL_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./state"));
        let model_sync_secs = std::env::var("SENTINEL_MODEL_SYNC_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(3600);

        anyhow::ensure!(!host_id.trim().is_empty(), "SENTINEL_HOST_ID cannot be empty");
        anyhow::ensure!(!api_url.trim().is_empty(), "SENTINEL_API_URL cannot be empty");
        anyhow::ensure!(model_sync_secs > 0, "SENTINEL_MODEL_SYNC_SECS must be > 0");
        Ok(Self { host_id, api_url, state_dir, model_sync_secs })
    }
}
