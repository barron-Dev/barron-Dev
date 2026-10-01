use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub host_id: String,
    pub api_url: String,
    pub state_dir: PathBuf,
    pub model_sync_secs: u64,
    pub device_id: String,
    pub tenant_id: String,
    pub command_poll_secs: u64,
}

impl AgentConfig {
    pub fn from_env() -> Result<Self> {
        let host_id = std::env::var("CYCLOTHONE_HOST_ID")
            .context("CYCLOTHONE_HOST_ID must identify this endpoint")?;
        let api_url = std::env::var("CYCLOTHONE_API_URL")
            .context("CYCLOTHONE_API_URL must identify the Cyclothone API")?;
        let state_dir = std::env::var("CYCLOTHONE_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\Cyclothone"));
        let model_sync_secs = std::env::var("CYCLOTHONE_MODEL_SYNC_SECS")
            .ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(3600);
        let persisted = crate::enrollment::load_identity(&state_dir)?.ok_or_else(|| anyhow::anyhow!("device identity is not enrolled"))?;
        let device_id = std::env::var("CYCLOTHONE_DEVICE_ID").unwrap_or_else(|_| persisted.0.clone());
        let tenant_id = std::env::var("CYCLOTHONE_TENANT_ID").unwrap_or_else(|_| persisted.1.clone());
        let command_poll_secs = std::env::var("CYCLOTHONE_COMMAND_POLL_SECS")
            .ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(5).clamp(1, 60);

        anyhow::ensure!(!host_id.trim().is_empty(), "CYCLOTHONE_HOST_ID cannot be empty");
        anyhow::ensure!(!api_url.trim().is_empty(), "CYCLOTHONE_API_URL cannot be empty");
        anyhow::ensure!(model_sync_secs > 0, "CYCLOTHONE_MODEL_SYNC_SECS must be > 0");
        anyhow::ensure!(!device_id.trim().is_empty(), "CYCLOTHONE_DEVICE_ID cannot be empty");
        anyhow::ensure!(!tenant_id.trim().is_empty(), "CYCLOTHONE_TENANT_ID cannot be empty");
        Ok(Self { host_id, api_url, state_dir, model_sync_secs, device_id, tenant_id, command_poll_secs })
    }
}