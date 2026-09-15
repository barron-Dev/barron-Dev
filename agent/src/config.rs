use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub host_id: String,
}

impl AgentConfig {
    pub fn from_env() -> Result<Self> {
        let host_id = std::env::var("SENTINEL_HOST_ID")
            .context("SENTINEL_HOST_ID must identify this endpoint")?;
        anyhow::ensure!(!host_id.trim().is_empty(), "SENTINEL_HOST_ID cannot be empty");
        Ok(Self { host_id })
    }
}
