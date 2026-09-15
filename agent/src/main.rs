#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = sentinel_agent::config::AgentConfig::from_env()?;
    let collector = sentinel_agent::etw::EtwCollector::start(config.host_id)?;
    collector.run(|event| {
        match serde_json::to_string(&event) {
            Ok(line) => tracing::info!(target = "sentinel.telemetry", "{}", line),
            Err(error) => tracing::error!(%error, "failed to serialize ETW event"),
        }
    })
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("sentinel-agent is Windows-only; ETW is unavailable on this platform"))
}
