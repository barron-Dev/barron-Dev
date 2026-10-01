#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if std::env::args().any(|arg| arg == "--service") {
        return cyclothone_agent::service::windows_service::run()
            .map_err(|error| anyhow::anyhow!("Windows service dispatcher failed: {error}"));
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(cyclothone_agent::run_agent())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "cyclothone-agent is Windows-only; ETW is unavailable on this platform"
    ))
}
