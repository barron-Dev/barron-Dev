pub mod config;
pub mod events;
pub mod ml;

#[cfg(windows)]
pub mod etw;

#[cfg(windows)]
pub mod service;

pub use events::{EndpointEvent, EventKind};
pub use ml::{ModelInfo, ModelSync, OnnxDetector};

#[cfg(windows)]
pub async fn run_agent() -> anyhow::Result<()> {
    use std::sync::Arc;

    use tokio::sync::RwLock;
    use tracing::warn;

    let config = config::AgentConfig::from_env()?;
    let model_dir = config.state_dir.join("models");
    std::fs::create_dir_all(&model_dir)?;

    let cert = config.state_dir.join("device.crt.pem");
    let key = config.state_dir.join("device.key.pem");
    let ca = config.state_dir.join("ca.crt.pem");

    let mut sync = ModelSync::new(
        config.api_url.clone(),
        model_dir.clone(),
        &cert,
        &key,
        &ca,
    )?;
    if let Err(error) = sync.sync_once().await {
        warn!(%error, "initial model sync failed; agent continues without local ML");
    }

    let detector: Arc<RwLock<Option<Arc<OnnxDetector>>>> =
        Arc::new(RwLock::new(sync.current()));
    let sync_detector = Arc::clone(&detector);
    let sync_config = config.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            sync_config.model_sync_secs,
        ));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let mut next = match ModelSync::new(
                sync_config.api_url.clone(),
                sync_config.state_dir.join("models"),
                &sync_config.state_dir.join("device.crt.pem"),
                &sync_config.state_dir.join("device.key.pem"),
                &sync_config.state_dir.join("ca.crt.pem"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    warn!(%error, "model sync initialization failed");
                    continue;
                }
            };
            if let Err(error) = next.sync_once().await {
                warn!(%error, "periodic model sync failed");
                continue;
            }
            *sync_detector.write().await = next.current();
        }
    });

    let collector = etw::EtwCollector::start(config.host_id)?;
    let _detector = detector;

    // ETW ProcessTrace is a blocking Windows API. Keep it off the Tokio
    // executor so model synchronization and shutdown remain responsive.
    tokio::task::spawn_blocking(move || {
        collector.run(|event| match serde_json::to_string(&event) {
            Ok(line) => tracing::info!(target = "sentinel.telemetry", "{}", line),
            Err(error) => tracing::error!(%error, "failed to serialize ETW event"),
        })
    })
    .await??;

    Ok(())
}
