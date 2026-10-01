pub mod config;
pub mod enrollment;
pub mod data_trust;
pub mod events;
pub mod commands;
pub mod ml;
pub mod telemetry;
#[cfg(windows)]
pub mod ipc;

#[cfg(windows)]
pub mod etw;

#[cfg(windows)]
pub mod service;

pub use data_trust::{TransferDecision as DataTrustDecision, TransferRequest as DataTrustTransferRequest};
pub use events::{EndpointEvent, EventKind};
pub use ml::{ModelInfo, ModelSync, OnnxDetector};

#[cfg(windows)]
pub async fn run_agent() -> anyhow::Result<()> {
    use std::sync::Arc;

    use tokio::sync::{mpsc, RwLock};
    use tracing::warn;

    let api_url = std::env::var("CYCLOTHONE_API_URL")
        .map_err(|_| anyhow::anyhow!("CYCLOTHONE_API_URL must identify the Cyclothone API"))?;
    let state_dir = std::env::var("CYCLOTHONE_STATE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\\ProgramData\\Cyclothone"));
    let enrolled = enrollment::bootstrap_if_needed(&api_url, &state_dir).await?;
    let identity = Arc::new(std::sync::Mutex::new(enrollment::load_identity(&state_dir)?));
    let health = Arc::new(ipc::HealthState::new(enrolled));
    ipc::spawn_status_server(
        api_url.clone(),
        state_dir.clone(),
        true,
        Arc::clone(&identity),
        Arc::clone(&health),
    );
    if !enrolled {
        tracing::info!("agent waiting for authenticated desktop enrollment");
        loop {
            if health.enrolled.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    let config = config::AgentConfig::from_env()?;
    let model_dir = config.state_dir.join("models");
    std::fs::create_dir_all(&model_dir)?;

    let cert = config.state_dir.join("device.crt.pem");
    let key = config.state_dir.join("device.key.pem");
    let ca = config.state_dir.join("ca.crt.pem");

    let mut sync = ModelSync::new(config.api_url.clone(), model_dir.clone(), &cert, &key, &ca)?;
    if let Err(error) = sync.sync_once().await {
        warn!(%error, "initial model sync failed; agent continues without local ML");
    }

    let detector: Arc<RwLock<Option<Arc<OnnxDetector>>>> =
        Arc::new(RwLock::new(sync.current()));
    let sync_detector = Arc::clone(&detector);
    let sync_config = config.clone();

    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(sync_config.model_sync_secs));
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

    // Single telemetry pipeline:
    // ETW -> bounded queue -> local ML enrichment -> bounded mTLS API delivery.
    let (raw_tx, raw_rx) = mpsc::channel::<EndpointEvent>(1024);
    let (enriched_tx, enriched_rx) = mpsc::channel::<EndpointEvent>(1024);

    tokio::spawn(ml::run_enricher(
        raw_rx,
        enriched_tx,
        Arc::clone(&detector),
        0.90,
    ));

    let (telemetry_tx, _telemetry_task) = telemetry::spawn(&config, Arc::clone(&health))?;
    tokio::spawn(async move {
        let mut rx = enriched_rx;
        while let Some(event) = rx.recv().await {
            if telemetry_tx.send(event).await.is_err() {
                warn!("telemetry delivery queue closed");
                break;
            }
        }
    });

    let collector = etw::EtwCollector::start(config.host_id.clone())?;
    let command_worker = commands::CommandWorker::from_config(&config)?;
    tokio::spawn(command_worker.run());

    tokio::task::spawn_blocking(move || {
        collector.run(move |event| {
            if let Err(error) = raw_tx.blocking_send(event) {
                tracing::error!(%error, "ETW telemetry queue closed");
            }
        })
    })
    .await??;

    Ok(())
}
