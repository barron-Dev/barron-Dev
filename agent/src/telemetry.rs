use anyhow::{Context, Result};
use reqwest::{Certificate, Identity};
use std::time::Duration;
use tracing::warn;

use crate::events::EndpointEvent;

const QUEUE_CAPACITY: usize = 1024;
const MAX_ATTEMPTS: usize = 5;

#[derive(Clone)]
pub struct TelemetryClient {
    api_url: String,
    client: reqwest::Client,
}

impl TelemetryClient {
    pub fn from_config(config: &crate::config::AgentConfig) -> Result<Self> {
        let cert = std::fs::read(config.state_dir.join("device.crt.pem"))
            .context("read device certificate")?;
        let key = std::fs::read(config.state_dir.join("device.key.pem"))
            .context("read device key")?;
        let ca = std::fs::read(config.state_dir.join("ca.crt.pem"))
            .context("read CA certificate")?;

        let mut identity_pem = cert;
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(&key);
        let identity = Identity::from_pem(&identity_pem).context("build mTLS identity")?;
        let ca = Certificate::from_pem(&ca).context("parse CA certificate")?;

        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(30))
            .user_agent("cyclothone-agent/telemetry-runtime")
            .build()?;

        Ok(Self {
            api_url: config.api_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    pub async fn send(&self, event: &EndpointEvent) -> Result<()> {
        let url = format!("{}/api/v1/agent/events", self.api_url);
        let mut delay = Duration::from_secs(1);

        for attempt in 1..=MAX_ATTEMPTS {
            match self.client.post(&url).json(event).send().await {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => {
                    let status = response.status();
                    if attempt == MAX_ATTEMPTS {
                        return Err(anyhow::anyhow!(
                            "telemetry rejected after {} attempts: {}",
                            MAX_ATTEMPTS,
                            status
                        ));
                    }
                    warn!(attempt, %status, event_id = %event.event_id, "telemetry delivery retry");
                }
                Err(error) => {
                    if attempt == MAX_ATTEMPTS {
                        return Err(error.into());
                    }
                    warn!(attempt, %error, event_id = %event.event_id, "telemetry delivery retry");
                }
            }

            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(8));
        }

        unreachable!("telemetry retry loop always returns")
    }
}

pub fn spawn(
    config: &crate::config::AgentConfig,
) -> Result<(
    tokio::sync::mpsc::Sender<EndpointEvent>,
    tokio::task::JoinHandle<()>,
)> {
    let client = TelemetryClient::from_config(config)?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<EndpointEvent>(QUEUE_CAPACITY);

    let task = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(error) = client.send(&event).await {
                warn!(%error, event_id = %event.event_id, "telemetry delivery failed");
            }
        }
    });

    Ok((tx, task))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_capacity_is_bounded() {
        assert_eq!(QUEUE_CAPACITY, 1024);
        assert!(QUEUE_CAPACITY > 0);
    }

    #[test]
    fn endpoint_path_is_canonical() {
        let base = "https://cyclothone-api.example";
        assert_eq!(format!("{}/api/v1/agent/events", base), "https://cyclothone-api.example/api/v1/agent/events");
    }
}
