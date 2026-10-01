use super::OnnxDetector;
use anyhow::{anyhow, Context, Result};
use reqwest::{Certificate, Identity};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct ModelInfo {
    pub version: i64,
    pub sha256: String,
    pub feature_names: Vec<String>,
    #[serde(default = "default_monitor")]
    pub threshold_monitor: f32,
    #[serde(default = "default_quarantine")]
    pub threshold_quarantine: f32,
    pub download_url: String,
}

fn default_monitor() -> f32 { 0.60 }
fn default_quarantine() -> f32 { 0.90 }

pub struct ModelSync {
    api_url: String,
    cache_dir: PathBuf,
    client: reqwest::Client,
    current: Option<Arc<OnnxDetector>>,
    current_sha: Option<String>,
}

impl ModelSync {
    pub fn new(
        api_url: String,
        cache_dir: PathBuf,
        cert_path: &Path,
        key_path: &Path,
        ca_path: &Path,
    ) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        let cert = std::fs::read(cert_path).context("read client cert")?;
        let key = std::fs::read(key_path).context("read client key")?;
        let mut combined = cert;
        combined.push(b'\n');
        combined.extend_from_slice(&key);
        let identity = Identity::from_pem(&combined).context("build identity")?;
        let ca_pem = std::fs::read(ca_path).context("read CA")?;
        let ca = Certificate::from_pem(&ca_pem).context("parse CA")?;

        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(30))
            .user_agent("sentinel-agent/0.1")
            .build()?;
        Ok(Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            cache_dir,
            client,
            current: None,
            current_sha: None,
        })
    }

    pub fn current(&self) -> Option<Arc<OnnxDetector>> { self.current.clone() }

    pub async fn sync_once(&mut self) -> Result<bool> {
        let info_url = format!("{}/v1/agent/model/active", self.api_url);
        let resp = self.client.get(&info_url).send().await?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(false);
        }
        if !resp.status().is_success() {
            return Err(anyhow!("active model request failed: {}", resp.status()));
        }
        let info: Option<ModelInfo> = resp.json().await?;
        let info = match info {
            Some(i) => i,
            None => return Ok(false),
        };

        if info.feature_names != super::FEATURE_NAMES {
            return Err(anyhow!("server model feature schema does not match agent"));
        }
        if info.sha256.len() != 64 || !info.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(anyhow!("invalid model sha256"));
        }
        if !(0.0..=1.0).contains(&info.threshold_monitor)
            || !(0.0..=1.0).contains(&info.threshold_quarantine)
            || info.threshold_monitor > info.threshold_quarantine
        {
            return Err(anyhow!("invalid model thresholds"));
        }
        if self.current_sha.as_deref() == Some(info.sha256.as_str()) {
            return Ok(false);
        }

        let model_path = self.cache_dir.join(format!("model-v{}.onnx", info.version));
        if !model_path.exists() || !verify_sha(&model_path, &info.sha256) {
            download(&self.client, &self.api_url, &info, &model_path).await?;
            if !verify_sha(&model_path, &info.sha256) {
                let _ = tokio::fs::remove_file(&model_path).await;
                return Err(anyhow!("model sha256 mismatch after download"));
            }
        }

        let detector = OnnxDetector::load(
            &model_path,
            info.version,
            info.threshold_monitor,
            info.threshold_quarantine,
        )?;
        info!("loaded onnx model v{} (sha={})", info.version, &info.sha256[..16]);
        self.current = Some(Arc::new(detector));
        self.current_sha = Some(info.sha256);
        Ok(true)
    }

    pub async fn run_periodic(mut self, every_secs: u64) -> ! {
        let mut ticker = tokio::time::interval(Duration::from_secs(every_secs));
        loop {
            ticker.tick().await;
            if let Err(e) = self.sync_once().await {
                warn!(error = %e, "model sync failed");
            }
        }
    }
}

async fn download(
    client: &reqwest::Client,
    api_url: &str,
    info: &ModelInfo,
    dest: &Path,
) -> Result<()> {
    let url = if info.download_url.starts_with("http://") || info.download_url.starts_with("https://") {
        info.download_url.clone()
    } else {
        format!("{}{}", api_url, info.download_url)
    };
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("download failed: {}", resp.status()));
    }
    let bytes = resp.bytes().await?;
    let tmp = dest.with_extension("tmp");
    tokio::fs::write(&tmp, &bytes).await?;
    tokio::fs::rename(&tmp, dest).await?;
    info!("downloaded model v{} ({} bytes)", info.version, bytes.len());
    Ok(())
}

fn verify_sha(path: &Path, expected: &str) -> bool {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let actual = hex::encode(Sha256::digest(&data));
    actual.eq_ignore_ascii_case(expected)
}
