use anyhow::{Context, Result};
use rcgen::{CertificateParams, DnType, KeyPair};
use serde::Deserialize;
use std::{path::{Path, PathBuf}, time::Duration};

#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    device_id: String,
    tenant_id: String,
    certificate_pem: String,
    ca_certificate_pem: String,
}

pub async fn bootstrap_if_needed(api_url: &str, state_dir: &Path) -> Result<()> {
    let cert = state_dir.join("device.crt.pem");
    let key = state_dir.join("device.key.pem");
    let ca = state_dir.join("ca.crt.pem");

    if cert.is_file() && key.is_file() && ca.is_file() {
        return Ok(());
    }

    let token = std::env::var("CYCLOTHONE_ENROLLMENT_TOKEN")
        .context("CYCLOTHONE_ENROLLMENT_TOKEN is required for first-time device enrollment")?;
    let name = std::env::var("CYCLOTHONE_DEVICE_NAME")
        .unwrap_or_else(|_| hostname::get().ok().and_then(|v| v.into_string().ok()).unwrap_or_else(|| "cyclothone-device".to_string()));
    let hostname = hostname::get()
        .ok()
        .and_then(|v| v.into_string().ok())
        .unwrap_or_else(|| name.clone());
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let platform = "windows".to_string();
    let platform_version = std::env::var("OS").ok();

    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::new())?;
    params.distinguished_name.push(DnType::CommonName, name.clone());
    let csr = params.serialize_request(&key_pair)?;
    let csr_pem = csr.pem()?;

    let url = format!("{}/api/v1/agent/enroll", api_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "token": token,
        "name": name,
        "hostname": hostname,
        "os": os,
        "os_version": platform_version,
        "arch": arch,
        "platform": platform,
        "platform_version": platform_version,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "csr_pem": csr_pem,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("cyclothone-agent/enrollment")
        .build()?;

    let response = client.post(url).json(&body).send().await?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("device enrollment rejected: {} {}", status, detail));
    }
    let enrolled: EnrollmentResponse = response.json().await?;

    anyhow::ensure!(!enrolled.device_id.is_empty(), "enrollment returned empty device_id");
    anyhow::ensure!(!enrolled.tenant_id.is_empty(), "enrollment returned empty tenant_id");

    std::fs::create_dir_all(state_dir)?;
    atomic_write(&key, key_pair.serialize_pem().as_bytes())?;
    atomic_write(&cert, enrolled.certificate_pem.as_bytes())?;
    atomic_write(&ca, enrolled.ca_certificate_pem.as_bytes())?;

    std::env::set_var("CYCLOTHONE_DEVICE_ID", &enrolled.device_id);
    std::env::set_var("CYCLOTHONE_TENANT_ID", &enrolled.tenant_id);

    Ok(())
}

fn atomic_write(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
