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

pub fn identity_paths(state_dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    (
        state_dir.join("device.crt.pem"),
        state_dir.join("device.key.pem"),
        state_dir.join("ca.crt.pem"),
        state_dir.join("identity.json"),
    )
}

pub fn load_identity(state_dir: &Path) -> Result<Option<(String, String)>> {
    let (_, _, _, identity) = identity_paths(state_dir);
    if !identity.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(identity)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    let device_id = value.get("device_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tenant_id = value.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if device_id.is_empty() || tenant_id.is_empty() {
        anyhow::bail!("persisted Cyclothone identity is incomplete");
    }
    Ok(Some((device_id, tenant_id)))
}

pub async fn bootstrap_if_needed(api_url: &str, state_dir: &Path) -> Result<bool> {
    let (cert, key, ca, _) = identity_paths(state_dir);

    if cert.is_file() && key.is_file() && ca.is_file() && load_identity(state_dir)?.is_some() {
        return Ok(true);
    }

    let token = match std::env::var("CYCLOTHONE_ENROLLMENT_TOKEN") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(false),
    };
    let detected_hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "cyclothone-device".to_string());
    let name = std::env::var("CYCLOTHONE_DEVICE_NAME").unwrap_or_else(|_| detected_hostname.clone());
    let hostname = detected_hostname;
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let platform = "windows".to_string();
    let platform_version = std::env::var("OS").ok();

    enroll_with_token(api_url, state_dir, &token, name, hostname, os, platform_version.clone(), arch, platform, platform_version).await?;
    Ok(true)
}

pub async fn enroll_with_token(
    api_url: &str,
    state_dir: &Path,
    token: &str,
    name: String,
    hostname: String,
    os: String,
    os_version: Option<String>,
    arch: String,
    platform: String,
    platform_version: Option<String>,
) -> Result<()> {
    let (cert, key, ca, _) = identity_paths(state_dir);
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
        "os_version": os_version,
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

    let (_, _, _, identity) = identity_paths(state_dir);
    atomic_write(&identity, serde_json::to_string(&serde_json::json!({
        "device_id": enrolled.device_id,
        "tenant_id": enrolled.tenant_id,
    }))?.as_bytes())?;

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
