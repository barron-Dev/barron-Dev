use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::{Certificate, Identity};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};
use tracing::warn;

#[derive(Debug, Clone, Deserialize)]
pub struct Command {
    pub id: String,
    pub tenant_id: String,
    pub device_id: String,
    pub action: String,
    pub args: Value,
    pub signature: String,
    pub signer_kid: String,
    pub issued_by: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
struct CommandEnvelope {
    commands: Vec<Command>,
}

#[derive(Clone)]
pub struct CommandWorker {
    api_url: String,
    device_id: String,
    tenant_id: String,
    signer_kid: String,
    verifier: VerifyingKey,
    client: reqwest::Client,
    poll_secs: u64,
}

impl CommandWorker {
    pub fn from_config(config: &crate::config::AgentConfig) -> Result<Self> {
        let cert = std::fs::read(config.state_dir.join("device.crt.pem")).context("read device certificate")?;
        let key = std::fs::read(config.state_dir.join("device.key.pem")).context("read device key")?;
        let ca = std::fs::read(config.state_dir.join("ca.crt.pem")).context("read CA certificate")?;
        let mut identity_pem = cert;
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(&key);
        let identity = Identity::from_pem(&identity_pem).context("build mTLS identity")?;
        let ca = Certificate::from_pem(&ca).context("parse CA certificate")?;
        let client = reqwest::Client::builder()
            .identity(identity).add_root_certificate(ca).timeout(Duration::from_secs(30))
            .user_agent("cyclothone-agent/command-runtime").build()?;

        let key_b64 = std::env::var("CYCLOTHONE_COMMAND_SIGNER_PUBLIC_KEY_B64")
            .context("CYCLOTHONE_COMMAND_SIGNER_PUBLIC_KEY_B64 must be provisioned")?;
        let raw = base64::engine::general_purpose::STANDARD.decode(key_b64.trim())
            .context("decode command signer public key")?;
        let key_bytes: [u8; 32] = raw.try_into()
            .map_err(|_| anyhow!("command signer public key must be exactly 32 bytes"))?;
        let signer_kid = std::env::var("CYCLOTHONE_COMMAND_SIGNER_KID")
            .context("CYCLOTHONE_COMMAND_SIGNER_KID must be provisioned")?;
        anyhow::ensure!(!signer_kid.trim().is_empty(), "command signer kid cannot be empty");

        Ok(Self {
            api_url: config.api_url.trim_end_matches('/').to_string(),
            device_id: config.device_id.clone(),
            tenant_id: config.tenant_id.clone(),
            signer_kid,
            verifier: VerifyingKey::from_bytes(&key_bytes)?,
            client,
            poll_secs: config.command_poll_secs,
        })
    }

    pub async fn run(self) -> ! {
        let mut ticker = tokio::time::interval(Duration::from_secs(self.poll_secs));
        loop {
            ticker.tick().await;
            match self.poll_once().await {
                Ok(commands) => {
                    for command in commands {
                        if let Err(error) = self.handle(command).await {
                            warn!(%error, "command handling failed");
                        }
                    }
                }
                Err(error) => warn!(%error, "command polling failed"),
            }
        }
    }

    async fn poll_once(&self) -> Result<Vec<Command>> {
        let url = format!("{}/api/v1/agent/commands?limit=10", self.api_url);
        let envelope: CommandEnvelope = self.client.get(url).send().await?.error_for_status()?.json().await?;
        Ok(envelope.commands)
    }

    async fn handle(&self, command: Command) -> Result<()> {
        let validation = self.validate_and_execute(&command).await;
        let (status, result, error) = match validation {
            Ok(value) => ("success", Some(value), None),
            Err(error) => ("failed", None, Some(error.to_string())),
        };

        let body = serde_json::json!({
            "command_id": command.id,
            "status": status,
            "result": result,
            "error": error,
        });
        let url = format!("{}/api/v1/agent/commands/{}/result", self.api_url, command.id);
        self.client.post(url).json(&body).send().await?.error_for_status()?;
        Ok(())
    }

    async fn validate_and_execute(&self, command: &Command) -> Result<Value> {
        anyhow::ensure!(command.device_id == self.device_id, "command device binding mismatch");
        anyhow::ensure!(command.tenant_id == self.tenant_id, "command tenant binding mismatch");
        anyhow::ensure!(command.signer_kid == self.signer_kid, "untrusted command signer kid");
        anyhow::ensure!(!expired(&command.expires_at)?, "command expired");

        let payload = canonical_payload(command);
        let encoded = serde_json::to_vec(&payload)?;
        let digest = hex::encode(Sha256::digest(encoded));
        let sig = base64::engine::general_purpose::STANDARD
            .decode(command.signature.trim()).context("decode command signature")?;
        let signature = Signature::from_slice(&sig).context("invalid Ed25519 signature encoding")?;
        self.verifier.verify(digest.as_bytes(), &signature)
            .map_err(|_| anyhow!("command signature verification failed"))?;

        execute(&command.action, &command.args).await
    }
}

fn canonical_payload(c: &Command) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("action".into(), c.action.clone().into());
    m.insert("args".into(), canonical_value(&c.args));
    m.insert("device_id".into(), c.device_id.clone().into());
    m.insert("expires_at".into(), c.expires_at.clone().into());
    m.insert("id".into(), c.id.clone().into());
    m.insert("issued_at".into(), c.issued_at.clone().into());
    m.insert("issued_by".into(), c.issued_by.clone().into());
    m.insert("tenant_id".into(), c.tenant_id.clone().into());
    m
}

fn canonical_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> =
                map.iter().map(|(k, v)| (k.clone(), canonical_value(v))).collect();
            serde_json::to_value(sorted).expect("serializing JSON values cannot fail")
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        _ => v.clone(),
    }
}

fn expired(value: &str) -> Result<bool> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value).context("invalid command expiry")?;
    Ok(parsed.with_timezone(&chrono::Utc) <= chrono::Utc::now())
}

async fn execute(action: &str, args: &Value) -> Result<Value> {
    match action {
        "kill_process" => kill_process(args).await,
        _ => Err(anyhow!("action '{}' is not implemented on this agent", action)),
    }
}

#[cfg(windows)]
async fn kill_process(args: &Value) -> Result<Value> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    let pid = args.get("pid").and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("pid required"))?;
    let pid = u32::try_from(pid).map_err(|_| anyhow!("invalid pid"))?;
    anyhow::ensure!(pid != 0, "pid 0 is forbidden");

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| anyhow!("OpenProcess failed: {e}"))?;
        let result = TerminateProcess(handle, 1)
            .map_err(|e| anyhow!("TerminateProcess failed: {e}"));
        let _ = CloseHandle(handle);
        result?;
    }
    Ok(serde_json::json!({"action":"kill_process","pid":pid}))
}

#[cfg(not(windows))]
async fn kill_process(_args: &Value) -> Result<Value> {
    Err(anyhow!("kill_process is Windows-only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_payload_is_deterministic() {
        let c = Command {
            id: "1".into(), tenant_id: "t".into(), device_id: "d".into(),
            action: "kill_process".into(), args: serde_json::json!({"z":1,"a":{"y":2,"x":3}}),
            signature: "sig".into(), signer_kid: "k".into(), issued_by: "u".into(),
            issued_at: "2026-09-18T00:00:00+00:00".into(),
            expires_at: "2026-09-18T00:05:00+00:00".into(),
        };
        let bytes = serde_json::to_vec(&canonical_payload(&c)).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(),
            r#"{"action":"kill_process","args":{"a":{"x":3,"y":2},"z":1},"device_id":"d","expires_at":"2026-09-18T00:05:00+00:00","id":"1","issued_at":"2026-09-18T00:00:00+00:00","issued_by":"u","tenant_id":"t"}"#);
    }
}
