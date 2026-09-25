use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::{Certificate, Identity};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::{Path, PathBuf}, time::Duration, net::ToSocketAddrs};
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
    #[serde(default)]
    pub case_action_id: Option<String>,
    #[serde(default)]
    pub execution_context: Value,
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
    state_dir: PathBuf,
    management_host: String,
    management_port: u16,
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
        let parsed_api = reqwest::Url::parse(&config.api_url).context("invalid agent API URL")?;
        let management_host = parsed_api.host_str().context("agent API URL has no host")?.to_string();
        let management_port = parsed_api.port_or_known_default().unwrap_or(443);

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
            state_dir: config.state_dir.clone(),
            management_host,
            management_port,
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

        execute(&command.action, &command.args, &self.state_dir, &self.management_host, self.management_port).await
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
    m.insert("case_action_id".into(), c.case_action_id.clone().map(Value::String).unwrap_or(Value::Null));
    m.insert("execution_context".into(), canonical_value(&c.execution_context));
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

async fn execute(action: &str, args: &Value, state_dir: &Path, management_host: &str, management_port: u16) -> Result<Value> {
    match action {
        "kill_process" => kill_process(args).await,
        "block_ip" => block_ip(args).await,
        "unblock_ip" => unblock_ip(args).await,
        "quarantine_file" => quarantine_file(args, state_dir).await,
        "restore_file" => restore_file(args, state_dir).await,
        "isolate_host" => isolate_host(args, state_dir, management_host, management_port).await,
        "release_host" => release_host(args, state_dir).await,
        // A hash alone does not identify a local file on Windows. Executing an
        // unverified hash-only block would create a false security guarantee.
        "block_hash" | "unblock_hash" => Err(anyhow!(
            "{} requires a platform-backed endpoint-control integration; hash-only execution is fail-closed",
            action
        )),
        _ => Err(anyhow!("action '{}' is not implemented on this agent", action)),
    }
}

#[cfg(windows)]
async fn powershell(script: &str) -> Result<String> {
    let output = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .await
        .context("launch PowerShell")?;
    if !output.status.success() {
        return Err(anyhow!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(not(windows))]
async fn powershell(_script: &str) -> Result<String> {
    Err(anyhow!("Windows response executor unavailable on non-Windows agent"))
}

fn safe_firewall_token(value: &str) -> Result<String> {
    let token: String = value.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    anyhow::ensure!(!token.is_empty() && token.len() <= 80, "invalid firewall rule token");
    Ok(token)
}

#[cfg(windows)]
async fn kill_process(args: &Value) -> Result<Value> {
    let pid = args.get("pid").and_then(Value::as_u64).ok_or_else(|| anyhow!("pid required"))?;
    anyhow::ensure!(pid > 0 && pid <= u32::MAX as u64, "invalid process id");
    let script = format!("Stop-Process -Id {} -Force -ErrorAction Stop", pid);
    powershell(&script).await?;
    Ok(serde_json::json!({"action":"kill_process","pid":pid}))
}

#[cfg(not(windows))]
async fn kill_process(_args: &Value) -> Result<Value> {
    Err(anyhow!("kill_process is Windows-only"))
}

async fn block_ip(args: &Value) -> Result<Value> {
    let ip = args.get("ip").and_then(Value::as_str).ok_or_else(|| anyhow!("ip required"))?;
    let ip = ip.parse::<std::net::IpAddr>().map_err(|_| anyhow!("invalid IP address"))?;
    #[cfg(windows)]
    {
        let token = safe_firewall_token(&ip.to_string().replace(':', "-"))?;
        let script = format!(
            "New-NetFirewallRule -Name 'Cyclothone-Block-IP-{token}' -DisplayName 'Cyclothone Block IP {token}' -Direction Inbound -RemoteAddress '{ip}' -Action Block -Profile Any -ErrorAction Stop | Out-Null;              New-NetFirewallRule -Name 'Cyclothone-Block-IP-Out-{token}' -DisplayName 'Cyclothone Block IP Out {token}' -Direction Outbound -RemoteAddress '{ip}' -Action Block -Profile Any -ErrorAction Stop | Out-Null"
        );
        powershell(&script).await?;
        return Ok(serde_json::json!({"action":"block_ip","ip":ip.to_string()}));
    }
    #[cfg(not(windows))]
    { let _ = ip; Err(anyhow!("block_ip is Windows-only")) }
}

async fn unblock_ip(args: &Value) -> Result<Value> {
    let ip = args.get("ip").and_then(Value::as_str).ok_or_else(|| anyhow!("ip required"))?;
    let ip = ip.parse::<std::net::IpAddr>().map_err(|_| anyhow!("invalid IP address"))?;
    #[cfg(windows)]
    {
        let token = safe_firewall_token(&ip.to_string().replace(':', "-"))?;
        let script = format!(
            "Remove-NetFirewallRule -Name 'Cyclothone-Block-IP-{token}','Cyclothone-Block-IP-Out-{token}' -ErrorAction SilentlyContinue"
        );
        powershell(&script).await?;
        return Ok(serde_json::json!({"action":"unblock_ip","ip":ip.to_string()}));
    }
    #[cfg(not(windows))]
    { let _ = ip; Err(anyhow!("unblock_ip is Windows-only")) }
}

fn protected_path(path: &Path, state_dir: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let state = state_dir.to_string_lossy().to_ascii_lowercase();
    lower == state || lower.starts_with(&(state.clone() + "\\"))
        || lower == r"c:\windows" || lower.starts_with(r"c:\windows\system32")
        || lower == r#"c:\program files"# || lower.starts_with(r#"c:\program files\"#)
}

async fn quarantine_file(args: &Value, state_dir: &Path) -> Result<Value> {
    let raw = args.get("path").and_then(Value::as_str).ok_or_else(|| anyhow!("path required"))?;
    let source = tokio::fs::canonicalize(raw).await.context("resolve quarantine path")?;
    anyhow::ensure!(source.is_file(), "quarantine target is not a regular file");
    anyhow::ensure!(!protected_path(&source, state_dir), "protected path cannot be quarantined");
    let quarantine_dir = state_dir.join("quarantine");
    tokio::fs::create_dir_all(&quarantine_dir).await?;
    let digest = {
        let data = tokio::fs::read(&source).await.context("read quarantine target")?;
        hex::encode(Sha256::digest(&data))
    };
    let file_name = source.file_name().and_then(|v| v.to_str()).unwrap_or("file");
    let destination = quarantine_dir.join(format!("{digest}-{file_name}"));
    tokio::fs::rename(&source, &destination).await.context("move file into quarantine")?;
    let manifest = quarantine_dir.join(format!("{digest}.json"));
    tokio::fs::write(&manifest, serde_json::to_vec(&serde_json::json!({
        "original": source,
        "quarantined": destination,
        "sha256": digest
    }))?).await?;
    Ok(serde_json::json!({"action":"quarantine_file","sha256":digest,"original":source,"quarantined":destination}))
}

async fn restore_file(args: &Value, state_dir: &Path) -> Result<Value> {
    let raw = args.get("original").and_then(Value::as_str).ok_or_else(|| anyhow!("original path required"))?;
    let original = PathBuf::from(raw);
    anyhow::ensure!(!protected_path(&original, state_dir), "protected path cannot be restored");
    let quarantine_dir = state_dir.join("quarantine");
    let mut matches = Vec::new();
    let mut dir = tokio::fs::read_dir(&quarantine_dir).await.context("open quarantine store")?;
    while let Some(entry) = dir.next_entry().await? {
        if entry.path().extension().and_then(|x| x.to_str()) == Some("json") {
            let data = tokio::fs::read(entry.path()).await?;
            let record: Value = serde_json::from_slice(&data)?;
            if record.get("original").and_then(Value::as_str) == Some(raw) {
                matches.push(record);
            }
        }
    }
    let record = matches.pop().ok_or_else(|| anyhow!("no quarantine record for original path"))?;
    let quarantined = PathBuf::from(record.get("quarantined").and_then(Value::as_str).ok_or_else(|| anyhow!("invalid quarantine record"))?);
    anyhow::ensure!(quarantined.is_file(), "quarantined file is missing");
    if let Some(parent) = original.parent() { tokio::fs::create_dir_all(parent).await?; }
    anyhow::ensure!(!original.exists(), "restore destination already exists");
    tokio::fs::rename(&quarantined, &original).await.context("restore quarantined file")?;
    Ok(serde_json::json!({"action":"restore_file","original":original,"restored":true}))
}

async fn isolate_host(_args: &Value, state_dir: &Path, management_host: &str, management_port: u16) -> Result<Value> {
    #[cfg(windows)]
    {
        let marker = state_dir.join("isolation.json");
        let api_host = management_host;
        let port = management_port.to_string();
        let addresses: Vec<String> = (api_host, management_port)
            .to_socket_addrs().map_err(|e| anyhow!("resolve management API: {e}"))?
            .map(|x| x.ip().to_string()).collect();
        anyhow::ensure!(!addresses.is_empty(), "management API did not resolve");
        let remote = addresses.join(",");
        let script = format!(
            "$ErrorActionPreference='Stop';              New-NetFirewallRule -Name 'Cyclothone-Isolation-In' -Direction Inbound -RemoteAddress Any -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null;              New-NetFirewallRule -Name 'Cyclothone-Isolation-Out' -Direction Outbound -RemoteAddress Any -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null;              New-NetFirewallRule -Name 'Cyclothone-Isolation-Management' -Direction Outbound -Protocol TCP -RemoteAddress '{remote}' -RemotePort {port} -Action Allow -OverrideBlockRules True -Profile Any -ErrorAction Stop | Out-Null"
        );
        powershell(&script).await?;
        let marker_bytes = serde_json::to_vec(&serde_json::json!({"management_addresses":addresses,"port":port}))?;
        tokio::fs::write(&marker, marker_bytes).await?;
        return Ok(serde_json::json!({"action":"isolate_host","management_allowlist":addresses}));
    }
    #[cfg(not(windows))]
    { let _ = state_dir; Err(anyhow!("isolate_host is Windows-only")) }
}

async fn release_host(_args: &Value, state_dir: &Path) -> Result<Value> {
    #[cfg(windows)]
    {
        let script = "Remove-NetFirewallRule -Name 'Cyclothone-Isolation-In','Cyclothone-Isolation-Out','Cyclothone-Isolation-Management' -ErrorAction SilentlyContinue";
        powershell(script).await?;
        let _ = tokio::fs::remove_file(state_dir.join("isolation.json")).await;
        return Ok(serde_json::json!({"action":"release_host","released":true}));
    }
    #[cfg(not(windows))]
    { let _ = state_dir; Err(anyhow!("release_host is Windows-only")) }
}


