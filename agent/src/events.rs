use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessStart,
    ProcessStop,
    NetworkConnect,
    FileActivity,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointEvent {
    pub schema_version: u16,
    pub event_id: String,
    pub observed_at: String,
    pub kind: EventKind,
    pub host_id: String,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub payload: Value,
}

impl EndpointEvent {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.schema_version == Self::SCHEMA_VERSION, "unsupported event schema version");
        anyhow::ensure!(!self.event_id.trim().is_empty(), "event_id required");
        anyhow::ensure!(!self.observed_at.trim().is_empty(), "observed_at required");
        anyhow::ensure!(!self.host_id.trim().is_empty(), "host_id required");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_normalized_event() {
        let event = EndpointEvent {
            schema_version: 1,
            event_id: "evt-1".into(),
            observed_at: "2026-09-16T00:00:00Z".into(),
            kind: EventKind::ProcessStart,
            host_id: "host-1".into(),
            pid: Some(42),
            parent_pid: Some(4),
            image: Some("C:\\\\Windows\\\\System32\\\\notepad.exe".into()),
            command_line: None,
            remote_address: None,
            remote_port: None,
            payload: Value::Null,
        };
        assert!(event.validate().is_ok());
    }

    #[test]
    fn rejects_wrong_schema() {
        let event = EndpointEvent {
            schema_version: 999,
            event_id: "evt-1".into(),
            observed_at: "now".into(),
            kind: EventKind::Unknown,
            host_id: "host-1".into(),
            pid: None,
            parent_pid: None,
            image: None,
            command_line: None,
            remote_address: None,
            remote_port: None,
            payload: Value::Null,
        };
        assert!(event.validate().is_err());
    }
}
