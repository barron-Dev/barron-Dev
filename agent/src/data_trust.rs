use serde::{Deserialize, Serialize};

/// Language-neutral transfer telemetry contract shared by endpoint adapters.
/// Keep this transport model independent of USB, Bluetooth, or any one OS.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferRequest {
    pub tenant_id: String,
    pub asset_id: Option<String>,
    pub device_id: Option<String>,
    pub actor_id: Option<String>,
    pub source_type: String,
    pub destination_type: String,
    pub destination_ref: Option<String>,
    pub destination_trust: String,
    pub bytes_transferred: u64,
    pub content_inspected: bool,
    pub content_hash: Option<String>,
    pub observed_at: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferDecision {
    pub decision: String,
    pub reason_codes: Vec<String>,
    pub policy_id: Option<String>,
    pub classification: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_non_usb_channel() {
        let request = TransferRequest {
            tenant_id: "t".into(),
            asset_id: None,
            device_id: Some("d".into()),
            actor_id: None,
            source_type: "endpoint".into(),
            destination_type: "airdrop".into(),
            destination_ref: Some("peer-1".into()),
            destination_trust: "unknown".into(),
            bytes_transferred: 100,
            content_inspected: false,
            content_hash: None,
            observed_at: "2026-09-16T00:00:00Z".into(),
            metadata: serde_json::json!({}),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("airdrop"));
    }
}
