use super::OnnxDetector;
use crate::events::EndpointEvent;
use std::sync::Arc;
use tokio::sync::{mpsc::{Receiver, Sender}, RwLock};

/// Scores telemetry locally before it crosses the endpoint/server boundary.
/// Inference failures are fail-open for telemetry delivery: the event is still
/// forwarded without ML enrichment.
pub async fn run(
    mut rx: Receiver<EndpointEvent>,
    tx: Sender<EndpointEvent>,
    detector: Arc<RwLock<Option<Arc<OnnxDetector>>>>,
    local_action_threshold: f32,
) {
    while let Some(mut ev) = rx.recv().await {
        let d = detector.read().await.clone();
        if let Some(det) = d {
            match det.score(ev.kind_str(), &ev.payload) {
                Ok(score) => {
                    if let Some(obj) = ev.payload.as_object_mut() {
                        obj.insert("local_ml_score".into(), serde_json::json!(score));
                        obj.insert("local_ml_version".into(), serde_json::json!(det.version));
                        obj.insert("local_ml_verdict".into(), serde_json::json!(det.verdict(score)));
                    }
                    if score >= local_action_threshold {
                        tracing::warn!(event_id = %ev.event_id, score, "local_ml: high-confidence event");
                    }
                }
                Err(e) => tracing::debug!(error = %e, event_id = %ev.event_id, "local inference failed"),
            }
        }
        if tx.send(ev).await.is_err() {
            return;
        }
    }
}
