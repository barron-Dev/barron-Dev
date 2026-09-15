mod features;
mod sync;

pub use features::{extract, FEATURE_NAMES, N_FEATURES};
pub use sync::{ModelInfo, ModelSync};

use anyhow::{anyhow, Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct OnnxDetector {
    session: Arc<Session>,
    pub version: i64,
    pub threshold_monitor: f32,
    pub threshold_quarantine: f32,
}

impl OnnxDetector {
    pub fn load(
        path: &Path,
        version: i64,
        threshold_monitor: f32,
        threshold_quarantine: f32,
    ) -> Result<Self> {
        anyhow::ensure!((0.0..=1.0).contains(&threshold_monitor));
        anyhow::ensure!((0.0..=1.0).contains(&threshold_quarantine));
        anyhow::ensure!(threshold_monitor <= threshold_quarantine);

        let session = Session::builder()?
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)?
            .commit_from_file(path)
            .with_context(|| format!("load onnx {}", path.display()))?;
        Ok(Self {
            session: Arc::new(session),
            version,
            threshold_monitor,
            threshold_quarantine,
        })
    }

    /// Returns the positive-class probability in [0, 1].
    pub fn score(&self, event_type: &str, payload: &serde_json::Value) -> Result<f32> {
        let features = extract(event_type, payload);
        let tensor = Tensor::from_array(([1usize, N_FEATURES], features.to_vec()))?;
        let outputs = self.session.run(ort::inputs!["input" => tensor])?;
        let (_shape, data) = outputs[0].try_extract_tensor::<f32>()?;

        if data.is_empty() {
            return Err(anyhow!("empty onnx output"));
        }
        let p = if data.len() >= 2 { data[1] } else { data[0] };
        anyhow::ensure!(p.is_finite(), "non-finite onnx probability");
        anyhow::ensure!((0.0..=1.0).contains(&p), "onnx probability outside [0,1]");
        Ok(p)
    }

    pub fn verdict(&self, score: f32) -> &'static str {
        if score >= self.threshold_quarantine {
            "quarantine"
        } else if score >= self.threshold_monitor {
            "monitor"
        } else {
            "allow"
        }
    }
}

pub struct ModelHandle {
    pub detector: Option<Arc<OnnxDetector>>,
    pub cache_dir: PathBuf,
}

impl ModelHandle {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { detector: None, cache_dir }
    }
}
