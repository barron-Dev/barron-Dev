"""Optional local environmental-sound classification with honest coverage.

The caller must provision a real TFLite model and its matching labels file. No labels
are guessed, no remote download occurs, and detections never actuate physical systems.
"""
from dataclasses import dataclass
from pathlib import Path
import hashlib


@dataclass(frozen=True, slots=True)
class SoundClassification:
    audio_sha256: str
    model_sha256: str | None
    label: str | None
    score: float | None
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    requires_human_review: bool = True


class YamnetTFLiteClassifier:
    def __init__(self, model_path: str, labels_path: str, *, threshold: float = 0.5):
        model, labels = Path(model_path), Path(labels_path)
        if not model.is_file() or not labels.is_file():
            raise ValueError("real_model_and_labels_files_required")
        if not 0 < threshold <= 1:
            raise ValueError("threshold_must_be_in_(0,1]")
        self.model_sha256 = hashlib.sha256(model.read_bytes()).hexdigest()
        raw_labels = labels.read_text(encoding="utf-8").splitlines()
        self.labels = tuple(line.strip().split(",", 1)[-1].strip()
                            for line in raw_labels if line.strip())
        if not self.labels:
            raise ValueError("empty_label_file")
        try:
            from tflite_runtime.interpreter import Interpreter
        except ImportError:
            try:
                from tensorflow.lite import Interpreter
            except ImportError as exc:
                raise RuntimeError("tflite_runtime_or_tensorflow_required") from exc
        self._interpreter = Interpreter(model_path=str(model), num_threads=2)
        self._interpreter.allocate_tensors()
        self._input = self._interpreter.get_input_details()
        self._output = self._interpreter.get_output_details()
        if len(self._input) != 1 or not self._output:
            raise ValueError("unexpected_tflite_model_signature")
        self.threshold = threshold

    def classify_pcm16(self, audio: bytes, *, sample_rate: int) -> SoundClassification:
        import numpy as np
        digest = hashlib.sha256(audio).hexdigest()
        if sample_rate != 16_000:
            return SoundClassification(digest, self.model_sha256, None, None,
                                       "unavailable", ("resampling_adapter_required",))
        if not audio:
            return SoundClassification(digest, self.model_sha256, None, None,
                                       "unavailable", ("empty_audio",))
        tensor = self._input[0]
        shape = tuple(int(v) for v in tensor["shape"])
        waveform = np.frombuffer(audio, dtype="<i2").astype(np.float32) / 32768.0
        # The model must accept a waveform tensor compatible with this audio chunk.
        expected = int(shape[-1]) if shape else 0
        if expected <= 0 or waveform.size != expected:
            return SoundClassification(digest, self.model_sha256, None, None,
                                       "unavailable", ("audio_chunk_model_shape_mismatch",))
        self._interpreter.set_tensor(tensor["index"], waveform.reshape(shape).astype(
            tensor["dtype"], copy=False))
        self._interpreter.invoke()
        scores = np.asarray(self._interpreter.get_tensor(self._output[0]["index"])).reshape(-1)
        if len(scores) != len(self.labels) or not len(scores):
            return SoundClassification(digest, self.model_sha256, None, None,
                                       "unavailable", ("model_label_dimension_mismatch",))
        index, score = int(np.argmax(scores)), float(np.max(scores))
        if not np.isfinite(score):
            return SoundClassification(digest, self.model_sha256, None, None,
                                       "unavailable", ("non_finite_model_score",))
        if score < self.threshold:
            return SoundClassification(digest, self.model_sha256, None, score,
                                       "partial_coverage", ("no_class_above_threshold",))
        return SoundClassification(digest, self.model_sha256, self.labels[index], score,
                                   "partial_coverage", ("model_calibration_not_verified",))
