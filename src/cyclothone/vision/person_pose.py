"""Optional local person detection and anonymous pose landmarks.

Weights must be provisioned as local files. The adapter does not download models,
persist face crops, identify people, or derive gait/identity templates. Pose outputs are
geometric observations only and must be tied to the source frame's evidence manifest.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import math


@dataclass(frozen=True, slots=True)
class BoundingBox:
    x1: int
    y1: int
    x2: int
    y2: int
    confidence: float


@dataclass(frozen=True, slots=True)
class PoseLandmark:
    x: float
    y: float
    z: float
    visibility: float


@dataclass(frozen=True, slots=True)
class PoseObservation:
    box: BoundingBox
    landmarks: tuple[PoseLandmark, ...]
    coverage_status: str
    coverage_gaps: tuple[str, ...]


class LocalYOLOPersonDetector:
    """Load locally provisioned YOLO weights and return only person bounding boxes."""
    def __init__(self, weights_path: str, *, confidence: float = 0.5, device: str = "cpu"):
        path = Path(weights_path).expanduser()
        if not path.is_file():
            raise ValueError("yolo_weights_must_be_a_local_file")
        if not 0 < confidence <= 1:
            raise ValueError("invalid_confidence_threshold")
        if device != "cpu" and not device.startswith("cuda"):
            raise ValueError("unsupported_device")
        try:
            from ultralytics import YOLO
        except ImportError as exc:
            raise RuntimeError("ultralytics_optional_dependency_required") from exc
        self._model = YOLO(str(path))
        self._confidence = confidence
        self._device = device

    def detect(self, frame):
        """Return boxes from a real BGR frame; invalid or empty frames fail closed."""
        import numpy as np
        if not isinstance(frame, np.ndarray) or frame.ndim != 3 or frame.shape[2] != 3:
            raise ValueError("frame_must_be_bgr_image")
        if frame.size == 0:
            raise ValueError("frame_must_not_be_empty")
        result = self._model.predict(source=frame, conf=self._confidence, device=self._device,
                                     verbose=False)[0]
        boxes = []
        if result.boxes is None:
            return tuple()
        height, width = frame.shape[:2]
        for item in result.boxes:
            cls = int(item.cls.item())
            # COCO person class index; non-COCO/custom label maps must not be assumed.
            if cls != 0:
                continue
            x1, y1, x2, y2 = (float(v) for v in item.xyxy[0].tolist())
            score = float(item.conf.item())
            if not all(math.isfinite(v) for v in (x1, y1, x2, y2, score)):
                continue
            left, top = max(0, int(x1)), max(0, int(y1))
            right, bottom = min(width, int(x2)), min(height, int(y2))
            if right <= left or bottom <= top:
                continue
            boxes.append(BoundingBox(left, top, right, bottom, score))
        return tuple(boxes)


class MediaPipePoseAdapter:
    """Extract transient geometric pose landmarks for one detected person crop."""
    def __init__(self, *, min_detection_confidence: float = 0.7,
                 min_tracking_confidence: float = 0.7, model_complexity: int = 1):
        if not 0 < min_detection_confidence <= 1 or not 0 < min_tracking_confidence <= 1:
            raise ValueError("invalid_pose_confidence")
        if model_complexity not in {0, 1, 2}:
            raise ValueError("invalid_model_complexity")
        try:
            import mediapipe as mp
        except ImportError as exc:
            raise RuntimeError("mediapipe_optional_dependency_required") from exc
        self._cv2 = __import__("cv2")
        self._pose = mp.solutions.pose.Pose(
            static_image_mode=False, model_complexity=model_complexity,
            min_detection_confidence=min_detection_confidence,
            min_tracking_confidence=min_tracking_confidence,
        )

    def extract(self, frame, box: BoundingBox) -> PoseObservation:
        import numpy as np
        if not isinstance(frame, np.ndarray) or frame.ndim != 3 or frame.shape[2] != 3:
            raise ValueError("frame_must_be_bgr_image")
        h, w = frame.shape[:2]
        if not (0 <= box.x1 < box.x2 <= w and 0 <= box.y1 < box.y2 <= h):
            raise ValueError("bounding_box_out_of_frame")
        crop = frame[box.y1:box.y2, box.x1:box.x2]
        if crop.size == 0:
            raise ValueError("empty_person_crop")
        rgb = self._cv2.cvtColor(crop, self._cv2.COLOR_BGR2RGB)
        result = self._pose.process(rgb)
        if not result.pose_landmarks:
            return PoseObservation(box, tuple(), "partial_coverage", ("pose_not_detected",))
        landmarks = tuple(PoseLandmark(float(p.x), float(p.y), float(p.z),
                                       float(p.visibility))
                          for p in result.pose_landmarks.landmark)
        if any(not all(math.isfinite(v) for v in (p.x, p.y, p.z, p.visibility))
               for p in landmarks):
            return PoseObservation(box, tuple(), "unavailable", ("non_finite_pose_landmark",))
        # Deliberately do not generate gait hashes, identity labels, or face-based matches.
        return PoseObservation(box, landmarks, "partial_coverage",
                               ("pose_not_calibrated_for_identity_or_metric_measurement",))

    def close(self):
        self._pose.close()
