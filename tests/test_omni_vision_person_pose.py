import pytest
from cyclothone.vision.person_pose import BoundingBox, LocalYOLOPersonDetector, MediaPipePoseAdapter


def test_yolo_requires_a_real_local_weights_file(tmp_path):
    with pytest.raises(ValueError, match="yolo_weights_must_be_a_local_file"):
        LocalYOLOPersonDetector(str(tmp_path / "missing.pt"))


def test_invalid_yolo_confidence_rejected_before_runtime_load(tmp_path):
    weights = tmp_path / "weights.pt"
    weights.write_bytes(b"not-a-real-model")
    with pytest.raises(ValueError, match="invalid_confidence_threshold"):
        LocalYOLOPersonDetector(str(weights), confidence=0)


def test_pose_box_must_be_inside_frame():
    import numpy as np
    adapter = object.__new__(MediaPipePoseAdapter)
    adapter._cv2 = None
    with pytest.raises(ValueError, match="bounding_box_out_of_frame"):
        adapter.extract(np.zeros((10, 10, 3), dtype=np.uint8),
                        BoundingBox(0, 0, 20, 20, 0.9))
