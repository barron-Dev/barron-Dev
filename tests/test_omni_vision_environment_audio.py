import pytest
from cyclothone.vision.environment_audio import YamnetTFLiteClassifier


def test_missing_model_or_labels_fail_closed(tmp_path):
    with pytest.raises(ValueError, match="real_model_and_labels_files_required"):
        YamnetTFLiteClassifier(str(tmp_path / "missing.tflite"), str(tmp_path / "labels.csv"))
