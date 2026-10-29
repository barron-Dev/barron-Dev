import hashlib
import pytest
from cyclothone.vision.audio_pipeline import process_audio


class FakeTranscriber:
    def __init__(self, text="hello", language="en"):
        self.text, self.language = text, language
    def transcribe(self, audio, sample_rate):
        assert sample_rate == 16000
        return self.text, self.language


class FakeTranslator:
    def translate(self, text, source_language, target_language):
        return "こんにちは"


def test_empty_audio_is_unavailable():
    result = process_audio(b"", sample_rate=16000, target_language="ja", transcriber=None)
    assert result.coverage_status == "unavailable"
    assert "empty_audio" in result.coverage_gaps


def test_missing_runtime_never_fabricates_transcript():
    audio = bytes(320)
    result = process_audio(audio, sample_rate=16000, target_language="ja", transcriber=None)
    assert result.transcript is None
    assert result.source_sha256 == hashlib.sha256(audio).hexdigest()
    assert result.coverage_status == "unavailable"


def test_translation_only_reported_when_adapter_returns_it():
    result = process_audio(bytes(320), sample_rate=16000, target_language="ja",
                           transcriber=FakeTranscriber(), translator=FakeTranslator())
    assert result.transcript == "hello"
    assert result.translated_text == "こんにちは"
    assert result.coverage_status == "complete"


def test_no_speech_is_explicit_partial_coverage():
    result = process_audio(bytes(320), sample_rate=16000, target_language="ja",
                           transcriber=FakeTranscriber(text=""))
    assert result.transcript is None
    assert result.coverage_status == "partial_coverage"


def test_sample_rate_is_not_silently_misrepresented():
    with pytest.raises(ValueError):
        process_audio(bytes(320), sample_rate=8000, target_language="ja",
                      transcriber=FakeTranscriber())
