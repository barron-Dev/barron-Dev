"""Local-first speech transcription/translation contracts.

Optional heavyweight runtimes load only when explicitly configured. Missing models or
empty audio return explicit unavailable coverage. This module does not create voiceprints
or identify speakers.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
import hashlib


@dataclass(frozen=True, slots=True)
class AudioResult:
    source_sha256: str
    transcript: str | None
    translated_text: str | None
    detected_language: str | None
    target_language: str
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    model_id: str | None


class Transcriber(Protocol):
    def transcribe(self, audio: bytes, sample_rate: int) -> tuple[str, str | None]: ...


class Translator(Protocol):
    def translate(self, text: str, source_language: str, target_language: str) -> str: ...


def process_audio(audio: bytes, *, sample_rate: int, target_language: str,
                  transcriber: Transcriber | None, translator: Translator | None = None,
                  model_id: str | None = None) -> AudioResult:
    """Process real PCM16 mono bytes with caller-supplied local runtimes."""
    if not isinstance(audio, bytes):
        raise TypeError("audio_must_be_bytes")
    if not 8_000 <= sample_rate <= 192_000:
        raise ValueError("unsupported_sample_rate")
    if not target_language or len(target_language) > 16:
        raise ValueError("invalid_target_language")
    if len(audio) % 2:
        raise ValueError("pcm16_audio_length_must_be_even")
    digest = hashlib.sha256(audio).hexdigest()
    if not audio:
        return AudioResult(digest, None, None, None, target_language, "unavailable",
                           ("empty_audio",), model_id)
    if transcriber is None:
        return AudioResult(digest, None, None, None, target_language, "unavailable",
                           ("transcriber_not_configured",), model_id)
    if sample_rate != 16_000:
        return AudioResult(digest, None, None, None, target_language, "unavailable",
                           ("audio_resampling_adapter_required",), model_id)
    text, language = transcriber.transcribe(audio, sample_rate)
    text = text.strip() if isinstance(text, str) else ""
    if not text:
        return AudioResult(digest, None, None, language, target_language,
                           "partial_coverage", ("no_speech_transcript",), model_id)
    translated = text if language == target_language else None
    gaps: list[str] = []
    if language != target_language:
        if translator is None:
            gaps.append("translator_not_configured")
        else:
            candidate = translator.translate(text, language or "und", target_language)
            if not isinstance(candidate, str) or not candidate.strip():
                gaps.append("translation_empty")
            else:
                translated = candidate.strip()
    return AudioResult(digest, text, translated, language, target_language,
                       "partial_coverage" if gaps else "complete", tuple(gaps), model_id)


class FasterWhisperAdapter:
    """Lazy faster-whisper adapter; model artifacts must already exist locally."""
    def __init__(self, model_path: str, *, device: str = "cpu",
                 compute_type: str = "int8", cpu_threads: int = 4):
        from pathlib import Path
        path = Path(model_path).expanduser()
        if not path.is_dir():
            raise ValueError("faster_whisper_model_path_must_be_local_directory")
        if device not in {"cpu", "cuda"}:
            raise ValueError("unsupported_device")
        if compute_type not in {"int8", "int8_float16", "float16", "float32"}:
            raise ValueError("unsupported_compute_type")
        from faster_whisper import WhisperModel
        self._model = WhisperModel(str(path), device=device, compute_type=compute_type,
                                   cpu_threads=max(1, min(cpu_threads, 64)),
                                   local_files_only=True)

    def transcribe(self, audio: bytes, sample_rate: int) -> tuple[str, str | None]:
        import numpy as np
        if sample_rate != 16_000:
            raise ValueError("faster_whisper_adapter_requires_16khz_pcm")
        samples = np.frombuffer(audio, dtype="<i2").astype(np.float32) / 32768.0
        segments, info = self._model.transcribe(samples, beam_size=5, vad_filter=True)
        return " ".join(s.text.strip() for s in segments).strip(), info.language


class MarianLocalTranslator:
    """Lazy local Marian adapter; it never resolves model files from the network."""
    def __init__(self, model_path: str, *, device: str = "cpu"):
        from pathlib import Path
        path = Path(model_path).expanduser()
        if not path.is_dir():
            raise ValueError("translation_model_path_must_be_local_directory")
        if device not in {"cpu", "cuda"}:
            raise ValueError("unsupported_device")
        import torch
        from transformers import MarianMTModel, MarianTokenizer
        self._torch, self._device = torch, device
        self._tokenizer = MarianTokenizer.from_pretrained(str(path), local_files_only=True)
        self._model = MarianMTModel.from_pretrained(str(path), local_files_only=True).to(device)
        self._model.eval()

    def translate(self, text: str, source_language: str, target_language: str) -> str:
        if not text.strip():
            return ""
        with self._torch.inference_mode():
            tokens = self._tokenizer([text], return_tensors="pt", truncation=True,
                                     max_length=512).to(self._device)
            output = self._model.generate(**tokens, num_beams=4, do_sample=False,
                                           max_new_tokens=512)
            return self._tokenizer.batch_decode(output, skip_special_tokens=True)[0]
