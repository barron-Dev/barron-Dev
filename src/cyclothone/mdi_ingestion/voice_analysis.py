"""Consent-gated voice-analysis boundary. No fabricated deepfake score or call-control action."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class VoiceAnalysisResult:
    status: str
    audio_sha256: str | None
    model_id: str | None
    score: float | None
    explanation: str

class VoiceDetector(Protocol):
    model_id: str
    def score_audio(self, audio: bytes, sample_rate_hz: int) -> float: ...

def analyze_consenting_audio(audio: bytes, *, sample_rate_hz: int,
                             consent_confirmed: bool, detector: VoiceDetector | None,
                             max_bytes: int=8_000_000) -> VoiceAnalysisResult:
    if not consent_confirmed:
        return VoiceAnalysisResult("denied_no_consent",None,None,None,"Explicit participant consent is required.")
    if not audio or len(audio)>max_bytes or sample_rate_hz not in (8000,16000,22050,24000,44100,48000):
        return VoiceAnalysisResult("invalid_input",None,None,None,"Audio payload or sample rate is invalid.")
    digest=hashlib.sha256(audio).hexdigest()
    if detector is None:
        return VoiceAnalysisResult("unavailable",digest,None,None,"No validated detector is configured; no score was generated.")
    try:
        score=float(detector.score_audio(audio,sample_rate_hz))
    except Exception:
        return VoiceAnalysisResult("error",digest,getattr(detector,"model_id","unknown"),None,"Configured detector failed.")
    if not 0.0<=score<=1.0:
        return VoiceAnalysisResult("invalid_model_output",digest,getattr(detector,"model_id","unknown"),None,"Detector output is outside [0,1].")
    return VoiceAnalysisResult("scored",digest,detector.model_id,score,"Model score is an indicator, not proof; human review is required.")
