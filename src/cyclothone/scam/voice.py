from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

VOICE_FEATURES: tuple[str, ...] = (
    *(f"mfcc_{i}_mean" for i in range(1, 9)),
    *(f"mfcc_{i}_std" for i in range(1, 9)),
    "spectral_centroid_mean", "spectral_centroid_std",
    "spectral_rolloff_mean", "spectral_rolloff_std",
    "spectral_flux_mean", "spectral_flux_std",
    "zcr_mean", "zcr_std", "rms_mean", "rms_std",
    "pitch_mean", "pitch_std", "voiced_ratio", "pause_ratio",
    "f0_jitter", "shimmer",
)


@dataclass(frozen=True)
class VoiceVerdict:
    score: float
    verdict: str
    features: dict[str, float]
    reasons: list[str]


class VoiceDeepfakeDetector:
    """Extract deterministic acoustic features from signed PCM input.

    Raw audio is not persisted by this class. A separately trained/versioned
    model can consume ``VOICE_FEATURES``; the heuristic is deliberately exposed
    as a signal source rather than being presented as a trained deepfake model.
    """

    SAMPLE_RATE = 16_000
    FRAME_MS = 25
    HOP_MS = 10
    N_MFCC = 8

    def extract_features(self, pcm_s16le: bytes) -> dict[str, float]:
        samples = np.frombuffer(pcm_s16le, dtype=np.int16).astype(np.float32) / 32768.0
        if samples.size < self.SAMPLE_RATE // 2:
            raise ValueError("audio must contain at least 500 ms of 16 kHz PCM")

        frames = self._frame(samples)
        if len(frames) < 4:
            raise ValueError("audio produced too few analysis frames")

        mfcc = self._mfcc(frames)
        mfcc_mean, mfcc_std = mfcc.mean(axis=0), mfcc.std(axis=0)
        spec = np.abs(np.fft.rfft(frames, axis=1)) + 1e-9
        freqs = np.fft.rfftfreq(frames.shape[1], d=1 / self.SAMPLE_RATE)
        centroid = (spec * freqs).sum(axis=1) / spec.sum(axis=1)
        cumulative = np.cumsum(spec, axis=1)
        threshold = 0.85 * cumulative[:, -1]
        rolloff = freqs[np.argmax(cumulative >= threshold[:, None], axis=1)]
        flux = np.sqrt(np.mean(np.diff(spec, axis=0) ** 2, axis=1))
        zcr = (frames[:, 1:] * frames[:, :-1] < 0).mean(axis=1)
        rms = np.sqrt(np.mean(frames**2, axis=1))
        pitch, jitter = self._pitch(frames)

        f: dict[str, float] = {}
        for i in range(self.N_MFCC):
            f[f"mfcc_{i+1}_mean"] = float(mfcc_mean[i])
            f[f"mfcc_{i+1}_std"] = float(mfcc_std[i])
        f.update({
            "spectral_centroid_mean": float(centroid.mean()),
            "spectral_centroid_std": float(centroid.std()),
            "spectral_rolloff_mean": float(rolloff.mean()),
            "spectral_rolloff_std": float(rolloff.std()),
            "spectral_flux_mean": float(flux.mean()),
            "spectral_flux_std": float(flux.std()),
            "zcr_mean": float(zcr.mean()), "zcr_std": float(zcr.std()),
            "rms_mean": float(rms.mean()), "rms_std": float(rms.std()),
            "pitch_mean": float(pitch.mean()) if pitch.size else 0.0,
            "pitch_std": float(pitch.std()) if pitch.size else 0.0,
            "voiced_ratio": float((pitch > 50).mean()) if pitch.size else 0.0,
            "pause_ratio": float((rms < max(float(rms.mean()) * 0.3, 1e-5)).mean()),
            "f0_jitter": float(jitter),
            "shimmer": float(rms.std() / (rms.mean() + 1e-9)),
        })
        return {name: f.get(name, 0.0) for name in VOICE_FEATURES}

    def heuristic_score(self, features: dict[str, float]) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        if features["f0_jitter"] < 0.005 and features["pitch_mean"] > 80:
            score += 0.20; reasons.append("very low F0 jitter")
        if features["shimmer"] < 0.02:
            score += 0.15; reasons.append("very low amplitude variation")
        if features["pitch_std"] < 8 and features["pitch_mean"] > 80:
            score += 0.20; reasons.append("highly stable pitch")
        if features["voiced_ratio"] > 0.92:
            score += 0.15; reasons.append("high voiced-frame ratio")
        if features["pause_ratio"] < 0.05:
            score += 0.10; reasons.append("very low pause ratio")
        if features["spectral_flux_std"] < 0.5:
            score += 0.10; reasons.append("low spectral variation")
        return min(score, 1.0), reasons

    def analyze(self, pcm_s16le: bytes) -> VoiceVerdict:
        features = self.extract_features(pcm_s16le)
        score, reasons = self.heuristic_score(features)
        verdict = "malicious" if score >= 0.75 else "suspicious" if score >= 0.40 else "safe"
        return VoiceVerdict(score, verdict, features, reasons)

    def _frame(self, samples: np.ndarray) -> np.ndarray:
        frame_len = int(self.SAMPLE_RATE * self.FRAME_MS / 1000)
        hop = int(self.SAMPLE_RATE * self.HOP_MS / 1000)
        n = 1 + (len(samples) - frame_len) // hop
        if n <= 0:
            return np.empty((0, frame_len), dtype=np.float32)
        starts = hop * np.arange(n)[:, None]
        indices = starts + np.arange(frame_len)[None, :]
        return samples[indices] * np.hamming(frame_len)[None, :]

    def _mfcc(self, frames: np.ndarray) -> np.ndarray:
        pre = np.concatenate((frames[:, :1], frames[:, 1:] - 0.97 * frames[:, :-1]), axis=1)
        power = np.abs(np.fft.rfft(pre, axis=1)) ** 2
        mel = np.log(power @ self._mel_filterbank(26, power.shape[1]).T + 1e-9)
        return mel @ self._dct_matrix(26, self.N_MFCC).T

    def _mel_filterbank(self, n_mels: int, n_bins: int) -> np.ndarray:
        def hz2mel(hz: float) -> float: return 2595.0 * math.log10(1.0 + hz / 700.0)
        def mel2hz(mel: np.ndarray) -> np.ndarray: return 700.0 * (10 ** (mel / 2595.0) - 1.0)
        mel_points = np.linspace(hz2mel(80), hz2mel(7600), n_mels + 2)
        hz = mel2hz(mel_points)
        bins = np.floor((n_bins - 1) * hz / self.SAMPLE_RATE).astype(int)
        fb = np.zeros((n_mels, n_bins), dtype=np.float32)
        for m in range(n_mels):
            left, center, right = bins[m:m + 3]
            if center > left:
                fb[m, left:center] = np.arange(center - left) / (center - left)
            if right > center:
                fb[m, center:right] = (right - np.arange(center, right)) / (right - center)
        return fb

    @staticmethod
    def _dct_matrix(n_inputs: int, n_outputs: int) -> np.ndarray:
        n = np.arange(n_inputs)[None, :]
        k = np.arange(n_outputs)[:, None]
        return np.cos(np.pi / n_inputs * (n + 0.5) * k)

    def _pitch(self, frames: np.ndarray) -> tuple[np.ndarray, float]:
        min_lag = self.SAMPLE_RATE // 400
        max_lag = self.SAMPLE_RATE // 50
        pitches: list[float] = []
        periods: list[float] = []
        for frame in frames:
            x = frame - frame.mean()
            corr = np.correlate(x, x, mode="full")[len(x)-1:]
            if corr[0] <= 1e-8:
                pitches.append(0.0); continue
            search = corr[min_lag:min(max_lag + 1, len(corr))]
            lag = min_lag + int(np.argmax(search))
            strength = float(corr[lag] / corr[0])
            if strength < 0.30:
                pitches.append(0.0); continue
            period = float(lag)
            pitches.append(self.SAMPLE_RATE / period)
            periods.append(period)
        p = np.asarray(pitches, dtype=np.float32)
        jitter = float(np.std(np.diff(periods)) / (np.mean(periods) + 1e-9)) if len(periods) > 1 else 0.0
        return p, jitter
