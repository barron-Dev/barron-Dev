"""Passive SDR energy detection. No protocol decoding or subscriber identification."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib, json, math
from typing import Any

@dataclass(frozen=True)
class SpectrumPeak:
    center_frequency_hz: int
    peak_frequency_hz: int
    relative_power_db: float
    noise_floor_db: float
    sample_rate_hz: int
    sample_count: int
    observed_at: str
    rf_hash: str
    method: str = "welch_median_energy_v1"
    measurement_unit: str = "dBFS"

def detect_spectrum_peaks(samples: Any, *, center_frequency_hz: int, sample_rate_hz: int,
                          observed_at: datetime | None = None, peak_margin_db: float = 10.0,
                          nperseg: int = 1024) -> list[dict[str, Any]]:
    import numpy as np
    from scipy import signal
    if center_frequency_hz <= 0 or sample_rate_hz <= 0: raise ValueError("frequency and sample rate must be positive")
    if not 0 <= peak_margin_db <= 80: raise ValueError("peak margin must be between 0 and 80 dB")
    iq = np.asarray(samples, dtype=np.complex64)
    if iq.ndim != 1 or iq.size < max(32, nperseg): raise ValueError("IQ buffer is too small or not one-dimensional")
    if not np.isfinite(iq.real).all() or not np.isfinite(iq.imag).all(): raise ValueError("IQ buffer has non-finite samples")
    freqs, psd = signal.welch(iq, fs=sample_rate_hz, nperseg=min(nperseg, iq.size),
                              return_onesided=False, scaling="density")
    freqs, psd = np.fft.fftshift(freqs), np.fft.fftshift(psd)
    positive = psd[psd > 0]
    if not positive.size: return []
    floor = float(np.median(positive))
    floor_db = 10.0 * math.log10(floor)
    psd_db = 10.0 * np.log10(np.maximum(psd, np.finfo(float).tiny))
    peaks, _ = signal.find_peaks(psd_db, height=floor_db + peak_margin_db)
    stamp = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    output = []
    for idx in peaks:
        hz, power = int(round(center_frequency_hz + float(freqs[idx]))), float(psd_db[idx])
        fingerprint = {"center_frequency_hz": center_frequency_hz, "peak_frequency_hz": hz,
                       "relative_power_db": round(power, 3), "noise_floor_db": round(floor_db, 3),
                       "sample_rate_hz": sample_rate_hz, "method": "welch_median_energy_v1"}
        digest = hashlib.sha256(json.dumps(fingerprint, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        output.append(asdict(SpectrumPeak(center_frequency_hz, hz, round(power, 3), round(floor_db, 3),
                                           sample_rate_hz, int(iq.size), stamp, digest)))
    return output

def capture_once(*, center_frequency_hz: int, sample_rate_hz: int = 2_000_000,
                 gain_db: float = 20.0, sample_count: int = 262_144, driver: str = "rtlsdr",
                 peak_margin_db: float = 10.0) -> list[dict[str, Any]]:
    if not 4096 <= sample_count <= 2_000_000: raise ValueError("sample count outside safe bounds")
    if not math.isfinite(gain_db) or not 0 <= gain_db <= 60: raise ValueError("gain outside safe bounds")
    try:
        import numpy as np
        from SoapySDR import Device, SOAPY_SDR_RX, SOAPY_SDR_CF32
    except ImportError as exc: raise RuntimeError("SoapySDR and NumPy must be installed on the edge host") from exc
    device = Device.make({"driver": driver}); stream = None; activated = False
    try:
        device.setSampleRate(SOAPY_SDR_RX, 0, float(sample_rate_hz))
        device.setFrequency(SOAPY_SDR_RX, 0, float(center_frequency_hz))
        device.setGain(SOAPY_SDR_RX, 0, float(gain_db))
        stream = device.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32, [0])
        rc = device.activateStream(stream)
        if rc != 0: raise RuntimeError(f"SDR stream activation failed: {rc}")
        activated = True; buffer = np.empty(sample_count, dtype=np.complex64); offset = 0
        while offset < sample_count:
            result = device.readStream(stream, [buffer[offset:]], sample_count - offset, timeoutUs=1_000_000)
            if result.ret < 0: raise RuntimeError(f"SDR read failed: {result.ret}")
            if result.ret == 0: raise TimeoutError("SDR capture timed out")
            offset += int(result.ret)
        return detect_spectrum_peaks(buffer, center_frequency_hz=center_frequency_hz,
                                     sample_rate_hz=sample_rate_hz, peak_margin_db=peak_margin_db)
    finally:
        if stream is not None:
            if activated:
                try: device.deactivateStream(stream)
                except Exception: pass
            try: device.closeStream(stream)
            except Exception: pass
