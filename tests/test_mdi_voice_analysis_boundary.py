from cyclothone.mdi_ingestion.voice_analysis import analyze_consenting_audio

def test_voice_analysis_never_fabricates_score_without_detector():
    result=analyze_consenting_audio(b"consented sample",sample_rate_hz=16000,consent_confirmed=True,detector=None)
    assert result.status=="unavailable" and result.score is None and result.audio_sha256

def test_voice_analysis_requires_consent_before_processing():
    result=analyze_consenting_audio(b"audio",sample_rate_hz=16000,consent_confirmed=False,detector=None)
    assert result.status=="denied_no_consent" and result.audio_sha256 is None
