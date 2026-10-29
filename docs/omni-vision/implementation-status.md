# Omni-Vision implementation status

This branch adds local processing contracts and optional adapters. It does not by itself
make Omni-Vision production-operational.

## Implemented in this block
- Audio bytes are hashed as received. A pluggable local transcription/translation pipeline
  reports explicit coverage gaps and refuses implicit sample-rate conversion.
- Optional faster-whisper and Marian adapters require local model directories and disable
  remote model resolution.
- Anonymous constant-velocity trajectory forecasts and polygon zone checks are
  deterministic; predictions remain uncertain and require human review.
- Optional environmental audio classification requires a real TFLite model and labels,
  hashes the model artifact, and reports unavailable/partial coverage honestly.
- nftables default-deny forwarding policy template for an isolated camera VLAN.

## Explicitly not claimed
- No face recognition, gait identification, voiceprint matching, or identity “demasking”.
  These are not implemented; anonymous safety-zone monitoring does not require them.
- A SHA-256 media digest is not proof of sensor authenticity, freshness, or truth. Trusted
  capture needs signed provenance, trusted time, nonce/replay controls, and key custody.
- RTSP/RTSPS alone does not guarantee client-certificate mTLS. Use a mutually authenticated
  edge gateway/tunnel where camera firmware cannot provide it.
- Monocular depth does not provide exact metric coordinates without calibration and scene
  constraints.
- Forecasts and sound classifications do not autonomously lock doors or dispatch police.
  Physical actions require separately authenticated, policy-bound, audited approval.
- No model is downloaded or silently selected. Provision approved, pinned artifacts first.

## Deployment gates
1. Verify artifact hashes/signatures and licenses for all model and label files.
2. Install optional runtime dependencies in a dedicated edge image; pin versions and emit
   an SBOM. Do not inflate the API's base image with CUDA/Torch by default.
3. Calibrate sample rate, sensor clocks, camera geometry, thresholds and uncertainty on
   real site data.
4. Bind results to tenant authorization, trusted key directory and durable atomic storage.
5. Run hardware-in-loop tests on the actual cameras, microphones, edge host and VLAN.
6. Test false positives, missing sources, model mismatch, clock skew, replay, disconnect,
   resource exhaustion and cross-tenant isolation.
7. Keep this draft PR open until CI and end-to-end deployment gates pass.
