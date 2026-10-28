# Omni-Vision Evidence Contract v1

This branch adds a local cryptographic primitive only. It is not yet wired to
Supabase, authenticated APIs, media decoding, a customer UI, or a production
journal.

## Product lanes

Evidence lane: hash exact source bytes before decode/re-encode; separately hash
derived frames and clips; bind event payloads to model/runtime provenance and
hash-chain links. Interpretation lane: an LLM may translate a user query into
validated filters and explain retrieved records. It may not create detections,
authorize actions, or turn a correlation into fact.

## Signed event envelope

The Python module uses canonical UTF-8 JSON, SHA-256 and Ed25519. The digest
covers schema version, key ID, previous event hash, payload digest and payload.
Verification recomputes both digests, checks the expected chain link, then
verifies the signature. The caller owns key storage and rotation.

## Required integration gates

- Authenticate and authorize tenant scope using existing Cyclothone principals.
- Resolve key IDs against the existing trusted public-key directory and enforce
  key status and purpose.
- Persist via an atomic backend/RPC that recomputes hashes and verifies
  signatures; never trust a client-provided verified flag.
- Preserve source-media hash, derived-artifact hashes, model/runtime version,
  camera enrollment, source/edge/server timestamps, custody records and gaps.
- Use externally held checkpoints for privileged rollback/truncation detection.
- Test tampering, replay, truncation, cross-tenant access, revoked keys, clock
  skew, missing media and interrupted offline sync.

A hash proves byte equality against a reference digest. A signature proves that
a trusted key signed covered data. Neither alone proves camera authenticity,
accurate time, a correct model prediction, an unstaged scene, or legal
admissibility.

VISION-CAM, VISION-FILE, VISION-AUDIO, VISION-DOC and VISION-ENV should share
this trust layer but retain typed modality-specific payloads and privacy/
retention rules. Sensitive identity matching and cross-source tracking require
separate legal, privacy, threat-model and human-review gates.
