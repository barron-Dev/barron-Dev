# MDI signed result contracts and defensive API boundaries

## Implemented source

- `contracts.py` creates deterministic canonical JSON, SHA-256 evidence and contract hashes, and Ed25519 signatures. Verification detects payload alteration.
- `mdi_journal_events` is an append-only, tenant-scoped journal source migration. A service-role-only RPC locks per tenant and rejects stale journal heads; mutation triggers reject UPDATE/DELETE.
- `a2p_verifier.py` authenticates a tenant API request using HMAC, strict E.164 fields, request timestamp bounds and payload-size limits. This is API-client integrity only. It is **not** carrier-origin authentication, SMS delivery, SHAKEN/STIR signing, or a routing API.
- `voice_analysis.py` is a consent-gated interface. It reports unavailable when no validated model is configured; it never manufactures a deepfake score. Any returned model score is a review indicator, not proof or an automatic call-disconnect command.

## Release and trust boundaries

- The SQL RPC does not itself verify Ed25519 signatures. A verifier must resolve the trusted public key by `signer_key_id` and independently verify the signed canonical payload before treating a contract as verified.
- Signing-key provisioning, rotation/revocation, durable key custody (KMS/HSM), external checkpointing, and independent journal verification are not yet integrated.
- A DB append-only trigger is tamper-resistance within normal DB permissions, not absolute immutability against database owners/superusers. For stronger assurance, export signed checkpoints to independently controlled storage.
- No live call interception, subscriber identity correlation, SIM blocking, carrier routing, or telecom-core configuration changes are implemented.
- Native OS APIs do not expose unrestricted cellular telemetry uniformly. Any future edge sensor must respect platform permissions, user consent, data minimization and per-tenant authorization. Do not infer IMSI-catcher identity from a signal-strength spike or 2G downgrade alone.
- No production migration is applied here. MDI live migration history must be reconciled before DDL promotion.
