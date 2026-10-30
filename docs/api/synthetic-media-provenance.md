# Synthetic-Media Provenance API

Phase 1 exposes C2PA verification through the Cyclothone API. The cryptographic result is deterministic; no AI model may change the provenance state.

## Authentication

- Customer console: Supabase bearer session with tenant membership and `console:read`.
- Developer integration: Cyclothone OAuth access token or API key with `media:provenance:verify`.
- All receipt reads are tenant-filtered. A receipt ID is never sufficient authorization.

## Verify

`POST /api/v1/media/verify-provenance`

Content type: `multipart/form-data`

Field: `file` — original media file. Current default upload limit is 250 MiB.

Response contains:
- `receipt_id`
- `validation_state`: `VALID`, `INVALID`, `UNTRUSTED`, `MISSING_PROVENANCE`, or `INDETERMINATE`
- SHA-256 of the original media and canonical C2PA manifest store
- certificate subject/issuer claim, if present
- active trust policy name and version
- C2PA SDK version
- receipt hash and Ed25519 signature proof
- interpretation limits

The current route processes the verification synchronously. The separate durable worker deployment remains a rollout requirement; do not treat this API slice as deployed until that worker is connected and authenticated end-to-end.

## Receipt history and evidence bundle

- `GET /api/v1/media/receipts`
- `GET /api/v1/media/receipts/{receipt_id}/bundle`

The `.ctprove` file is a ZIP archive containing the signed receipt, canonical signed payload, C2PA report, and extracted manifest store when available.

Independently verify the receipt signature and hashes:

```bash
python scripts/verify_ctprove_bundle.py evidence.ctprove \
  --trusted-public-key cyclothone-provenance-signing-public.pem \
  --media original-media.mp4
```

The public key must be obtained independently from Cyclothone's trusted key-distribution channel. A public key embedded in the bundle alone proves only internal signature consistency, not signer identity.

## State semantics

| State | Meaning |
|---|---|
| `VALID` | CAI SDK reports `Trusted` with configured trust anchors. |
| `UNTRUSTED` | SDK reports valid but not trusted, or trusted state lacks configured anchors. |
| `INVALID` | A recognized signature or hard-binding integrity validation error. |
| `MISSING_PROVENANCE` | Official Reader finds no C2PA manifest. |
| `INDETERMINATE` | Malformed input, unknown validation failure, or insufficient evidence to classify. |

C2PA trust does not establish the identity of a depicted person, the truth of the scene, or that the signer’s claims are factually correct. Missing provenance does not mean media is fake. The current implementation explicitly reports that OCSP/revocation checking is not performed; do not interpret a trust result as a current revocation-status guarantee.
