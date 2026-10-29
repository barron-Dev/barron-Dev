# MDI product surface and commercial assumptions

This document describes target product behavior and proposed price hypotheses, not current service entitlements or proven performance.

## Customer workspace
- Tenant-scoped status for RF, telecom-risk, A2P request-integrity and consented voice-analysis sources.
- Every tile distinguishes `healthy`, `partial`, `stale`, `unavailable` and `not_configured`; unavailable sources never imply clean.
- Result details expose signed contract verification state, evidence hashes, signer key ID, source provenance, coverage, timestamp and human-review disposition.
- High-impact actions are recommendations only until a separately authorized, auditable carrier/provider integration exists. No SIM block or call drop is implemented here.

## Developer workspace
- Tenant-authenticated API requests, strict request schemas, replay/freshness bounds, usage accounting and signed result receipts.
- A2P API request authentication is distinct from carrier-origin authentication. SHAKEN/STIR must use carrier/provider-issued identity and certificate workflows, not Cyclothone Ed25519/HMAC contracts.
- Voice API accepts only explicitly consented audio and reports unavailable unless a validated detector/model is provisioned. No <200 ms SLA is claimed until benchmarked on the target runtime and traffic.

## Native edge sensors
- Android cellular information varies by Android version, device OEM, permissions and background-execution restrictions. iOS does not provide equivalent general-purpose cell-scanning APIs to ordinary apps.
- Build platform-specific opt-in collection only after privacy/legal review; minimize identifiers and prefer coarse/hashed measurements. Never upload IMSI/IMEI or record calls silently.
- Desktop Wi-Fi/Bluetooth inventory must use platform permission APIs, local-only processing by default and explicit opt-in before any telemetry leaves the device.

## Pricing hypotheses to validate with customers
| Package | Proposed unit | Initial hypothesis |
|---|---|---:|
| A2P request-integrity | per 1,000 API requests | $5 |
| Consent-based voice analysis | per audio minute | $0.02 |
| Passive RF sensor management | per node/month | $2,500 |
| Enterprise edge sensor | per active device/month | $3 |
| Sovereign carrier deployment | annual license | $1,500,000 |

These figures are not published prices or validated unit economics. Before offering them, measure provider costs, storage/egress, support, regional residency, carrier licensing, hardware and model-inference costs, minimum commitments, and service-level targets.

## Product roadmap gates
1. Contract signing-key custody, key rotation/revocation and independent checkpointing.
2. Live ingestion proof and source freshness/coverage UI.
3. Tenant-scoped APIs and authenticated end-to-end tests.
4. Validated voice model with published evaluation dataset, language coverage, calibration and false-positive/negative rates.
5. Provider/carrier integrations under explicit contracts and legal authorization.
6. Platform-specific native sensor prototypes, consent revocation, battery/privacy tests and app-store policy review.
