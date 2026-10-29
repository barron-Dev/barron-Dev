# MDI live ingestion pipes

## Included
- Passive local SDR energy detection using Welch PSD and median noise floor. Welch power spectral density is recorded in dBFS/Hz for normalized IQ samples; it is not calibrated dBm. No protocol decoding, IMSI/IMEI extraction, call interception, or subscriber tracking.
- Public CelesTrak weather-group OMM fetch, source-response SHA-256, and Skyfield/SGP4 orbital position propagation.
- Strict CSV parser for an authoritative, licensed MCC/MNC export. No guessed ITU endpoint and no fabricated registry rows.
- Server-side PostgREST writers targeting the existing MDI RF and satellite tables. Service-role keys are required only in trusted worker environments.

## Activation
Install requirements-mdi-ingestion.txt in the trusted worker. Install SoapySDR and the correct driver from the edge host's supported OS/vendor packages. Configure SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and set CYCLOTHONE_MDI_INGESTION_ENABLED=true only after legal authorization, network controls, and source review. Never put the service key in browser code.

For RF capture, attach an authorized SDR and capture a bounded buffer on a locally permitted frequency. For satellite data, configure an explicit authorized observing location and use the allowlisted public CelesTrak catalog. For telecom registry import, document source, license, retrieval date, and checksum before loading CSV.

## Honest coverage and security
A strong or unregistered RF signal is only an anomaly lead, not proof of a rogue tower or malicious actor. Public orbital elements do not prove a satellite is communicating with or observing a ground target. Missing or stale source data must remain unknown/unavailable, never clean. No automatic dark-web fan-out or interdiction trigger is installed; routing requires an authenticated, tenant-scoped case workflow and human adjudication.

## Migration gate
The migration in this branch is source-only. Live Supabase migration history has 221 entries while main currently has only 24 files in supabase/migrations, and historical SQL exists elsewhere in the repository. Reconcile every live migration to authoritative source/checksum before applying any production DDL. No production migration, merge, or deployment is claimed.
