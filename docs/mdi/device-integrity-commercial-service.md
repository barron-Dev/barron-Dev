# MDI Device Integrity — commercial service contract

## Product outcome, not a dashboard
MDI Device Integrity produces a deterministic, versioned assessment and evidence receipt. Each result includes a canonical evidence hash, explicit coverage, rule version, observed signals, limitations, and a recommended policy action. The commercial value is the reproducible assessment, signed evidence chain, and policy handoff—not a dashboard.

## Commercial service lines
- **Mobile Threat Defense:** tenant-scoped fleet posture, risk changes, explainable access recommendations, incident evidence. Pricing hypothesis: $5 / active device / month.
- **Executive VIP Shield:** high-assurance review queue, priority evidence collection, policy escalation and audit-ready incident bundle. Pricing hypothesis: $150 / device / month. No 24/7 SOC promise until staffed and contracted.
- **App Integrity API:** deterministic app/build/signature and device-posture checks for customer-owned integrations. Pricing hypothesis: $2 / 1,000 checks; unvalidated.
- **Network Trust Monitor:** TLS validation outcomes, DNS changes and supported platform signals. No guarantee of detecting every evil twin or OS-level blocking without a separately approved and tested network adapter.

## Platform truth
- Android root indicators are heuristic and bypassable; any Play Integrity token must be verified server-side when integrated. Installed-app visibility is restricted by Android package-visibility rules.
- Ordinary iOS apps cannot enumerate all installed apps or inspect arbitrary process trees. Jailbreak checks are heuristic. DeviceCheck/App Attest do not prove absence of all spyware or zero-click compromise.
- Battery drain alone is not treated as spyware evidence.
- No automatic wipe, remote screen lock or network kill switch exists in this source-only implementation. Corporate-data removal requires an enrolled, explicitly authorized management/container capability and audited action path.

## Security architecture
- Cyclothone owns rules, authorization, evidence and enforcement.
- No carrier API, carrier credential, carrier-control action, or external carrier API dependency.
- Client-reported signals are not proof; server-side attestation and contract verification are required before enforcement.
- No untrusted trigger enqueues Dark Web tasks or initiates lockdown.
- If source/platform capability is unavailable, return source_unavailable or partial_coverage, never verified_clean.

## Release gates
Migration is source-only. Before production: reconcile live migration versions/checksums; add authenticated ingestion; verify native Android and iOS adapters; validate attestation server-side; test tenant isolation/replay protection; append signed journal contracts; execute authenticated E2E. No zero-click detection claim until independently validated telemetry exists.
