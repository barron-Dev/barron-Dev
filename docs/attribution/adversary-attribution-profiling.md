# Cyclothone DW — Adversary Attribution & Threat Actor Profiling

## Implemented on the feature branch

- Deterministic probabilistic attribution engine with seven weighted signals: infrastructure 0.25, ATT&CK/TTP 0.20, malware 0.15, behavioural 0.15, victimology 0.10, identity markers 0.10, temporal 0.05.
- Diamond Model output always contains adversary, capability, infrastructure, and victim vertices; unknown vertices are explicit.
- ATT&CK technique-ID syntax validation, observed-action to Cyber Kill Chain phase mapping, and technique overlap scoring across campaigns.
- Four confidence tiers with per-signal explanations. CONFIRMED/SUSPECTED require at least two signal families, two independent source identifiers, and infrastructure or identity overlap; every assessment remains analyst-review-required.
- Privacy-minimized behavioural summaries: UTC activity histograms, vocabulary richness and average sentence length, infrastructure/registrar/tool preferences and operational descriptors. Raw messages, typo signatures, biometric traits and inferred real-world identity are not stored by this helper.
- Server-side persistence orchestrator that compares a complete activity cluster with existing profiles, enriches profiles for suspected/high-confidence associations, and creates a provisional activity-cluster profile when no known profile reaches POSSIBLE. It never invents a named actor.
- PostgreSQL tables for actor profiles, attribution assessments, actor relationships and evidence records, with RLS enabled and direct anon/authenticated access revoked.

## Confidence and evidence controls

The score follows the specified weighted composite. Missing signals score zero; they are not imputed. The engine preserves both the raw-score tier and the guarded tier, records per-signal scores and reasons, and keeps analyst review required. CONFIRMED is a review queue tier, not an automatic public assertion. Behavioural similarities and temporal correlations are weak, spoofable evidence and must not be used to identify a private person.

## Important release boundary

This commit adds code and an unapplied migration only. It does not change production. It does not claim that Neo4j/APOC triggers, a GNN, Leiden community detection, Censys, VoidAccess, Flare, Recorded Future/Mandiant, EUREKHA, external forum tools, or any other third-party integration is installed or authorized. ATT&CK IDs are syntax-checked here; a current MITRE ATT&CK catalogue lookup is still needed to validate technique existence and metadata. The current streaming finding shape does not reliably supply a complete cross-source activity cluster, so assess_activity_cluster must be called by the authorized cluster assembler/worker; it is not invoked for every individual finding. No CI, Vercel build, deployment, migration, or secret/infrastructure change was run or requested.

## Remaining before production claim

1. Wire the cluster assembler to call assess_activity_cluster with stable cluster IDs, independent source provenance, preserved evidence IDs and all four Diamond vertices.
2. Add an authenticated analyst review/override API and customer-safe read API with tenant authorization; never expose global profiles or raw evidence directly to browsers.
3. Add source-of-truth graph integration (Neo4j or PostgreSQL graph tables), idempotent graph updates, relationship reconciliation and tested cycle/recursion prevention.
4. Add ATT&CK catalogue sync, CAPEC relationships and validated technique/community clustering; implement Leiden only when the graph data and runtime dependency are actually present.
5. Implement durable alert routing for new provisional clusters and material profile changes, with signed outbound webhooks and event-time evidence preservation.
6. Apply the migration through the approved release process, then run one consolidated CI/runtime/E2E verification block. None of those production steps is claimed complete.
