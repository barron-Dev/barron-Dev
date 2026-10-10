# Cyclothone change-detection release gate

## Implemented in this code block

- Canonical event taxonomy and the specified weighted score: severity 40%, relevance 25%, source reliability 20%, freshness 15%.
- Tier routing labels: immediate at 7+, scheduled at 4+, otherwise archive.
- Deterministic event IDs, SHA-256 evidence fingerprints, privacy-minimized subject IDs, and URL query/fragment stripping.
- Durable PostgreSQL outbox with idempotent record RPC, publish retry counters, and a 90-day retention boundary.
- Optional Kafka producer using CYCLOTHONE_KAFKA_BOOTSTRAP_SERVERS and CYCLOTHONE_KAFKA_CHANGE_TOPIC.
- Dark Web scheduler emits an event for each collected finding and reports the streaming path as degraded if durable event persistence fails.

## Not yet implemented or proven

- The migration is not applied to production and no production worker has been deployed.
- Kafka is not configured or verified reachable; without it, events remain in the database outbox.
- There is no verified consumer group, Redis Streams deployment, graph-mutation subscriber, Neo4j APOC trigger, or graph recursion/idempotency guard in production.
- Meta, X, Instagram, TikTok, stealer-log, broad forum, and infrastructure-change adapters are not wired by this change. Source catalogue size is not operational source coverage.
- Webhook delivery, Slack/PagerDuty routing, HMAC receiver integration, screenshot capture, and RFC 3161 timestamp authority are not wired by this change.
- Retention cleanup is exposed as a service-role function but is not scheduled; operational scheduling must be configured before claiming enforcement.
- No claim is made that one million sources are supported or running.

## Release order

1. Review the code and migration together.
2. Configure the real Kafka endpoint and any approved provider credentials in the secret store.
3. Apply the migration and deploy the matching worker/API in one controlled release.
4. Run targeted checks and the single consolidated CI/Vercel verification block.
5. Prove a real authorized observation from provider collection through outbox, Kafka, consumer, persisted evidence, graph update, and customer-visible result.
