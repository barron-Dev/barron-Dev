# Sentinel Desktop Console

Sentinel's first presentation surface is desktop/web console only. Mobile is intentionally deferred to a later client.

## Primary desktop surfaces

- Overview: active incidents, endpoint health, isolation state, Data Trust blocks, deception triggers.
- Data Trust: asset inventory, classification, policy, transfer graph, blocked/reviewed events.
- Deception: deployed artifacts, canary triggers, source/device correlation, response state.
- Investigations: authorized sessions, evidence, provider state, audit timeline.
- Endpoints: device posture, telemetry health, policy enforcement state.
- Audit: immutable security events and operator actions.

## Data Trust interaction model

Every transfer is rendered as `source -> destination -> asset -> decision`. Destination is not hard-coded to removable media; the API vocabulary includes endpoint, removable media, peer transfer, cloud/browser/API, email/messaging, network/VPN, printer, clipboard, screen sharing, and other supported transports.

Unknown transports are visible and handled by policy rather than silently treated as safe.

## Safety boundary

The console can request policy enforcement, isolation, quarantine, investigation, and credential reset workflows on authorized assets. It does not expose device PINs, plaintext secrets, decryption bypasses, or unauthorized remote-control capabilities.
