# Cyclothone source categories and exclusions

## Product rule

Cyclothone maintains separate **dark-web** and **surface-web** source categories.
Classification follows the collection route, not the subject matter. A public
Telegram preview or public paste remains surface web. A reviewed public onion
site accessed through Tor is a dark-web collection route. Do not relabel one
layer as another to inflate coverage.

## Current catalog

| Source ID | Category | Layer | Status | Notes |
| --- | --- | --- | --- | --- |
| `native_onion` | Public onion sites | Dark | Implemented, runtime unverified | Requires reviewed seeds and reachable Tor SOCKS proxy |
| `ransomwatch` | Ransomware leak feed | Dark | Historical only | Must not count as a live check until a live pull is verified |
| `telegram_public` | Public messaging previews | Surface | Implemented | Public previews only; not private groups |
| `pastebin_public` | Public paste sites | Surface | Implemented | Public feed/content only |
| `github_code` | Code repository search | Surface | Planned optional connector | Not required by native onion collection |
| `hibp` | External breach corpus | Surface | Planned optional connector | Not required by native onion collection |

## Exclusions

Reddit is explicitly excluded from the Cyclothone source catalog. No Reddit
connector, polling job, or finding source should be added. Existing source rows
must be audited separately before deletion: deleting a code reference is not
the same as safely removing historical evidence or database records.

## Safe retirement procedure for any discovered legacy Reddit integration

1. Locate every Reddit adapter, import, scheduler entry, source registry row,
   environment variable, and UI category using a full-repository and live-schema audit.
2. Disable new polling first and record the exact affected source IDs.
3. Preserve historical findings and audit trails unless an approved retention
   policy explicitly authorizes deletion.
4. Remove code/configuration in a reviewed migration or PR; do not delete unrelated
   source data or shared infrastructure.
5. Verify that Reddit cannot be registered, polled, or counted in coverage.
6. Confirm surface and dark layers remain separate and all counts reflect real attempts.

This catalog is a taxonomy and guardrail, not proof that every source is wired
through production. Source availability and per-request attempts must be persisted
and shown honestly.
