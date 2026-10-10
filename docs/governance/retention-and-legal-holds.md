# Retention and legal-hold controls — staged implementation

This block adds tenant-scoped retention policy configuration and a legal-hold register, with database-trigger audit events. It deliberately does not run deletion or claim the hold is enforced by every data lifecycle.

## Endpoints
- POST /api/v1/governance/retention-policies — governance:manage
- GET /api/v1/governance/retention-policies — governance:read
- POST /api/v1/governance/legal-holds — governance:manage
- GET /api/v1/governance/legal-holds — governance:read
- POST /api/v1/governance/legal-holds/{id}/release — governance:manage

A retention policy is configuration, not proof of execution. A legal hold is only effective after every deletion/expiry worker checks active holds before acting. Do not enable destructive retention jobs until resource inventories, legal-hold checks, audit outcomes, and recovery procedures pass non-production end-to-end tests.
