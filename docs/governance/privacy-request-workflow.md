# Privacy governance workflow — staged implementation

## Implemented in this branch
- Tenant-scoped privacy-request intake, listing, and controlled state transitions.
- Separate privacy:read and privacy:manage scopes.
- Non-reversible subject_ref requirement to avoid placing raw identifiers in the request register.
- Transactional database-trigger audit events for insert/update, with before/after state limited to workflow metadata.
- Terminal states require a resolution summary; invalid transitions are rejected.

## Deliberate boundaries
- This is workflow tracking, not automated fulfilment of access/erasure/portability requests and not a legal-compliance certification.
- The route uses the existing privileged Supabase server client, so tenant filters and scope checks are mandatory. The migration adds no broad client-facing RLS policies.
- Do not give API credentials the new scopes until the authorization matrix has been reviewed.
- Audit rows have no update/delete route, but a database owner can still alter them; immutability is not cryptographically guaranteed.
- No retention deletion worker, legal-hold enforcement, PIA assessment engine, or production migration is included in this block.
- Apply only through the approved migration process; validate in non-production first.

## API
- POST /api/v1/governance/privacy-requests — privacy:manage
- GET /api/v1/governance/privacy-requests — privacy:read
- POST /api/v1/governance/privacy-requests/{id}/transition — privacy:manage

Before release, test cross-tenant isolation, scope denial, database trigger audit atomicity, duplicate submissions, and every allowed/denied transition against a disposable non-production database.
