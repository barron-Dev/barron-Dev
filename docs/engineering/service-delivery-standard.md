# Cyclothone service delivery standard

This is a mandatory implementation rule for every Cyclothone commercial service and every substantial service capability.

## Frontend is part of the service, not a later phase

When engineering begins work on a service, its relevant frontend must be implemented in the same delivery block as its backend and data-plane work. Do not leave a service as backend-only and defer its user interface to a later project phase.

Choose the surface by the intended operator:
- **Customer workspace:** customer outcomes, request or action entry points, status, coverage, findings, evidence and next steps.
- **Developer workspace:** API integration, credentials/scopes where applicable, request/response contracts, execution state, receipts, errors and operational diagnostics.
- **Kontrol / internal operator surface:** only when the capability requires privileged platform operation; never substitute an internal dashboard for a customer or developer experience.

## Minimum implementation contract

For each service block, deliver together:
1. Backend/API and tenant/role authorization.
2. Persistence, lifecycle and evidence/receipt handling.
3. Worker/provider execution or a clearly identified real infrastructure dependency.
4. Customer and/or developer frontend for the intended operator.
5. Honest lifecycle states: available, running, partial, blocked, unavailable, failed, or complete.
6. Tests for authorization, tenant isolation, failure modes, evidence integrity and frontend build.
7. Authenticated end-to-end proof before claiming the service is production-ready.

A frontend must call real supported APIs for live operations. It must not display fabricated data, synthetic findings, invented provider health, or a success state inferred from a missing response.

## Truthful readiness

- A UI page or API route does not prove that the service is operational.
- A capability may be visible while marked **release-gated**, **partial**, or **unavailable** when dependencies are not ready.
- Missing sources, unavailable providers, empty intelligence, stale coverage or missing attestation must never be presented as a clean result.
- A capability that fails closed must expose the reason and the exact dependency required to unblock it.
- Keep commercial service names and catalogue keys canonical. Do not create new catalogue services for internal modules, models, missions or tools.

## Delivery sequence

Work in coordinated, substantial blocks. Finish backend, persistence, authorization, worker/provider path, evidence, intended frontend and tests together as far as the verified dependencies permit. Open a single coherent PR for the block, keep production migrations and releases behind their required approvals, and report **done / blocked / remaining** with commit and test evidence.
