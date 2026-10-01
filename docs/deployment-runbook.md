# Sentinel Production Deployment Runbook

This is the authoritative deployment path for the current Sentinel repository. It intentionally does **not** collapse historical SQL migrations into a destructive mega-migration. The repository's migrations remain the source of schema history; a fresh environment must apply them in repository order after dependency review.

## 1. Deployment topology

- **Application:** FastAPI application exported as `sentinel.api.app:app`.
- **Database/control plane:** Supabase PostgreSQL.
- **Edge/serverless:** Vercel may front API routes; do not put long-running workers in Vercel Functions.
- **Endpoint:** Windows Sentinel agent in `agent/`.
- **Container:** `Dockerfile` + `deploy/docker-compose.yml` provide the self-hosted API runtime.
- **Schedulers:** the application currently starts several in-process schedulers. These are suitable only for a persistent process. Before a Vercel-only deployment, scheduled work must be moved to an external scheduler/cron execution path rather than relying on FastAPI lifespan persistence.

## 2. Source of truth

Repository: `barron-Dev/barron-Dev`, branch `main`.

Runtime entrypoint:

```text
uvicorn sentinel.api.app:app --host 0.0.0.0 --port 8000
```

The application currently mounts the API under `/api/v1` and exposes an unauthenticated liveness endpoint at `/health`.

## 3. Prerequisites

- Python 3.11+
- Docker Engine + Docker Compose v2 for container deployment
- Supabase project with the required database credentials
- GitHub Actions enabled for CI
- A secret-management system for production secrets
- A persistent execution environment if in-process schedulers are enabled

Never place Supabase `service_role` credentials, signing keys, provider credentials, or federation secrets in the repository or a client-side environment variable.

## 4. Fresh database procedure

1. Back up the target database according to the organization's Supabase backup policy.
2. Inspect every file under `sql/` and establish the dependency order from the SQL itself. Do not assume numeric filenames alone prove dependencies.
3. Apply migrations sequentially to a disposable/staging project first.
4. Verify required tables, indexes, functions/RPC signatures, RLS policies, and grants.
5. Run the repository test suite against staging.
6. Only then apply the identical migration set to production.

The current repository contains numbered migrations beginning with the core control-plane migrations and continuing through the later intelligence, federation, and physical-digital work. Later hardening migrations must not be skipped simply because an earlier migration appears to provide the same feature.

## 5. Application build

```bash
python -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-server.txt
pip install -e .
pytest
```

For the production image:

```bash
docker build -t sentinel-platform:local .
docker run --rm --env-file deploy/.env sentinel-platform:local
```

The container runs as a non-root user and drops Linux capabilities. Keep the filesystem read-only where the application permits it.

## 6. Compose deployment

Create `deploy/.env` outside source control and populate it from the production secret store.

```bash
cd deploy
docker compose config
cd ..
docker compose -f deploy/docker-compose.yml up -d --build
```

Verify:

```bash
curl -fsS http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

Then inspect application logs and confirm database connectivity through an authenticated control-plane operation. A green liveness check alone is not a database readiness check.

## 7. CI/CD gate

The repository currently has Python test and Windows agent workflows under `.github/workflows/`. Production deployment must be gated on:

1. dependency installation;
2. Python tests;
3. agent build/tests where applicable;
4. migration validation against staging;
5. image build;
6. health check after deployment;
7. rollback readiness.

Never promote a build merely because it compiles.

## 8. Secrets map

The exact environment-variable names are defined by the implementation and must be collected from the repository before provisioning. Build the production secret inventory from code/configuration rather than inventing names.

Classify every secret as:

| Class | Examples | Exposure |
|---|---|---|
| Database | Supabase URL/service credentials | Server only |
| Authentication | JWT/signing/session secrets | Server only |
| Federation | `SENTINEL_FED_SALT`, TAXII credentials | Server only |
| Provider | Intel/response/vendor credentials | Server only |
| Endpoint | Enrollment/signing material | Agent/server controlled |
| Cryptographic | KMS/Vault references and keys | Dedicated secret/KMS system |

Secrets must never be returned in API metadata, logs, error messages, telemetry, or case evidence unless explicitly designed for that purpose.

## 9. Tenant and security verification

Before accepting a pilot tenant, verify:

- authenticated routes reject unauthenticated requests;
- tenant IDs are derived from authenticated identity, not request-controlled ownership fields;
- service-role database paths are unreachable from public clients;
- RLS is enabled on exposed tenant data;
- UPDATE operations have both ownership and `WITH CHECK` protection where applicable;
- federation and physical ingestion cannot cross tenant boundaries;
- no fake device/event identifiers are used to create detections;
- detection promotion flows through the canonical Detection -> AutoCase -> Response architecture;
- raw credentials/cookies/passwords are not retained by intelligence collectors;
- external HTTP integrations enforce HTTPS, credential isolation, timeouts, response limits, and SSRF protections.

## 10. Pilot cutover

For the first customer, enable only the agreed V1 capabilities. Keep non-pilot modules disabled by configuration or access policy rather than deleting their code.

Recommended operational sequence:

```text
Tenant provisioned
  -> endpoints enrolled
  -> telemetry verified
  -> detection rules enabled
  -> controlled response actions enabled
  -> recovery tested
  -> SOC onboarding
  -> production monitoring
```

Record baseline metrics before enabling automated response: telemetry coverage, detection latency, response latency, API availability, agent health, and false-positive rate.

## 11. Rollback

Application rollback:

1. stop promotion;
2. redeploy the last known-good application image/commit;
3. verify `/health`;
4. verify authenticated read/write control-plane operations;
5. review audit logs;
6. leave database schema unchanged unless a schema rollback has been explicitly tested.

Database rollback is migration-specific. Do **not** run ad-hoc destructive SQL in production. If a migration is irreversible, restore from the tested backup/point-in-time recovery procedure or apply a forward corrective migration.

## 12. Incident recovery

Preserve audit records and evidence needed for investigation. Rotate compromised credentials through the secret provider, invalidate affected sessions/tokens where applicable, isolate affected endpoints through the existing response path, and verify tenant boundaries after recovery.

## 13. Definition of deployable V1

A V1 is considered deployable only when all of the following are true:

- fresh staging environment can be provisioned from repository state;
- database migration order is reproducible;
- API starts from the documented entrypoint;
- container health check succeeds;
- CI is green;
- secrets are provisioned outside Git;
- authenticated tenant isolation is verified;
- endpoint enrollment and telemetry are verified;
- Detection -> AutoCase -> Response is exercised with real identifiers;
- backup and rollback procedures have been exercised;
- pilot onboarding can be performed by someone other than the original developer.

This document is a living operational artifact. Changes to runtime entrypoints, migration order, secrets, schedulers, deployment targets, or security boundaries must update this runbook in the same change set.
