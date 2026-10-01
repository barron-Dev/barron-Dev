# Cyclothone Enterprise Bridge

Java enterprise integration boundary for banks, MSSPs and regulated environments.

This module is intentionally a contract-first foundation. It is not deployed by the Python Railway service and it does not contain production credentials.

## Security boundary
- gRPC transport must use mutual TLS in deployment.
- Every request is tenant-scoped and authenticated by the surrounding gateway.
- Tenant IDs supplied by clients are authorization inputs, never proof of authorization.
- HSM operations are abstracted behind an interface; SoftHSM is suitable only for development/test, not a production banking key store.
- Indicator batches are bounded and validated before ingestion.
