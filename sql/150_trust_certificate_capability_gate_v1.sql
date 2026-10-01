# Trust certificate capability gate

This migration hardens certificate issuance so the authoritative issuance RPC is service-role-only and requires an active, valid TRUST_CERTIFICATE authority key before a certificate can be created.

The certificate issuance path remains evidence/policy/cryptography bound; no authority key or certificate is seeded by this migration.
