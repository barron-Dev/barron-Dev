-- Branch-only: private object storage for sanitized DW evidence.
-- This creates no evidence records and does not classify any finding as verified.
BEGIN;

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'dw-evidence-private',
  'dw-evidence-private',
  false,
  512000,
  ARRAY['text/plain']
)
ON CONFLICT (id) DO UPDATE
SET public = false,
    file_size_limit = 512000,
    allowed_mime_types = ARRAY['text/plain'];

-- No anon/authenticated policies are added. Storage access is intended only
-- through the server-side service client. Bucket privacy alone is not a
-- retention policy; lifecycle/retention enforcement must be reviewed separately.

COMMIT;
