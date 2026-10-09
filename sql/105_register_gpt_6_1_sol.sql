-- 105_register_gpt_6_1_sol.sql
-- Register GPT-6.1 Sol for every tenant that exists when this migration runs.
-- Registration only: no routes, agents, provider bindings, execution bindings,
-- or ACTIVE lifecycle transitions are created here. Execution remains fail-closed
-- until separate review, account access verification, and end-to-end evidence.

begin;

insert into public.ai_providers (
  id,
  tenant_id,
  provider_key,
  display_name,
  lifecycle_state,
  health_state,
  circuit_state,
  quota,
  cost_meta
)
values (
  'openai',
  null,
  'openai',
  'OpenAI',
  'REGISTERED',
  'UNKNOWN',
  'CLOSED',
  '{"requests_per_minute": null, "tokens_per_minute": null, "notes": "Provider quotas must be confirmed from the OpenAI project before activation."}'::jsonb,
  '{"billing_currency": "USD"}'::jsonb
)
on conflict (id) do nothing;

insert into public.ai_models (
  id,
  tenant_id,
  provider_model_key,
  display_name,
  version,
  lifecycle_state,
  modality,
  cost_meta,
  rate_limit,
  concurrency_limit
)
select
  'openai:gpt-6.1-sol:' || t.id::text,
  t.id,
  'gpt-6.1-sol',
  'GPT-6.1 Sol',
  1,
  'REGISTERED',
  'text',
  jsonb_build_object(
    'billing_currency', 'USD',
    'input_usd_per_million_tokens', 2,
    'cached_input_usd_per_million_tokens', 0.10,
    'output_usd_per_million_tokens', 10,
    'pricing_source', 'OpenAI published standard API pricing; verify before activation'
  ),
  '{"requests_per_minute": null, "tokens_per_minute": null, "notes": "Set limits after confirming the OpenAI project tier."}'::jsonb,
  null
from public.tenants t
on conflict (id) do nothing;

commit;
