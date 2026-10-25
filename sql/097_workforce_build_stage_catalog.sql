-- 097_workforce_build_stage_catalog.sql
-- Build-stage workforce catalogue for Kontrol.
-- Safe to run repeatedly. This seeds role/permission/department definitions only:
-- it does NOT create employees, fake identities, tenant memberships, tasks, or sessions.
-- Owner identity binding is intentionally separate and must be bound to the real Supabase auth user.

begin;

insert into workforce.departments (code, name)
values
  ('EXEC', 'Executive & Governance'),
  ('ENG', 'Engineering & Platform'),
  ('SECOPS', 'Security Operations'),
  ('THREAT_INTEL', 'Threat Intelligence & Dark Web'),
  ('AI_RESEARCH', 'AI, Models & Research'),
  ('PRODUCT', 'Product & Experience'),
  ('CUSTOMER', 'Customer Success & Service Delivery'),
  ('PARTNERSHIPS', 'Sales & Strategic Partnerships'),
  ('FINOPS', 'Finance & Operations'),
  ('LEGAL_COMPLIANCE', 'Legal, Risk & Compliance')
on conflict (code) do update
set name = excluded.name, active = true;

insert into workforce.roles (role_key, name, description, system_role)
values
  ('owner', 'Owner', 'Founder-level platform authority across Cyclothone; assigned only through the controlled owner bootstrap.', true),
  ('platform_admin', 'Platform Administrator', 'Platform operations with explicitly granted platform permissions.', true),
  ('engineering_lead', 'Engineering Lead', 'Engineering delivery and approved technical operations.', true),
  ('security_operations', 'Security Operations Analyst', 'Security monitoring, investigation and approved response workflows.', true),
  ('threat_intelligence', 'Threat Intelligence Analyst', 'Threat research and source-verified intelligence workflows.', true),
  ('ai_engineer', 'AI & Model Engineer', 'AI service, model and agent engineering within approved scopes.', true),
  ('product_manager', 'Product Manager', 'Product planning, delivery and customer experience workflows.', true),
  ('customer_success', 'Customer Success', 'Customer service delivery and support workflows.', true),
  ('partnerships_manager', 'Sales & Partnerships', 'Commercial pipeline and partnership workflows.', true),
  ('finance_operations', 'Finance & Operations', 'Internal finance and operational workflows.', true),
  ('legal_compliance', 'Legal & Compliance', 'Compliance, evidence and policy workflows.', true),
  ('employee', 'Employee', 'Baseline internal employee; no privileged platform access by default.', true)
on conflict (role_key) do update
set name = excluded.name,
    description = excluded.description,
    system_role = true,
    active = true;

insert into workforce.permissions (permission_key, name, description, scope_required)
values
  ('kontrol.home.read', 'View Kontrol Home', 'Read the internal Kontrol home and own work summary.', false),
  ('workforce.directory.read', 'Read Workforce Directory', 'Read employee and department directory data.', false),
  ('workforce.directory.manage', 'Manage Workforce Directory', 'Create and update real employee and department records.', false),
  ('workforce.roles.manage', 'Manage Workforce Roles', 'Assign and revoke workforce roles and scopes.', false),
  ('workforce.tasks.read', 'Read Workforce Tasks', 'Read tasks within assigned scope.', true),
  ('workforce.tasks.manage', 'Manage Workforce Tasks', 'Create, assign, update and close tasks within authorized scope.', true),
  ('workforce.projects.read', 'Read Workforce Projects', 'Read projects within assigned scope.', true),
  ('workforce.projects.manage', 'Manage Workforce Projects', 'Manage projects within authorized scope.', true),
  ('workforce.schedule.manage', 'Manage Work Schedules', 'Manage schedules and working hours when backed by the approved scheduling model.', false),
  ('workforce.ai.use', 'Use Internal Work AI', 'Use approved work missions and internal AI sessions.', true),
  ('workforce.ai.manage', 'Manage Internal AI Assignments', 'Assign and revoke internal AI missions within authorized scope.', true),
  ('platform.integrations.read', 'Read Platform Integrations', 'Inspect configured integration status and capability metadata.', false),
  ('platform.integrations.manage', 'Manage Platform Integrations', 'Manage integrations through explicitly approved backend operations.', false),
  ('platform.security.manage', 'Manage Platform Security', 'Manage platform security controls through approved workflows.', false),
  ('platform.audit.read', 'Read Audit Evidence', 'Read audit trails and evidence permitted to the principal.', false),
  ('platform.settings.manage', 'Manage Platform Settings', 'Manage platform settings through approved operations.', false),
  ('platform.ai.providers.manage', 'Manage AI Provider Routing', 'Manage provider routing and model-service configuration through approved operations.', false),
  ('platform.services.manage', 'Manage Cyclothone Services', 'Manage service catalogue and service orchestration through approved operations.', false)
on conflict (permission_key) do update
set name = excluded.name,
    description = excluded.description,
    scope_required = excluded.scope_required,
    active = true;

-- Owner receives every permission present in this canonical catalogue. The role alone
-- grants nothing until an authenticated employee is explicitly assigned to it.
insert into workforce.role_permissions (role_id, permission_id)
select r.id, p.id
from workforce.roles r
cross join workforce.permissions p
where r.role_key = 'owner'
on conflict (role_id, permission_id) do nothing;

-- Staff roles receive only the smallest currently defined useful baseline.
insert into workforce.role_permissions (role_id, permission_id)
select r.id, p.id
from workforce.roles r
join workforce.permissions p
  on p.permission_key in ('kontrol.home.read', 'workforce.tasks.read', 'workforce.ai.use')
where r.role_key = 'employee'
on conflict (role_id, permission_id) do nothing;

insert into workforce.role_permissions (role_id, permission_id)
select r.id, p.id
from workforce.roles r
join workforce.permissions p
  on p.permission_key in (
    'kontrol.home.read',
    'workforce.directory.read',
    'workforce.tasks.read',
    'workforce.tasks.manage',
    'workforce.projects.read',
    'workforce.projects.manage',
    'workforce.ai.use',
    'workforce.ai.manage',
    'platform.audit.read'
  )
where r.role_key = 'engineering_lead'
on conflict (role_id, permission_id) do nothing;

insert into workforce.role_permissions (role_id, permission_id)
select r.id, p.id
from workforce.roles r
join workforce.permissions p
  on p.permission_key in (
    'kontrol.home.read',
    'workforce.tasks.read',
    'workforce.tasks.manage',
    'workforce.projects.read',
    'workforce.ai.use',
    'platform.audit.read'
  )
where r.role_key in ('security_operations', 'threat_intelligence', 'ai_engineer', 'product_manager', 'customer_success', 'partnerships_manager', 'finance_operations', 'legal_compliance')
on conflict (role_id, permission_id) do nothing;

commit;
