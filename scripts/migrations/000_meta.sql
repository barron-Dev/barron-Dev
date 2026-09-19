create table if not exists schema_migrations (
    version         text primary key,
    name            text not null,
    checksum        text not null,
    applied_at      timestamptz not null default now(),
    applied_by      text,
    duration_ms     integer,
    status          text not null default 'success'
                    check (status in ('success','failed','rolled_back')),
    error           text
);

create index if not exists idx_schema_migrations_applied
    on schema_migrations(applied_at desc);
