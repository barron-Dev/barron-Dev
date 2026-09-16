-- Sentinel Data Trust channel expansion, migration 025.
-- Keep the transfer model medium-agnostic: USB is only one channel among many.

alter table data_trust_transfer_events
    drop constraint if exists data_trust_transfer_events_destination_type_check;

alter table data_trust_transfer_events
    add constraint data_trust_transfer_events_destination_type_check
    check (destination_type = any (array[
        'endpoint','usb','bluetooth','cloud','browser','network','email',
        'messaging','airdrop','nearby_share','wifi_direct','nfc','printer',
        'clipboard','screen_share','api','removable_media','vpn','unknown'
    ]));

alter table data_trust_transfer_events
    drop constraint if exists data_trust_transfer_events_source_type_check;

alter table data_trust_transfer_events
    add constraint data_trust_transfer_events_source_type_check
    check (source_type = any (array[
        'endpoint','browser','cloud','mobile','server','email','messaging',
        'api','network','unknown'
    ]));

create index if not exists idx_data_trust_transfer_destination
    on data_trust_transfer_events(tenant_id, destination_type, observed_at desc);

create index if not exists idx_data_trust_transfer_decision
    on data_trust_transfer_events(tenant_id, decision, observed_at desc);
