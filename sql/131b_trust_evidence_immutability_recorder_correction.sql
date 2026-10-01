-- 131b_trust_evidence_immutability_recorder_correction.sql
-- Evidence is immutable after insertion; duplicate recording is idempotent.
drop function public.trust_record_evidence(uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb);

create function public.trust_record_evidence(
 p_subject_id uuid,p_evidence_type text,p_source_type text,p_source_id text,
 p_content_type text,p_content_uri text,p_content_hash text,p_collected_at timestamptz,
 p_expires_at timestamptz default null,p_signature_algorithm text default null,
 p_signer_key_id text default null,p_signature text default null,p_metadata jsonb default '{}'::jsonb)
returns public.trust_evidence
language plpgsql security definer set search_path=public,pg_catalog as $$
declare s public.trust_subjects;e public.trust_evidence;h text;
begin
 if p_subject_id is null or p_content_hash is null or p_content_hash !~ '^[0-9a-f]{64}$'
 or p_collected_at is null or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb))<>'object'
 then raise exception 'invalid_trust_evidence'; end if;
 select * into s from public.trust_subjects where id=p_subject_id for share;
 if not found then raise exception 'trust_subject_not_found'; end if;
 if s.lifecycle_state in('REVOKED','EXPIRED') then raise exception 'trust_subject_not_evidence_eligible'; end if;
 h:=public.trust_evidence_hash(p_subject_id,p_evidence_type,p_source_type,p_source_id,
 p_content_hash,p_collected_at,p_expires_at,p_signer_key_id);
 insert into public.trust_evidence(
 tenant_id,subject_id,evidence_type,source_type,source_id,content_type,content_uri,
 content_hash,evidence_hash,collected_at,expires_at,signature_algorithm,signer_key_id,signature,metadata)
 values(s.tenant_id,p_subject_id,p_evidence_type,p_source_type,p_source_id,p_content_type,
 p_content_uri,p_content_hash,h,p_collected_at,p_expires_at,p_signature_algorithm,
 p_signer_key_id,p_signature,coalesce(p_metadata,'{}'::jsonb))
 on conflict(subject_id,evidence_hash) do nothing returning * into e;
 if e.id is null then
   select * into e from public.trust_evidence where subject_id=p_subject_id and evidence_hash=h;
 end if;
 return e;
end $$;

revoke all on function public.trust_record_evidence(
 uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb)
from public,anon,authenticated;
grant execute on function public.trust_record_evidence(
 uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb)
to service_role;
