-- Training Control production foundation (Supabase PostgreSQL)
-- Apply in a private Supabase project. Never publish a service-role key.
create extension if not exists pgcrypto;
create type public.tc_role as enum ('manager','admin','instructor','pilot');
create type public.tc_status as enum ('pending','approved','rejected');
create table public.profiles (
 id uuid primary key references auth.users(id) on delete restrict,
 full_name text not null check (length(trim(full_name))>=3),
 role public.tc_role not null default 'pilot',
 active boolean not null default true,
 aircraft_types text[] not null default '{}',
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create table public.flight_entries (
 id uuid primary key default gen_random_uuid(),
 pilot_id uuid not null references public.profiles(id),
 flight_date date not null,
 flight_number text not null,
 route text not null,
 aircraft_type text not null,
 capacity text not null check(capacity in ('pic','fo')),
 medical_utc timestamptz not null,
 off_block_utc timestamptz not null,
 takeoff_utc timestamptz not null,
 landing_utc timestamptz not null,
 on_block_utc timestamptz not null,
 debrief_minutes integer not null default 30 check(debrief_minutes>=30),
 international boolean not null default false,
 block_night_minutes integer not null default 0 check(block_night_minutes>=0),
 flight_night_minutes integer not null default 0 check(flight_night_minutes>=0),
 landings integer not null default 1 check(landings>=0),
 night_landings integer not null default 0 check(night_landings>=0 and night_landings<=landings),
 instructor_flight boolean not null default false,
 status public.tc_status not null default 'pending',
 reviewed_by uuid references public.profiles(id),
 reviewed_at timestamptz,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 check(medical_utc<=off_block_utc and off_block_utc<takeoff_utc and takeoff_utc<landing_utc and landing_utc<on_block_utc),
 check(on_block_utc-off_block_utc<=interval '24 hours'),
 check((not international) or debrief_minutes>=40),
 check(block_night_minutes<=extract(epoch from (on_block_utc-off_block_utc))/60),
 check(flight_night_minutes<=extract(epoch from (landing_utc-takeoff_utc))/60),
 check(flight_night_minutes<=block_night_minutes)
);
create table public.flight_crew (
 flight_id uuid not null references public.flight_entries(id) on delete cascade,
 member_order integer not null check(member_order>=1),
 full_name text not null,
 position text not null check(position in ('pic','fo','instructor','engineer','navigator','radio','observer','other')),
 profile_id uuid references public.profiles(id),
 primary key(flight_id,member_order)
);
create table public.training_events (
 id uuid primary key default gen_random_uuid(),
 pilot_id uuid not null references public.profiles(id),
 instructor_id uuid references public.profiles(id),
 kind text not null,
 scheduled_at timestamptz,
 completed_at timestamptz,
 due_at timestamptz,
 status text not null default 'planned' check(status in ('planned','complete','cancelled')),
 notes text,
 created_at timestamptz not null default now()
);
create table public.pilot_documents (
 id uuid primary key default gen_random_uuid(),
 pilot_id uuid not null references public.profiles(id),
 category text not null,
 document_number text,
 issued_on date,
 expires_on date,
 storage_path text not null unique,
 file_name text not null,
 uploaded_by uuid not null references public.profiles(id),
 created_at timestamptz not null default now(),
 check(expires_on is null or issued_on is null or expires_on>=issued_on)
);
create table public.audit_events (
 id bigint generated always as identity primary key,
 actor_id uuid references public.profiles(id),
 action text not null,
 subject_id uuid,
 detail jsonb not null default '{}'::jsonb,
 happened_at timestamptz not null default now()
);
create index on public.flight_entries(pilot_id,flight_date desc);
create index on public.training_events(pilot_id,due_at);
create index on public.pilot_documents(pilot_id,expires_on);

-- Security helpers run with definer privileges, avoiding recursive RLS checks.
create function public.tc_role_of(uid uuid) returns public.tc_role
language sql stable security definer set search_path=public
as $$select role from public.profiles where id=uid and active=true limit 1$$;
create function public.tc_can_manage() returns boolean
language sql stable security definer set search_path=public
as $$select coalesce(public.tc_role_of(auth.uid()) in ('manager','admin'),false)$$;
create function public.tc_is_manager() returns boolean
language sql stable security definer set search_path=public
as $$select coalesce(public.tc_role_of(auth.uid())='manager',false)$$;
create function public.tc_can_read_pilot(uid uuid) returns boolean
language sql stable security definer set search_path=public
as $$select public.tc_can_manage() or (auth.uid()=uid and public.tc_role_of(auth.uid()) is not null) or
exists(select 1 from public.training_events t where t.pilot_id=uid and t.instructor_id=auth.uid() and public.tc_role_of(auth.uid())='instructor')$$;
revoke all on function public.tc_role_of(uuid), public.tc_can_manage(), public.tc_is_manager(), public.tc_can_read_pilot(uuid) from public;
grant execute on function public.tc_role_of(uuid), public.tc_can_manage(), public.tc_is_manager(), public.tc_can_read_pilot(uuid) to authenticated;

alter table public.profiles enable row level security;
alter table public.flight_entries enable row level security;
alter table public.flight_crew enable row level security;
alter table public.training_events enable row level security;
alter table public.pilot_documents enable row level security;
alter table public.audit_events enable row level security;

create policy profiles_read on public.profiles for select to authenticated
using(public.tc_can_manage() or (id=auth.uid() and public.tc_role_of(auth.uid()) is not null));
create policy flights_read on public.flight_entries for select to authenticated
using(public.tc_can_read_pilot(pilot_id));
create policy flights_create on public.flight_entries for insert to authenticated
with check(public.tc_can_read_pilot(pilot_id) and status='pending' and reviewed_by is null);
create policy crew_read on public.flight_crew for select to authenticated
using(exists(select 1 from public.flight_entries f where f.id=flight_id and public.tc_can_read_pilot(f.pilot_id)));
create policy crew_create on public.flight_crew for insert to authenticated
with check(exists(select 1 from public.flight_entries f where f.id=flight_id and f.status='pending' and public.tc_can_read_pilot(f.pilot_id)));
create policy training_read on public.training_events for select to authenticated
using(public.tc_can_read_pilot(pilot_id) or (instructor_id=auth.uid() and public.tc_role_of(auth.uid())='instructor'));
create policy training_write on public.training_events for insert to authenticated
with check(public.tc_can_manage());
create policy training_update on public.training_events for update to authenticated
using(public.tc_can_manage()) with check(public.tc_can_manage());
create policy documents_read on public.pilot_documents for select to authenticated
using(public.tc_can_read_pilot(pilot_id));
create policy documents_insert on public.pilot_documents for insert to authenticated
with check(public.tc_can_manage() and uploaded_by=auth.uid());
create policy audit_read on public.audit_events for select to authenticated
using(public.tc_is_manager());

-- Sensitive mutations are only exposed as server-side RPCs.
create function public.tc_set_user_access(target uuid, new_role public.tc_role, enabled boolean)
returns void language plpgsql security definer set search_path=public as $$
declare old_role public.tc_role;
begin
 if not public.tc_is_manager() then raise exception 'Training Manager only'; end if;
 select role into old_role from public.profiles where id=target for update;
 if old_role is null then raise exception 'User not found'; end if;
 if old_role='manager' then raise exception 'Cannot modify Training Manager'; end if;
 if new_role='manager' then raise exception 'Cannot grant Training Manager'; end if;
 update public.profiles set role=new_role,active=enabled,updated_at=now() where id=target;
 insert into public.audit_events(actor_id,action,subject_id,detail)
 values(auth.uid(),'set_user_access',target,jsonb_build_object('role',new_role,'active',enabled));
end $$;
revoke all on function public.tc_set_user_access(uuid,public.tc_role,boolean) from public;
grant execute on function public.tc_set_user_access(uuid,public.tc_role,boolean) to authenticated;

create function public.tc_review_flight(target uuid, decision public.tc_status)
returns void language plpgsql security definer set search_path=public as $$
declare prior public.tc_status;
begin
 if not public.tc_can_manage() then raise exception 'Not authorized'; end if;
 if decision='pending' then raise exception 'Invalid decision'; end if;
 select status into prior from public.flight_entries where id=target for update;
 if prior is distinct from 'pending' then raise exception 'Flight is not pending'; end if;
 if (select count(*) from public.flight_crew where flight_id=target)<3 then raise exception 'At least 3 crew required'; end if;
 if (select count(*) from public.flight_crew where flight_id=target and position='pic')<>1
 or (select count(*) from public.flight_crew where flight_id=target and position='fo')<1 then raise exception 'PIC and FO required'; end if;
 update public.flight_entries set status=decision,reviewed_by=auth.uid(),reviewed_at=now(),updated_at=now() where id=target;
 insert into public.audit_events(actor_id,action,subject_id,detail) values(auth.uid(),'review_flight',target,jsonb_build_object('decision',decision));
end $$;
revoke all on function public.tc_review_flight(uuid,public.tc_status) from public;
grant execute on function public.tc_review_flight(uuid,public.tc_status) to authenticated;

-- Private storage bucket. Download via authenticated signed URLs and path-based policies.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('pilot-documents','pilot-documents',false,10485760,array['application/pdf','image/jpeg','image/png','image/webp'])
on conflict(id) do nothing;
create policy tc_docs_download on storage.objects for select to authenticated
using(bucket_id='pilot-documents' and exists(
 select 1 from public.pilot_documents d where d.storage_path=name and public.tc_can_read_pilot(d.pilot_id)
));
create policy tc_docs_upload on storage.objects for insert to authenticated
with check(bucket_id='pilot-documents' and public.tc_can_manage());
create policy tc_docs_delete on storage.objects for delete to authenticated
using(bucket_id='pilot-documents' and public.tc_is_manager());

-- First manager bootstrap: create the auth user through the Supabase Auth admin console,
-- then run a one-time insert into profiles with its UUID as manager, using SQL editor.
-- NEVER put a service_role key into web/Android client code.
