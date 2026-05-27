-- BDC Flash Drill — Supabase Schema v1
-- Run in: Supabase Dashboard → SQL Editor → New Query → paste → Run

-- ============================================================
-- DEV RESET — uncomment if you need to wipe and recreate
-- ============================================================
-- drop table if exists answers cascade;
-- drop table if exists drill_sessions cascade;
-- drop table if exists rep_progress cascade;
-- drop table if exists reps cascade;
-- drop function if exists create_rep(text, text, text);
-- drop function if exists verify_pin(text, text);
-- drop function if exists get_rep(uuid);

-- ============================================================
-- Extensions
-- Supabase pre-installs pgcrypto in the `extensions` schema, so we
-- reference its functions as `extensions.crypt(...)` / `extensions.gen_salt(...)`
-- in the RPCs below (our function search_path is locked to `public`).
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

-- ============================================================
-- reps — identity table. Email + 4-digit PIN auth.
-- ============================================================
create table reps (
  id            uuid primary key default gen_random_uuid(),
  email         text not null unique,
  name          text not null,
  pin_hash      text not null,
  is_admin      boolean not null default false,
  created_at    timestamptz not null default now(),
  last_drill_at timestamptz
);

-- ============================================================
-- rep_progress — per-rep, per-question Leitner state.
-- Direct replacement for the localStorage `bdc_drill_state` object.
-- ============================================================
create table rep_progress (
  rep_id        uuid not null references reps(id) on delete cascade,
  question_id   text not null,
  bucket        smallint not null default 1 check (bucket between 1 and 5),
  last_seen     timestamptz,
  correct_count integer not null default 0,
  wrong_count   integer not null default 0,
  primary key (rep_id, question_id)
);

create index rep_progress_rep_idx on rep_progress(rep_id);

-- ============================================================
-- drill_sessions — one row per drill attempt.
-- ============================================================
create table drill_sessions (
  id            uuid primary key default gen_random_uuid(),
  rep_id        uuid not null references reps(id) on delete cascade,
  started_at    timestamptz not null default now(),
  ended_at      timestamptz,
  correct_count integer not null default 0,
  wrong_count   integer not null default 0
);

create index drill_sessions_rep_idx     on drill_sessions(rep_id);
create index drill_sessions_started_idx on drill_sessions(started_at desc);

-- ============================================================
-- answers — granular log of every question response.
-- Powers the admin dashboard.
-- ============================================================
create table answers (
  id                uuid primary key default gen_random_uuid(),
  rep_id            uuid not null references reps(id) on delete cascade,
  session_id        uuid references drill_sessions(id) on delete set null,
  question_id       text not null,
  question_type     text not null,
  question_category text,
  was_correct       boolean not null,
  typed_text        text,
  selected_idx      smallint,
  grader_used       text,    -- 'keyword' | 'llm'
  grader_feedback   text,    -- personalized feedback from LLM grader, if any
  created_at        timestamptz not null default now()
);

create index answers_rep_idx      on answers(rep_id);
create index answers_question_idx on answers(question_id);
create index answers_created_idx  on answers(created_at desc);

-- ============================================================
-- Auth RPCs (SECURITY DEFINER — execute with table owner's privileges
-- so they can read/write `reps` even though anon can't touch it directly).
-- ============================================================

-- Register a new rep with a 4-digit PIN. Returns the new rep's UUID.
create or replace function create_rep(p_email text, p_name text, p_pin text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  new_id uuid;
begin
  if p_pin !~ '^\d{4}$' then
    raise exception 'PIN must be exactly 4 digits';
  end if;

  insert into reps (email, name, pin_hash)
  values (
    lower(trim(p_email)),
    trim(p_name),
    extensions.crypt(p_pin, extensions.gen_salt('bf', 10))
  )
  returning id into new_id;

  return new_id;
end;
$$;

-- Verify email + PIN. Returns rep_id on match, null otherwise.
create or replace function verify_pin(p_email text, p_pin text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  matched_id uuid;
begin
  select id into matched_id
  from reps
  where email = lower(trim(p_email))
    and pin_hash = extensions.crypt(p_pin, pin_hash);

  return matched_id;
end;
$$;

-- Fetch rep public info by id (omits pin_hash). Used after login.
create or replace function get_rep(p_id uuid)
returns table (id uuid, email text, name text, is_admin boolean, last_drill_at timestamptz)
language sql
security definer
set search_path = public
as $$
  select id, email, name, is_admin, last_drill_at
  from reps where id = p_id;
$$;

-- ============================================================
-- Row Level Security + permissions
-- ============================================================

-- reps: RLS on, NO policies = all anon access denied at the row level.
-- The SECURITY DEFINER RPCs above run as the function owner and bypass
-- RLS, so login/registration still works.
-- Also revoke direct table grants as defense-in-depth.
alter table reps enable row level security;
revoke all on reps from anon;

grant execute on function create_rep(text, text, text) to anon;
grant execute on function verify_pin(text, text) to anon;
grant execute on function get_rep(uuid) to anon;

-- Other tables: RLS on with permissive v1 policies.
-- Trust boundary is the closed BDC team. Data is non-sensitive (drill answers).
-- v2: replace `using (true)` with policies that check a custom JWT claim
--     minted by an Edge Function after PIN verify.
alter table rep_progress   enable row level security;
alter table drill_sessions enable row level security;
alter table answers        enable row level security;

create policy "v1 open access" on rep_progress
  for all to anon using (true) with check (true);

create policy "v1 open access" on drill_sessions
  for all to anon using (true) with check (true);

create policy "v1 open access" on answers
  for all to anon using (true) with check (true);
