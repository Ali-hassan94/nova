-- Nova cloud migration: har user ka alag data (Row Level Security).
-- Supabase > SQL Editor mein poori file ek baar chalayein.
-- Chalane se pehle neeche 'CHANGE_ME_STRONG_PASSWORD' ko apna lamba password bana lein.

create extension if not exists pgcrypto;

create table if not exists app_users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  pass_hash text not null,
  created_at timestamptz not null default now()
);

-- App ye role use karega. Is par RLS lagti hai, is liye ek user doosre ka data nahi dekh sakta.
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'nova_app') then
    create role nova_app login password 'CHANGE_ME_STRONG_PASSWORD' nobypassrls;
  end if;
end $$;
grant usage on schema public to nova_app;
grant select, insert on app_users to nova_app;

-- Purana habits unique index (sirf name par) hata dein, ab har user ke liye alag hoga.
do $$ declare r record; begin
  for r in select indexname from pg_indexes
           where schemaname = 'public' and tablename = 'habits'
             and indexdef ilike 'create unique index%lower(%' loop
    execute format('drop index public.%I', r.indexname);
  end loop;
end $$;

alter table tasks add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists tasks_user_idx on tasks(user_id);
alter table tasks enable row level security;
drop policy if exists own_rows on tasks;
create policy own_rows on tasks for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on tasks to nova_app;

alter table expenses add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists expenses_user_idx on expenses(user_id);
alter table expenses enable row level security;
drop policy if exists own_rows on expenses;
create policy own_rows on expenses for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on expenses to nova_app;

alter table moods add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists moods_user_idx on moods(user_id);
alter table moods enable row level security;
drop policy if exists own_rows on moods;
create policy own_rows on moods for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on moods to nova_app;

alter table habits add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists habits_user_idx on habits(user_id);
alter table habits enable row level security;
drop policy if exists own_rows on habits;
create policy own_rows on habits for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on habits to nova_app;

alter table habit_logs add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists habit_logs_user_idx on habit_logs(user_id);
alter table habit_logs enable row level security;
drop policy if exists own_rows on habit_logs;
create policy own_rows on habit_logs for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on habit_logs to nova_app;

alter table reminders add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists reminders_user_idx on reminders(user_id);
alter table reminders enable row level security;
drop policy if exists own_rows on reminders;
create policy own_rows on reminders for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on reminders to nova_app;

alter table notes add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists notes_user_idx on notes(user_id);
alter table notes enable row level security;
drop policy if exists own_rows on notes;
create policy own_rows on notes for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on notes to nova_app;

alter table memories add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists memories_user_idx on memories(user_id);
alter table memories enable row level security;
drop policy if exists own_rows on memories;
create policy own_rows on memories for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on memories to nova_app;

alter table command_logs add column if not exists user_id uuid references app_users(id) on delete cascade
  default nullif(current_setting('app.user_id', true), '')::uuid;
create index if not exists command_logs_user_idx on command_logs(user_id);
alter table command_logs enable row level security;
drop policy if exists own_rows on command_logs;
create policy own_rows on command_logs for all to nova_app
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
grant select, insert, update, delete on command_logs to nova_app;

create unique index if not exists habits_user_name_uq on habits (user_id, lower(name));
grant usage, select on all sequences in schema public to nova_app;

-- OPTIONAL: pehle ka apna purana data (jis mein user_id khali hai) apne naye account ko dena ho to,
-- pehle app mein register karein, phir ye chalayein (email apni likhein):
-- do $$ declare u uuid := (select id from app_users where email = 'aap@example.com'); begin
--   update tasks set user_id = u where user_id is null;
--   update expenses set user_id = u where user_id is null;
--   update moods set user_id = u where user_id is null;
--   update habits set user_id = u where user_id is null;
--   update habit_logs set user_id = u where user_id is null;
--   update reminders set user_id = u where user_id is null;
--   update notes set user_id = u where user_id is null;
--   update memories set user_id = u where user_id is null;
--   update command_logs set user_id = u where user_id is null;
-- end $$;
